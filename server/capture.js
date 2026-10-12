'use strict';
/**
 * 旁路持续采集引擎（对齐 AnaTraf「全流量持续采集 → 完整留存 → 随时回溯」）
 *
 * 任务模型：
 *   kind = 'pcap'    本地旁路抓包（需 tshark/dumpcap，或系统已装 Npcap 时可用 dumpcap）
 *   kind = 'device'  设备侧轮询采集（SSH 定期取 MAC/ARP/会话表、接口状态，结果长期留存）
 *
 * 运行方式：随服务启动的后台调度器，每 SCHED_LEAD 秒巡检一次，
 *   对 enabled 且到点的任务跑一轮（串行，避免抓包争抢）；跑完落盘 pcap + 解析会话入库 + 清理过期数据。
 * 留存：任务可设 retainHours，超时自动删除 pcap 文件与会话库记录（保留策略）。
 */
const path = require('path');
const fs = require('fs');
const store = require('./store');
const db = require('./db');
const dpi = require('./dpi');
const netutil = require('./netutil');

const CAP_DIR = store.CAP_DIR;
const SCHED_LEAD = 5000;          // 巡检间隔
const running = new Map();        // taskId -> { proc, until }
let timer = null;
let sweepTimer = null;

/** 抓包可执行文件：tshark 优先（解析也能用它），其次 dumpcap */
function capBin() {
  return netutil.captureEngine();
}

function env() { return (db.settingsSync() || {}).capture || {}; }

/** 启动日志用的一行状态 */
function info() {
  const r = [];
  const b = capBin();
  r.push(`旁路采集  ${b.bin ? b.tool + ' 可用 (' + b.bin + ')' : '未检测到本机抓包后端（仍可使用设备侧采集）'}`);
  return r;
}

/* ------------------------------ 一轮采集 ------------------------------ */
/** 同步跑一轮本地抓包（阻塞等待到结束或超时）——用于手动触发 */
async function runOnce(id) {
  const task = await db.taskFind(id);
  if (!task) return { ok: false, error: '任务不存在' };
  if (task.kind === 'device') return runDeviceOnce(task);
  return runPcapOnce(task);
}

async function runPcapOnce(task) {
  const b = capBin();
  if (!b.bin) return { ok: false, error: '未检测到本机抓包后端，可把任务类型改成设备侧采集。' };
  const sec = Math.max(1, Math.min(300, Number(task.seconds || 30)));
  const sizeMB = Math.max(1, Number(task.pcapSize || 100));
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const wantedFile = path.join(CAP_DIR, `task-${task.id}-${stamp}.pcap`);
  const t0 = Date.now();
  let captured;
  try {
    captured = await netutil.captureToFile({ out: wantedFile, iface: task.iface || '1', filter: (task.bpf || '').trim(), seconds: sec, sizeMB });
  } catch (e) {
    await db.taskSave({ id: task.id, status: 'error', lastEndedAt: new Date().toISOString() });
    return { ok: false, error: '抓包失败：' + e.message };
  }
  const file = captured.path || wantedFile;
  const exists = fs.existsSync(file);
  const size = exists ? fs.statSync(file).size : 0;
  if (!exists) {
    await db.taskSave({ id: task.id, status: 'error', lastEndedAt: new Date().toISOString() });
    return { ok: false, error: '抓包未产生文件：' + String(captured.log || '').slice(-200) };
  }

  /* 解析并入库 */
  const parsed = /\.pcap$/i.test(file) ? dpi.parsePcapFile(file) : { packets: 0, sessions: [], error: 'PCAPNG 文件等待 TShark 解析' };
  const rows = (parsed.sessions || []).map(s => ({
    id: store.uid('flw_'),
    startedAt: s.startedAt,
    srcIp: s.srcIp, dstIp: s.dstIp, srcPort: s.srcPort, dstPort: s.dstPort,
    proto: s.proto, appProto: s.appProto || '',
    taskId: task.id, fileId: path.basename(file),
    bytes: s.bytes, pkts: s.pkts, durationMs: s.durationMs,
    hint: s.hint || {}, tags: s.tags || []
  }));
  const inserted = rows.length ? await db.flowInsert(rows) : 0;
  await db.capSave({
    id: path.basename(file).replace(/\.[^.]+$/, ''),
    name: task.name,
    path: file,
    size,
    iface: task.iface || '',
    mode: 'pcap',
    filter: task.bpf || '',
    source: task.kind || 'pcap',
    startedAt: new Date(t0).toISOString(),
    endedAt: new Date().toISOString(),
    ...{ packets: parsed.packets, sessions: rows.length, inserted, taskId: task.id, engine: captured.engine || b.tool, parseNote: parsed.error || '' }
  });
  await db.taskSave({
    id: task.id,
    status: 'idle',
    runs: Number(task.runs || 0) + 1,
    lastStartedAt: new Date(t0).toISOString(),
    lastEndedAt: new Date().toISOString()
  });
  store.audit({ user: 'system', action: 'capture.task.run', target: task.name, detail: `${parsed.packets} 包 / ${rows.length} 会话 / ${(size / 1048576).toFixed(1)}MB` });
  return { ok: true, file: path.basename(file), size, packets: parsed.packets, sessions: rows.length, inserted, engine: captured.engine || b.tool, ms: Date.now() - t0 };
}

/** 设备侧采集：SSH 取 MAC/ARP/会话表，结果落库以供后续回溯 */
async function runDeviceOnce(task) {
  const netutil = require('./netutil');
  const cred = task.credentialId ? await db.credentialsFind(task.credentialId) : null;
  if (!cred) return { ok: false, error: '任务未绑定有效凭据，请先在任务里选择设备凭据' };
  const cmds = netutil.TABLE_CMDS?.[cred.vendor] || netutil.TABLE_CMDS?.cisco || {};
  const t0 = Date.now();
  const rows = [];
  const errors = [];
  const hosts = String(task.hosts || cred.host || '').split(/[\s,;]+/).filter(Boolean);
  for (const h of hosts.slice(0, 8)) {
    try {
      const r = await netutil.sshExec(
        { host: h, port: cred.port || 22, username: cred.username, secret: store.decrypt(cred.secretEnc), kind: cred.kind },
        cmds.mac ? [cmds.mac] : ['show mac address-table'],
        { timeoutMs: 20000 }
      );
      rows.push({ host: h, cmd: cmds.mac || 'show mac address-table', out: String(r.stdout || '').slice(0, 20000), at: new Date().toISOString() });
    } catch (e) { errors.push(`${h}: ${e.message}`); }
  }
  await db.capSave({
    id: store.uid('cap_'),
    name: task.name,
    path: '',
    size: rows.reduce((a, r) => a + (r.out || '').length, 0),
    iface: '', mode: 'device',
    filter: '', source: 'device',
    startedAt: new Date(t0).toISOString(),
    endedAt: new Date().toISOString(),
    ...{ hosts: rows.map(r => r.host), samples: rows, errors, taskId: task.id }
  });
  await db.taskSave({
    id: task.id, status: errors.length && !rows.length ? 'error' : 'idle',
    runs: Number(task.runs || 0) + 1,
    lastStartedAt: new Date(t0).toISOString(),
    lastEndedAt: new Date().toISOString()
  });
  return { ok: true, samples: rows.length, errors: errors.slice(0, 3), ms: Date.now() - t0 };
}

/** 立即跑一轮（不等待调度） */
async function trigger(id, user = 'system') {
  const r = await runOnce(id);
  store.audit({ user, action: 'capture.task.trigger', target: id, result: r.ok ? 'ok' : 'fail', detail: r.error || '' });
  return r;
}

/* ------------------------------ 调度与留存 ------------------------------ */
async function tick() {
  try {
    const tasks = await db.taskList();
    for (const t of tasks) {
      if (!t.enabled || running.has(t.id)) continue;
      const gap = Number(t.intervalSec || 300);
      const last = t.lastStartedAt ? new Date(t.lastStartedAt).getTime() : 0;
      if (Date.now() - last < gap * 1000) continue;
      markRunning(t.id);
      runOnce(t.id).catch(e => {
        db.taskSave({ id: t.id, status: 'error' }).catch(() => { });
        console.error(`[capture] 任务 ${t.name} 执行失败：`, e.message);
      }).finally(() => clearRunning(t.id));
    }
  } catch (e) { console.error('[capture] 调度异常：', e.message); }
}

function markRunning(id) { running.set(id, Date.now()); }
function clearRunning(id) { running.delete(id); }

/** 保留策略：删除过期 pcap 与会话库记录 */
async function sweep() {
  try {
    const tasks = await db.taskList();
    const now = Date.now();
    let removedFiles = 0, removedFlows = 0;
    for (const t of tasks) {
      const hrs = Number(t.retainHours || 72);
      const cut = now - hrs * 3600 * 1000;
      if (!isFinite(cut)) continue;
      let dirCut = '';
      try { dirCut = fs.readdirSync(CAP_DIR).filter(f => { const st = fs.statSync(path.join(CAP_DIR, f)); return st.mtimeMs < cut; }); } catch { }
      for (const f of dirCut) { try { fs.unlinkSync(path.join(CAP_DIR, f)); removedFiles++; } catch { } }
      const tasksWithCut = tasks.filter(x => new Date(x.lastEndedAt || 0).getTime() < cut).map(x => x.id);
      if (tasksWithCut.length) removedFlows += await db.flowRemoveOld(new Date(cut).toISOString(), tasksWithCut);
    }
    if (removedFiles || removedFlows) console.log(`[capture] 保留策略清理：删除 ${removedFiles} 个 pcap / ${removedFlows} 条会话记录`);
  } catch (e) { /* 清理失败不影响主流程 */ }
}

/* -------------------------------- 对外 -------------------------------- */
async function start() {
  if (timer) return;
  timer = setInterval(tick, SCHED_LEAD);
  sweepTimer = setInterval(sweep, 30 * 60 * 1000);
  tick();
  const tasks = await db.taskList().catch(() => []);
  const enabled = tasks.filter(t => t.enabled).length;
  console.log(`  旁路采集  已启动 · 任务 ${tasks.length} 个（启用 ${enabled} 个）`);
}

module.exports = { start, info, runOnce, trigger, sweep, capBin, running };
