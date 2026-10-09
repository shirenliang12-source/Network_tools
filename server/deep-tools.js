/* =========================================================================
 * 深度排障工具引擎（#71）
 * 三块能力，全部复用既有引擎，避免重复造轮子：
 *   1) 端口错包钻取  portErrorDrilldown  —— 从 datasource(SNMP/Zabbix) 拉端口计数器，
 *      与基线快照做差值，定位 CRC/错包/丢弃/冲突 的根因与严重度。
 *   2) MTR 深度分析  mtr                  —— 包装 toolbox.mtrTrace，逐跳定位瓶颈跳与丢包跳，
 *      产出 ECharts 可直接消费的延迟/丢包序列。
 *   3) PCAP 关联分析 pcapCorrelate       —— 复用 dpi.parsePcapFile + computeFlowMetrics，
 *      按 主机/IP/端口 过滤，给出该对象的重传/握手/HTTP·DNS 响应与问题会话。
 * 数据源容错：真实 SNMP 取不到时 datasource 自动走 Demo 兜底，本模块只消费其结果。
 * ========================================================================= */
'use strict';
const fs = require('fs');
const path = require('path');
const ds = require('./datasource');
const toolbox = require('./toolbox');
const dpi = require('./dpi');
const dpiMetrics = require('./dpi-metrics');
const customProto = require('./custom-proto');
const store = require('./store');

/* 端口错误计数器元数据：字段名 → 中文标签/所属层/典型根因 */
const ERRC = {
  crcErrors:      { label: 'CRC 校验错',  layer: '物理层',   cause: '线缆/水晶头/光模块/光纤劣化，或两端速率不匹配' },
  inErrors:       { label: '入方向错误',   layer: '物理层',   cause: '接收侧物理层故障（噪声、信号衰减、模块损坏）' },
  outErrors:      { label: '出方向错误',   layer: '物理层',   cause: '发送侧物理层故障（模块、线缆、对端问题）' },
  inDiscards:     { label: '入向丢弃',     layer: '缓冲/QoS', cause: 'RX 缓冲满、ACL 丢弃、QoS/风暴抑制、入向队列溢出' },
  outDiscards:    { label: '出向丢弃',     layer: '缓冲/QoS', cause: 'TX 拥塞、出向队列满、QoS 限速、出向 ACL 丢弃' },
  alignmentErrors:{ label: '对齐错误',     layer: '物理层',   cause: '帧长度/编码异常，多为线缆或模块问题' },
  collisions:     { label: '冲突',         layer: '半双工',   cause: '双工模式不匹配（一端全双工一端半双工）' },
  deferred:       { label: '延迟冲突',     layer: '半双工',   cause: '链路拥塞或沿用半双工协商' },
  lateCollisions: { label: '晚冲突',       layer: '半双工',   cause: '网线超距（>100m）或双工不匹配' },
  giants:         { label: '超长帧',       layer: '物理层',   cause: 'MTU/Jumbo 配置不一致或线缆问题' },
  runts:          { label: '残帧',         layer: '物理层',   cause: '线缆/模块故障导致帧被截断' }
};
/* 计数器严重度阈值：delta 超过该值即升级一级 */
const SEV_OF = (delta) => (delta <= 0 ? 'none' : delta <= 20 ? 'low' : delta <= 200 ? 'medium' : 'high');

const BASELINE_FILE = path.join(store.DATA_DIR, 'port-baseline.json');
function loadBaselines() {
  try { return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8') || '{}'); } catch { return {}; }
}
function saveBaselines(obj) {
  try { fs.writeFileSync(BASELINE_FILE, JSON.stringify(obj, null, 2)); } catch { /* 忽略落盘失败 */ }
}

/* ----------------------------- 端口错包钻取 ----------------------------- */
function findPort(ports, name) {
  if (!ports || !ports.length) return null;
  const n = String(name || '').trim().toLowerCase();
  if (!n) return null;
  return ports.find(p => p.name && p.name.toLowerCase() === n)
    || ports.find(p => p.name && p.name.toLowerCase().includes(n))
    || null;
}

async function readPortCounters(host, portName) {
  const detail = await ds.getProvider().ports(host);
  const ports = (detail && detail.ports) || [];
  const port = findPort(ports, portName);
  if (!port) {
    const names = ports.slice(0, 12).map(p => p.name).join(', ');
    return { ok: false, error: `未找到端口 "${portName}"（该设备共 ${ports.length} 个端口，示例：${names}）`, host, ports: ports.map(p => p.name) };
  }
  const counters = {};
  for (const k of Object.keys(ERRC)) counters[k] = Number(port[k] != null ? port[k] : 0) || 0;
  return {
    ok: true, host, port: {
      name: port.name, alias: port.alias || '', operStatus: port.operStatus, adminStatus: port.adminStatus,
      speedMbps: port.speedMbps, duplex: port.duplex, util: port.util, inBps: port.inBps || 0, outBps: port.outBps || 0
    },
    counters
  };
}

/**
 * 端口错包钻取：返回当前计数器 + 与基线差值 + 严重度 + 根因 + 建议
 */
async function portErrorDrilldown(host, portName) {
  const base = await readPortCounters(host, portName);
  if (!base.ok) return base;
  const baselines = loadBaselines();
  const key = `${host}|${base.port.name}`;
  const snap = baselines[key];
  const rows = [];
  let totalDelta = 0, maxSev = 'none';
  const SEV_RANK = { none: 0, low: 1, medium: 2, high: 3 };
  for (const k of Object.keys(ERRC)) {
    const cur = base.counters[k];
    let delta = 0, baseline = null;
    if (snap && typeof snap.counters[k] === 'number') {
      baseline = snap.counters[k];
      // 计数器单调递增；若当前 < 基线视为设备重启/计数器回绕，按当前值计（无法算差值）
      delta = cur >= baseline ? cur - baseline : cur;
    }
    const sev = SEV_OF(delta);
    if (SEV_RANK[sev] > SEV_RANK[maxSev]) maxSev = sev;
    totalDelta += delta;
    rows.push(Object.assign({ key: k, current: cur, baseline, delta, severity: sev }, ERRC[k]));
  }

  // 健康度：100 起，按各类 delta 加权扣分
  let health = 100;
  for (const r of rows) {
    if (r.key === 'crcErrors' || r.key === 'inErrors' || r.key === 'outErrors') health -= Math.min(40, r.delta * 0.8);
    else if (r.key === 'inDiscards' || r.key === 'outDiscards') health -= Math.min(25, r.delta * 0.4);
    else health -= Math.min(15, r.delta * 0.2);
  }
  health = Math.max(0, Math.round(health));

  // 根因归类
  const physical = rows.filter(r => r.layer === '物理层' && r.delta > 0).map(r => r.label);
  const buffer = rows.filter(r => r.layer === '缓冲/QoS' && r.delta > 0).map(r => r.label);
  const half = rows.filter(r => r.layer === '半双工' && r.delta > 0).map(r => r.label);

  const causes = [];
  if (physical.length) causes.push({ area: '物理层', prob: `${physical.join('、')} 持续增长，典型为线缆/光模块/光纤劣化或对端端口物理故障`, confidence: 'high' });
  if (half.length) causes.push({ area: '双工', prob: `${half.join('、')} 增长，强烈指向两端速率/双工不匹配（一端强制、一端自适应）`, confidence: 'high' });
  if (buffer.length) causes.push({ area: '缓冲/QoS', prob: `${buffer.join('、')} 增长，可能为队列拥塞、ACL/限速丢弃或广播风暴`, confidence: 'medium' });
  if (!causes.length) causes.push({ area: '无新增错包', prob: '与基线相比未检出错误计数增长，端口物理层健康；若仍有业务异常请查流量/会话层', confidence: 'high' });

  const recs = [];
  if (physical.length) {
    recs.push(`登录 ${host} 执行 display interface ${base.port.name}（H3C/Huawei）或 show interface ${base.port.name}（Cisco），确认 CRC/input-error 是否仍在增长`);
    recs.push('优先更换该端口网线或水晶头；若为光口则清洁/更换光模块与光纤，必要时换端口对比');
  }
  if (half.length) recs.push(`核对对端端口 speed/duplex 与本端一致，避免一端 auto 一端强制（show interface 看 Duplex 是否 Full）`);
  if (buffer.length) recs.push('排查入/出向丢弃来源：是否广播风暴、ACL 误丢弃或 QoS 队列拥塞，必要时调整限速/风暴抑制');
  recs.push('错包增长期间用「旁路采集/PCAP 关联分析」对该端口镜像抓包，确认是否特定流量触发');
  if (!snap) recs.unshift('当前无基线，可先点「打基线」记录当前计数器，过一段时间再钻取以得到准确的增量');

  return {
    ok: true, host, port: base.port,
    hasBaseline: !!snap, baselineAt: snap ? snap.at : null,
    health, severity: maxSev,
    counters: rows, totalDelta,
    summary: causes[0].prob,
    causes, recommendations: recs
  };
}

/** 记录当前计数器为基线快照 */
async function portErrorBaseline(host, portName) {
  const base = await readPortCounters(host, portName);
  if (!base.ok) return base;
  const baselines = loadBaselines();
  baselines[`${host}|${base.port.name}`] = { at: store.nowSec(), counters: base.counters };
  saveBaselines(baselines);
  return { ok: true, host, port: base.port.name, at: baselines[`${host}|${base.port.name}`].at, counters: base.counters };
}

/* ----------------------------- MTR 深度分析 ----------------------------- */
async function mtr(target, opts = {}) {
  const r = await toolbox.mtrTrace(target, opts);
  if (!r.ok) {
    return {
      ok: false, target: r.target || target, ip: r.ip || null,
      error: r.error || 'MTR 执行失败',
      hops: [], diagnosis: { health: 'unknown', summary: r.error || '路由追踪不可用（沙箱/环境缺少 tracert 或 traceroute）' },
      charts: null
    };
  }
  const hops = r.hops || [];
  // 逐跳瓶颈：与上一跳相比平均延迟增量最大的跳
  let bottleneckHop = null, maxDelta = 0, firstLossHop = null;
  for (let i = 0; i < hops.length; i++) {
    const h = hops[i];
    if (h.loss > 0 && firstLossHop == null) firstLossHop = h.ttl;
    if (h.avg != null && i > 0) {
      const prev = hops[i - 1];
      if (prev.avg != null) {
        const d = h.avg - prev.avg;
        if (d > maxDelta) { maxDelta = d; bottleneckHop = h.ttl; }
      }
    }
  }
  const lossHops = hops.filter(h => h.loss > 0).map(h => h.ttl);
  const highLatencyHops = hops.filter(h => h.avg != null && h.avg > 150).map(h => h.ttl);

  let health = 'good', summary;
  if (firstLossHop == null && maxDelta < 30 && !highLatencyHops.length) {
    health = 'good'; summary = '各跳延迟平稳、无丢包，路径质量健康';
  } else if (lossHops.length || highLatencyHops.length || maxDelta >= 30) {
    health = (lossHops.length || maxDelta >= 80) ? 'bad' : 'warn';
    const bits = [];
    if (firstLossHop != null) bits.push(`第 ${firstLossHop} 跳起出现丢包`);
    if (bottleneckHop != null) bits.push(`第 ${bottleneckHop} 跳延迟陡增 +${maxDelta.toFixed(1)}ms（疑似瓶颈）`);
    if (highLatencyHops.length) bits.push(`第 ${highLatencyHops.join('、')} 跳延迟偏高(>150ms)`);
    summary = bits.join('；') + '，建议从该跳向两侧设备排查';
  } else {
    health = 'warn'; summary = '路径基本可用，存在轻微延迟波动';
  }

  // ECharts 序列（前端可直接 setOption）
  const labels = hops.map(h => h.ip ? `${h.ttl}·${h.ip}` : `第${h.ttl}跳`);
  const latency = {
    categories: labels,
    min: hops.map(h => h.min != null ? h.min : null),
    avg: hops.map(h => h.avg != null ? h.avg : null),
    max: hops.map(h => h.max != null ? h.max : null)
  };
  const loss = { categories: labels, loss: hops.map(h => h.loss || 0) };

  return {
    ok: true, target: r.target, ip: r.ip, rounds: r.rounds, hopCount: r.hopCount, loss: r.loss,
    notes: r.notes || [],
    hops: hops.map(h => ({ ttl: h.ttl, ip: h.ip || '', loss: h.loss || 0, avg: h.avg, min: h.min, max: h.max, jitter: h.jitter || 0 })),
    diagnosis: { health, summary, bottleneckHop, firstLossHop, lossHops, highLatencyHops, maxDelta: +maxDelta.toFixed(1) },
    charts: { latency, loss }
  };
}

/* ----------------------------- PCAP 关联分析 ----------------------------- */
function sessionMatch(s, host, port) {
  if (host) {
    const h = String(host).trim();
    if (s.srcIp !== h && s.dstIp !== h) return false;
  }
  if (port) {
    const p = String(port).trim();
    if (String(s.srcPort) !== p && String(s.dstPort) !== p) return false;
  }
  return true;
}

async function pcapCorrelate({ file, host, port } = {}) {
  if (!file) return { ok: false, error: '请指定抓包文件' };
  const name = String(file).replace(/[^\w.\-]/g, '');
  const full = path.join(store.CAP_DIR, name);
  if (!fs.existsSync(full)) return { ok: false, error: `抓包文件不存在：${name}` };
  try {
    let customDefs = [];
    try { customDefs = await customProto.asDefs(); } catch (e) { customDefs = []; }
    const parsed = dpi.parsePcapFile(full, { customDefs });
    if (parsed.error) return { ok: false, error: parsed.error };
    const sessions = (parsed.sessions || []).filter(s => sessionMatch(s, host, port));
    const m = dpiMetrics.computeFlowMetrics(sessions, parsed.packets);

    // 问题会话：重传 / RST / 握手慢 / HTTP·DNS 响应慢
    const problems = sessions
      .filter(s => s.perf && (s.perf.retrans > 0 || s.perf.rst || (s.perf.handshakeMs > 300) || (s.perf.httpRespMs > 800) || (s.perf.dnsRespMs > 500)))
      .sort((a, b) => (b.perf.retrans + (b.perf.rst ? 5 : 0)) - (a.perf.retrans + (a.perf.rst ? 5 : 0)) || (b.bytes || 0) - (a.bytes || 0))
      .slice(0, 12)
      .map(s => ({
        srcIp: s.srcIp, dstIp: s.dstIp, srcPort: s.srcPort, dstPort: s.dstPort, proto: s.proto, appProto: s.appProto,
        bytes: s.bytes || 0, pkts: s.pkts || 0,
        retrans: s.perf.retrans || 0, rst: !!s.perf.rst,
        handshakeMs: s.perf.handshakeMs || 0, httpRespMs: s.perf.httpRespMs || 0, dnsRespMs: s.perf.dnsRespMs || 0
      }));

    const scopeTxt = [host ? `主机 ${host}` : '', port ? `端口 ${port}` : ''].filter(Boolean).join(' / ') || '全部流量';
    return {
      ok: true, file: name, scope: scopeTxt, host: host || '', port: port || '',
      totalSessions: parsed.sessions.length, matchedSessions: sessions.length,
      matchedBytes: m.totals.bytes, span: m.span,
      kpi: m.kpi, byProto: m.byProto.slice(0, 10),
      problemSessions: problems,
      summary: sessions.length
        ? `在「${scopeTxt}」范围内共 ${sessions.length} 条会话，重传率 ${m.kpi.retransRate}%，问题会话 ${problems.length} 条`
        : `「${scopeTxt}」范围内未匹配到会话（请确认 IP/端口或选择含该对象的抓包）`
    };
  } catch (e) {
    return { ok: false, error: 'PCAP 解析异常：' + e.message };
  }
}

module.exports = {
  ERRC, portErrorDrilldown, portErrorBaseline, mtr, pcapCorrelate, readPortCounters
};
