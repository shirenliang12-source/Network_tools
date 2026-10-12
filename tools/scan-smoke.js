'use strict';
/**
 * 网络扫描链路自检
 *
 * 分两段：
 *   A 段（引擎级，无需服务）：目标展开 → 端口解析 → 服务识别 → 风险判定 → 真实 TCP 扫描
 *   B 段（接口级，需服务）：任务 CRUD → 执行扫描 → 入库 → 主机/端口/统计查询 → CSV 导出 → 权限
 *
 * A 段为了不依赖外部环境，会临时在本机起一个「打完 SSH banner 就关」的监听口，
 * 扫描它必然拿到 open + ssh，扫描一个没人监听的端口必然 closed，结果可复现。
 *
 * 用法：node tools/scan-smoke.js [baseUrl]   （默认 http://127.0.0.1:8787）
 */
const net = require('net');
const scanner = require('../server/scanner');

let pass = 0, fail = 0;
const fails = [];
const ok = (n, c, e) => {
  if (c) { pass++; console.log(`  ✓ ${n}${e ? ' — ' + e : ''}`); }
  else { fail++; fails.push(n); console.log(`  ✗ ${n}${e ? ' — ' + e : ''}`); }
};

/**
 * 收掉测试监听。
 * 注意不能 await server.close(cb)：还有连接挂着时回调不会触发，而监听句柄已释放，
 * 事件循环会被判定为空、进程直接静默退出，后面的检查根本跑不到。
 */
function closeSrv(srv) {
  try { srv.closeAllConnections && srv.closeAllConnections(); } catch { }
  try { srv.close(); } catch { }
}

/** 起一个监听口，客户端一连上就把 banner 吐回去 —— 等价于一台开了 SSH 的机器 */
function listenBanner(text) {
  return new Promise(resolve => {
    // 扫描器探测完会直接 destroy 客户端连接，服务端socket 随之收到 ECONNRESET，这里必须接住
    const srv = net.createServer((s) => {
      s.on('error', () => { });
      try { s.end(text); } catch { }
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

/* ============================ A 段：引擎级 ============================ */
function checkExpand() {
  console.log('\n[A1] 目标展开');
  (async () => {
    const c24 = await scanner.expandTargets('10.0.0.0/24');
    ok('CIDR /24 展开', c24.length === 256, `${c24.length} 个地址（${c24[0]} ~ ${c24[c24.length - 1]}）`);

    const c30 = await scanner.expandTargets('10.0.0.0/30');
    ok('CIDR /30 展开', c30.length === 4, `${c30.join(' ')}`);

    const unaligned = await scanner.expandTargets('10.1.2.3/24');
    ok('CIDR 非对齐地址归整', unaligned[0] === '10.1.2.0' && unaligned.length === 256, `${unaligned[0]} ~ ${unaligned[unaligned.length - 1]}`);

    const range = await scanner.expandTargets('10.0.0.1-10');
    ok('区间展开', range.length === 10, `${range[0]} ~ ${range[range.length - 1]}`);

    const one = await scanner.expandTargets('172.16.1.10');
    ok('单个地址', one.length === 1 && one[0] === '172.16.1.10', one.join(','));

    // 逗号/分号/空格混写，且重复地址只保留一个
    const mixed = await scanner.expandTargets('10.0.0.1, 10.0.0.1, 10.0.0.2; 10.0.0.2 10.0.0.3');
    ok('混合分隔去重', mixed.length === 3 && new Set(mixed).size === 3, mixed.join(' '));

    let err = '';
    try { await scanner.expandTargets('10.0.0.0/8'); } catch (e) { err = e.message; }
    ok('超上限拦截（/8 = 1600 万）', /超过单次上限/.test(err), err.slice(0, 60));

    err = '';
    try { await scanner.expandTargets('999.1.1.1'); } catch (e) { err = e.message; }
    ok('非法目标报错', /无法解析目标/.test(err), err.slice(0, 60));

    err = '';
    try { await scanner.expandTargets(''); } catch (e) { err = e.message; }
    ok('空目标报错', /未解析到任何目标/.test(err), err.slice(0, 60));
  })();
}

function checkPorts() {
  console.log('\n[A2] 端口解析');
  const p1 = scanner.parsePorts('22,80,443');
  ok('逗号分隔', p1.join(',') === '22,80,443', p1.join(','));

  const p2 = scanner.parsePorts('1000-1003');
  ok('区间展开', p2.join(',') === '1000,1001,1002,1003', p2.join(','));

  const p3 = scanner.parsePorts('443,22,80,443,22');
  ok('去重排序', p3.join(',') === '22,80,443', p3.join(','));

  const p4 = scanner.parsePorts('22,100000,0,80');
  ok('越界端口剔除', p4.join(',') === '22,80', p4.join(','));

  const p5 = scanner.parsePorts('1000-5');            // 区间写反
  ok('反序区间不展开', p5.length === 0, `得到 ${p5.length} 个`);

  const web = scanner.parsePorts(scanner.PORT_PRESETS.web.ports.join(','));
  ok('Web 预设可用', web.length === scanner.PORT_PRESETS.web.ports.length, `${web.length} 个端口`);

  ok('预设列表', scanner.presets().length >= 6, scanner.presets().map(p => p.label).join('/'));
}

function checkService() {
  console.log('\n[A3] 服务识别');
  const cases = [
    [22, 'SSH-2.0-OpenSSH_8.9\r\n', 'ssh'],
    [80, 'HTTP/1.1 400 Bad Request\r\n', 'http'],
    [445, '\r\n\x00\x00\x00\x00Samba', 'microsoft-ds'],
    [502, '\x00\x00\x00\x00\x00\x06\x00\x00\x00\x01\x00\x00SIEMENS', 's7comm'],
    [6379, '-Redis 7.0.0\n', 'redis']
  ];
  for (const [port, banner, want] of cases) {
    const got = scanner.identifyService(port, banner);
    ok(`banner 识别 ${port}`, got.service === want, `${got.service} / ${got.product || '-'}`);
  }

  const fb = scanner.identifyService(443, '');          // 没 banner，走端口表
  ok('无 banner 走端口表兜底', fb.service === 'https', `443 → ${fb.service}`);
  const unk = scanner.identifyService(9999, '');
  ok('无规则端口标 unknown', unk.service === 'unknown', `9999 → ${unk.service}`);
}

function checkRisk() {
  console.log('\n[A4] 风险判定');
  // 关键回归：没抓到 banner 时服务是 unknown，高危端口必须仍能按端口规则兜底
  const must = [
    [445, 'high'], [3389, 'high'], [23, 'high'], [21, 'high'],
    [502, 'critical'], [102, 'critical'], [6379, 'critical'],
    [3306, 'high'], [1433, 'high'], [22, 'info'], [443, 'info'], [80, 'low']
  ];
  for (const [port, level] of must) {
    const r = scanner.riskOf(port, 'unknown');
    ok(`unknown 兜底 ${port}`, !!r && r.level === level, r ? `${r.level} · ${r.tag}` : '无规则');
  }

  const r445 = scanner.riskOf(445, 'unknown');
  ok('445 命中 SMB 规则', r445 && r445.tag === 'SMB 暴露', r445 ? r445.desc.slice(0, 40) : '');

  // 服务名已识别但与规则不符时不应误报（同端口不同服务的场景）
  const mismatch = scanner.riskOf(445, 'http');
  ok('服务不符不误报', mismatch === null, `445/http → ${mismatch ? mismatch.tag : '无规则'}`);

  const noRule = scanner.riskOf(9999, 'unknown');
  ok('无规则端口不报风险', noRule === null, String(noRule));

  const h1 = scanner.hostRisk([{ port: 445 }, { port: 80 }]);
  ok('主机风险取最高级', h1.level === 'high', `${h1.level} · ${h1.tags.join('、')}`);
  const h2 = scanner.hostRisk([{ port: 445 }, { port: 502 }, { port: 80 }]);
  ok('工控端口提级为极高', h2.level === 'critical', `${h2.level} · ${h2.tags.join('、')}`);
  const h3 = scanner.hostRisk([{ port: 9999 }]);
  ok('无风险主机为 info', h3.level === 'info' && h3.tags.length === 0, h3.level);

  ok('风险规则库', scanner.RISK_RULES.length >= 20, `${scanner.RISK_RULES.length} 条规则`);
}

async function checkRealScan() {
  console.log('\n[A5] 真实 TCP 扫描');
  const srv = await listenBanner('SSH-2.0-OpenSSH_8.9\r\n');
  const port = srv.address().port;
  const targets = ['127.0.0.1'];

  try {
    const alive = await scanner.discover(targets, { mode: 'tcp', ports: scanner.DISCOVER_PORTS, concurrency: 20, timeoutMs: 800 });
    ok('存活发现', alive.some(a => a.ip === '127.0.0.1'), `存活 ${alive.length} 台`);

    const open = await scanner.scanPorts(alive, [port, 9999], { concurrency: 20, timeoutMs: 800, banner: true });
    const gotPort = open.find(p => p.port === port);
    const closed = open.find(p => p.port === 9999);
    ok('开放端口探测', !!gotPort, gotPort ? `${gotPort.ip}:${gotPort.port} ${gotPort.service}` : '未探到');
    ok('关闭端口不入表', !closed, closed ? '异常：9999 竟然开放' : '9999 未开放（符合预期）');
    ok('banner 抓取', gotPort && /SSH-/.test(gotPort.banner || ''), gotPort ? (gotPort.banner || '').trim().slice(0, 30) : '');
    ok('服务识别命中 ssh', gotPort && gotPort.service === 'ssh', gotPort ? gotPort.service : '');

    const hosts = scanner.groupByHost(open);
    ok('按主机聚合', hosts.length === 1 && hosts[0].openPorts.length === 1, hosts.length ? `${hosts[0].ip} 开放 ${hosts[0].openPorts.length} 个端口` : '');
    ok('聚合风险', hosts[0] && hosts[0].riskLevel === 'info', hosts[0] ? hosts[0].riskLevel : '');
  } finally {
    closeSrv(srv);
  }
}

/* ============================ B 段：接口级 ============================ */
async function checkApi(srvPort) {
  console.log('\n[B] 接口全链路');
  const BASE = (process.argv[2] || 'http://127.0.0.1:8787').replace(/\/+$/, '');
  let token = '';
  try {
    const lg = await fetch(BASE + '/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'admin@123' })
    }).then(r => r.json());
    token = lg.token || '';
  } catch { }

  if (!token) { console.log('  (服务未启动，跳过接口部分)'); return; }

  const call = async (m, p, body = null) => {
    const res = await fetch(BASE + '/api' + p, {
      method: m,
      headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}),
      body: body === null ? undefined : JSON.stringify(body)
    });
    const ct = res.headers.get('content-type') || '';
    return { status: res.status, data: ct.includes('application/json') ? await res.json() : { raw: await res.text() } };
  };

  /* 预设置 */
  const ps = await call('GET', '/scan/presets');
  ok('预设置接口', ps.data.ok === true && ps.data.presets.length >= 6,
    `${ps.data.presets.length} 组预设 / ${ps.data.modes.length} 种模式 / ${(ps.data.riskRules || []).length} 条风险规则`);

  /* 任务 CRUD */
  const taskPorts = [srvPort, 9999, 445].join(',');
  const cr = await call('POST', '/scan/tasks', {
    name: 'scan-smoke 自检任务', targets: '127.0.0.1', ports: taskPorts,
    discoverMode: 'tcp', banner: true, intervalSec: 3600, retainHours: 24, enabled: false
  });
  const taskId = cr.data.task && cr.data.task.id;
  ok('创建扫描任务', !!taskId, taskId || (cr.data.error || ''));
  if (!taskId) return;

  const bad = await call('POST', '/scan/tasks', { name: '', targets: '' });
  ok('空参数拒绝', bad.status === 400, `HTTP ${bad.status} · ${bad.data.error || ''}`);

  const lt = await call('GET', '/scan/tasks');
  ok('任务列表', lt.data.ok === true && Array.isArray(lt.data.rows), `${(lt.data.rows || []).length} 个任务`);

  const ut = await call('PUT', '/scan/tasks/' + taskId, { name: 'scan-smoke 自检任务(改)', retainHours: 48 });
  ok('更新任务', ut.data.ok === true && ut.data.task.name === 'scan-smoke 自检任务(改)', ut.data.task ? ut.data.task.name : '');

  /* 执行扫描 */
  const rn = await call('POST', '/scan/tasks/' + taskId + '/run', {});
  ok('执行扫描任务', rn.data.ok === true && rn.data.runId, rn.data.error || `存活 ${rn.data.alive} / 端口 ${rn.data.openPorts} / ${rn.data.ms}ms`);

  const r403 = await call('POST', '/scan/tasks/' + taskId + '/toggle', { enabled: true });
  ok('任务启停', r403.data.ok === true && r403.data.task.enabled === true, r403.data.task ? String(r403.data.task.enabled) : '');

  /* 结果查询 */
  const runId = rn.data.runId;
  const hs = await call('GET', '/scan/hosts?runId=' + runId);
  ok('主机查询', hs.data.ok === true && hs.data.rows.length >= 1, `${hs.data.rows.length} 台 · ${(hs.data.rows[0] || {}).ip}(${(hs.data.rows[0] || {}).riskLevel})`);

  const ps2 = await call('GET', '/scan/ports?runId=' + runId);
  const myPort = (ps2.data.rows || []).find(p => p.port === srvPort);
  ok('端口查询', ps2.data.ok === true && ps2.data.rows.length >= 1, `${ps2.data.rows.length} 条`);
  ok('扫描到的 SSH 端口', !!myPort, myPort ? `${myPort.port} ${myPort.service} → ${myPort.riskLevel}` : '');

  const st = await call('GET', '/scan/stats?runId=' + runId);
  ok('风险统计', st.data.ok === true && Array.isArray(st.data.byRisk),
    (st.data.byRisk || []).map(x => `${x.level}:${x.count}`).join(' ') + ` · 风险端口 ${st.data.riskPorts}`);

  const rf = await call('GET', '/scan/ports?runId=' + runId + '&risk=high');
  ok('按风险过滤', rf.data.ok === true, `high 端口 ${rf.data.rows ? rf.data.rows.length : 0} 条`);

  const rl = await call('GET', '/scan/runs?limit=5');
  ok('扫描历史', rl.data.ok === true && rl.data.rows.length >= 1, `${rl.data.rows.length} 次 · 最近 ${(rl.data.rows[0] || {}).status}`);

  /* CSV 导出（BOM 防 Excel 乱码）
     注意：Response.text() 会按规范吃掉开头的 BOM，只能看字节才能验 */
  const ex = await fetch(BASE + '/api/scan/export?runId=' + runId, { headers: { Authorization: 'Bearer ' + token } });
  const buf = ex.status === 200 ? Buffer.from(await ex.arrayBuffer()) : Buffer.alloc(0);
  const csv = buf.toString('utf8').replace(/^﻿/, '');   // Buffer.toString 不吃 BOM，得手动去
  const lines = csv.split('\r\n').filter(Boolean);
  const bom = buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF;
  ok('CSV 导出', ex.status === 200 && lines.length >= 2, `HTTP ${ex.status} · ${lines.length} 行`);
  ok('CSV 带 BOM（Excel 不乱码）', bom, bom ? 'EF BB BF' : '缺少 BOM 头');
  ok('CSV 表头', lines[0] && lines[0].startsWith('主机IP'), lines[0] || '');

  /* 快速扫描 */
  const qk = await call('POST', '/scan/quick', {
    targets: '127.0.0.1', ports: taskPorts, banner: false,
    discoveryPorts: taskPorts, timeoutMs: 900, retries: 1, reverseDns: false, note: '自动化验证'
  });
  ok('快速扫描', qk.data.ok === true, `存活 ${qk.data.alive} / 端口 ${qk.data.openPorts} / ${qk.data.ms}ms`);
  ok('快速扫描返回结构化明细', qk.data.availabilityRate === 100
    && Array.isArray(qk.data.hostPreview) && Array.isArray(qk.data.services)
    && Array.isArray(qk.data.recommendations),
  `可用率 ${qk.data.availabilityRate}% · 主机明细 ${(qk.data.hostPreview || []).length} 条`);
  ok('自定义参数生效', qk.data.parameters?.retries === 1
    && qk.data.parameters?.reverseDns === false && qk.data.parameters?.note === '自动化验证',
  JSON.stringify(qk.data.parameters || {}));

  /* 权限：审计角色不应有扫描权限 */
  const lg2 = await call('POST', '/auth/login', { username: 'audit', password: 'audit@123' });
  const t2 = lg2.data && lg2.data.token;
  if (t2) {
    // 设计意图：扫描是主动往网段发包的行为，审计角色只能读结果、不能发起扫描
    const q = await fetch(BASE + '/api/scan/tasks', { headers: { Authorization: 'Bearer ' + t2 } });
    ok('审计角色不能管扫描任务', q.status === 403, `HTTP ${q.status}`);
    const q2 = await fetch(BASE + '/api/scan/quick', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + t2 },
      body: JSON.stringify({ targets: '127.0.0.1', ports: '22' })
    });
    ok('审计角色不能发起扫描', q2.status === 403, `HTTP ${q2.status}`);
    const q3 = await fetch(BASE + '/api/scan/hosts?runId=' + runId, { headers: { Authorization: 'Bearer ' + t2 } });
    ok('审计角色可读扫描结果', q3.status === 200, `HTTP ${q3.status}`);
  }

  /* 清理 */
  const dl = await call('DELETE', '/scan/tasks/' + taskId);
  ok('删除扫描任务', dl.data.ok === true, `HTTP ${dl.status}`);
}

/* ============================== 入口 ============================== */
(async () => {
  console.log('\n=== 网络扫描链路自检（引擎 → 入库 → 接口）===\n');
  await checkExpand();
  await new Promise(r => setImmediate(r));
  checkPorts();
  checkService();
  checkRisk();
  await checkRealScan();

  const srv = await listenBanner('SSH-2.0-OpenSSH_8.9\r\n');
  const srvPort = srv.address().port;
  try { await checkApi(srvPort); } finally { closeSrv(srv); }

  console.log(`\n=== 完成：通过 ${pass} 项，失败 ${fail} 项 ===`);
  if (fails.length) console.log('失败项：\n  - ' + fails.join('\n  - '));
  console.log('');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('自检失败：', e); process.exit(1); });
