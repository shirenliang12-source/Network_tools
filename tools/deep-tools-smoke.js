'use strict';
/**
 * 深度排障工具自检（#71）
 *   A 段（引擎级，无需服务）：端口错包钻取/基线差值、MTR 优雅失败、PCAP 关联过滤
 *   B 段（接口级，可选）：若本地有服务则登录并验证 /api/deep/* 路由连通与权限门禁
 *
 * 用法：node tools/deep-tools-smoke.js [baseUrl]   （默认 http://127.0.0.1:8799）
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const dt = require('../server/deep-tools');
const db = require('../server/db');
const ROOT = path.join(__dirname, '..');
const CAP_DIR = path.join(ROOT, 'data', 'captures');

const BASE = (process.argv[2] || 'http://127.0.0.1:8799').replace(/\/+$/, '');

let pass = 0, fail = 0, skip = 0;
const fails = [];
const ok = (n, c, e) => { if (c) { pass++; console.log(`  ✓ ${n}${e ? ' — ' + e : ''}`); } else { fail++; fails.push(n); console.log(`  ✗ ${n}${e ? ' — ' + e : ''}`); } };
const skipped = (n, e) => { skip++; console.log(`  ⊘ ${n}${e ? ' — ' + e : ''}`); };
const section = (t) => console.log('\n◆ ' + t);

/** 极简 HTTP 客户端 */
function req(method, p, body, token) {
  return new Promise((resolve, reject) => {
    const u = new URL(BASE + p);
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ method, hostname: u.hostname, port: u.port, path: u.pathname + u.search, headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}) }, res => {
      let buf = ''; res.on('data', d => buf += d); res.on('end', () => { try { resolve({ status: res.statusCode, data: buf ? JSON.parse(buf) : null }); } catch { resolve({ status: res.statusCode, data: null }); } });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

(async () => {
  console.log('深度排障工具自检（#71）');
  console.log('BASE = ' + BASE);
  try { await db.init(); } catch (e) { console.log('（db 未初始化，部分依赖走兜底：' + (e.message || e) + '）'); }

  /* ------------------------- A 段：引擎级 ------------------------- */
  section('A. 端口错包钻取 / 基线差值');
  const HOST = 'SW-CORE-01', PORT = 'Ethernet1/1';
  const base = await dt.readPortCounters(HOST, PORT);
  ok('readPortCounters 命中端口', base.ok && base.port && base.port.name === PORT, base.ok ? `crc=${base.counters.crcErrors}` : base.error);
  const dr = await dt.portErrorDrilldown(HOST, PORT);
  ok('portErrorDrilldown 返回结构', dr.ok && dr.counters && dr.counters.length === 11 && typeof dr.health === 'number', `health=${dr.health} sev=${dr.severity}`);
  ok('portErrorDrilldown 含根因与建议', Array.isArray(dr.causes) && dr.causes.length && Array.isArray(dr.recommendations) && dr.recommendations.length);
  const bl = await dt.portErrorBaseline(HOST, PORT);
  ok('portErrorBaseline 记录快照', bl.ok && bl.at > 0);
  const dr2 = await dt.portErrorDrilldown(HOST, PORT);
  ok('打基线后再次钻取 hasBaseline=true', dr2.hasBaseline === true, `baselineAt=${dr2.baselineAt}`);
  const miss = await dt.portErrorDrilldown(HOST, '不存在端口');
  ok('端口不存在时优雅报错', miss.ok === false && /未找到端口/.test(miss.error || ''), miss.error || '');

  section('B. MTR 路径分析（优雅失败不崩）');
  const m1 = await dt.mtr('127.0.0.1', { maxHops: 5, rounds: 2 });
  ok('mtr 返回结构且含 diagnosis', m1 && m1.diagnosis && Array.isArray(m1.hops), m1.ok ? `hops=${m1.hopCount}` : ('ok:false → ' + (m1.error || '').slice(0, 40)));
  ok('mtr 含 charts 序列结构', m1.diagnosis && (!m1.ok || (m1.charts && m1.charts.latency && m1.charts.loss)), m1.ok ? 'latency+loss' : '不可用');

  section('C. PCAP 关联分析');
  const capFiles = fs.existsSync(CAP_DIR) ? fs.readdirSync(CAP_DIR).filter(f => f.endsWith('.pcap') || f.endsWith('.pcapng')) : [];
  const sample = capFiles[0];
  const missFile = await dt.pcapCorrelate({ file: 'no_such_file.pcap' });
  ok('PCAP 文件不存在时优雅报错', missFile.ok === false && /抓包文件不存在/.test(missFile.error || ''));
  if (sample) {
    const pc = await dt.pcapCorrelate({ file: sample, host: '', port: '' });
    ok('pcapCorrelate 解析样例文件', pc.ok && pc.kpi && Array.isArray(pc.byProto) && typeof pc.matchedSessions === 'number', `file=${sample} matched=${pc.matchedSessions} retrans=${pc.kpi.retransRate}%`);
    ok('pcapCorrelate 问题会话结构正确', pc.ok && Array.isArray(pc.problemSessions) && pc.problemSessions.every(s => 'srcIp' in s && 'retrans' in s && 'handshakeMs' in s));
    const pcF = await dt.pcapCorrelate({ file: sample, host: '10.252.28.99', port: '' });
    ok('按主机过滤后范围收窄或为空（不崩）', pcF.ok && typeof pcF.matchedSessions === 'number', `scope=${pcF.scope} matched=${pcF.matchedSessions}`);
  } else {
    skipped('无样例 pcap 文件，跳过 PCAP 解析实证');
  }

  /* ------------------------- B 段：接口级（可选） ------------------------- */
  section('D. 接口级（需本地服务，可跳过）');
  let token = null;
  try {
    const lr = await req('POST', '/api/auth/login', { username: 'admin', password: 'admin@123' });
    if (lr.status === 200 && lr.data && lr.data.token) { token = lr.data.token; ok('登录成功', true); }
    else skipped('登录失败，跳过接口级', JSON.stringify(lr.data).slice(0, 60));
  } catch (e) { skipped('本地服务不可用，跳过接口级', String(e.message || e).slice(0, 60)); }

  if (token) {
    const peR = await req('POST', '/api/deep/port-error', { host: HOST, port: PORT }, token);
    ok('POST /api/deep/port-error 200', peR.status === 200 && peR.data && peR.data.ok, peR.status + (peR.data && peR.data.error ? ' ' + peR.data.error : ''));
    const blR = await req('POST', '/api/deep/port-error/baseline', { host: HOST, port: PORT }, token);
    ok('POST /api/deep/port-error/baseline 200', blR.status === 200 && blR.data && blR.data.ok);
    const mR = await req('POST', '/api/deep/mtr', { target: '127.0.0.1' }, token);
    ok('POST /api/deep/mtr 200', mR.status === 200 && mR.data && 'diagnosis' in mR.data, mR.status + '');
    if (sample) {
      const pcR = await req('POST', '/api/deep/pcap', { file: sample }, token);
      ok('POST /api/deep/pcap 200', pcR.status === 200 && pcR.data && pcR.data.ok, pcR.status + (pcR.data && pcR.data.error ? ' ' + pcR.data.error : ''));
    }
    const noPerm = await req('POST', '/api/deep/mtr', { target: 'x' }); // 无 token → 401
    ok('未登录访问 /api/deep/mtr 被拒(401)', noPerm.status === 401, 'status=' + noPerm.status);
  }

  console.log(`\n结果：PASS ${pass} / FAIL ${fail} / SKIP ${skip}`);
  if (fail) { console.log('失败项：\n - ' + fails.join('\n - ')); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error('自检异常：', e); process.exit(2); });
