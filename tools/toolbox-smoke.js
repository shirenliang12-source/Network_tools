'use strict';
/**
 * 网络运维工具箱链路自检（NetToolbox 集成）
 *
 * 分两段：
 *   A 段（引擎级，无需服务）：子网计算 / URL 规整 / 私有网判断 / 速率换算 / 钳制
 *                          → 本地重定向服务器验证 redirectTrace 与 httpCheck
 *                          → 本机 OS 探测（ping / ifstat / mtr / fingerprint）
 *                          → 外网依赖项（whois / publicIp / sslCert / ntp / dns / wol）尽力探测
 *   B 段（接口级，需服务）：登录 → /api/toolbox/* 路由连通性 → 鉴权与 scan 权限门禁
 *
 * A 段刻意不依赖外部网络：重定向链用本地临时 HTTP 服务制造，结果可复现；
 * 外网依赖项若当前环境无出口则记 skip，不计入失败。
 *
 * 用法：node tools/toolbox-smoke.js [baseUrl]   （默认 http://127.0.0.1:8787）
 */
const http = require('http');
const tb = require('../server/toolbox');
const tbs = require('../server/toolbox-scan');
const snmpTools = require('../server/snmp-tools');

const BASE = (process.argv[2] || 'http://127.0.0.1:8787').replace(/\/+$/, '');

let pass = 0, fail = 0, skip = 0;
const fails = [];
const ok = (n, c, e) => {
  if (c) { pass++; console.log(`  ✓ ${n}${e ? ' — ' + e : ''}`); }
  else { fail++; fails.push(n); console.log(`  ✗ ${n}${e ? ' — ' + e : ''}`); }
};
const skipped = (n, e) => { skip++; console.log(`  ⊘ ${n}${e ? ' — ' + e : ''}`); };
// 外网依赖项：失败记 skip，不阻塞
const soft = async (n, fn) => {
  try { const r = await fn(); if (r && r.ok === false && r.error) return skipped(n, r.error); ok(n, true, r && r._note); }
  catch (e) { skipped(n, String(e && e.message || e).slice(0, 80)); }
};

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/** 起一个本地 HTTP 服务：/a 返回 302 跳 /b，/b 返回 200 */
function startRedirectServer() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      if (req.url === '/a') { res.writeHead(302, { Location: '/b' }); res.end(); }
      else { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<title>ok</title>hi'); }
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

(async () => {
  console.log('=== 网络运维工具箱自检（A 段：引擎级）===');

  /* ---------- 纯计算 ---------- */
  const sa = tb.subnetAnalyze('192.168.10.0/24');
  ok('subnet.analyze 192.168.10.0/24',
    sa.ok && sa.network === '192.168.10.0' && sa.prefix === 24 && sa.mask === '255.255.255.0' &&
    sa.broadcast === '192.168.10.255' && sa.firstHost === '192.168.10.1' && sa.lastHost === '192.168.10.254' &&
    sa.total === 256 && sa.usable === 254 && sa.addressClass === 'C' && sa.scope && sa.scope.indexOf('私有') >= 0,
    `net=${sa.network} mask=${sa.mask} usable=${sa.usable} class=${sa.addressClass}`);

  const sv = tb.subnetVlsm('192.168.0.0/24', [50, 20, 10]);
  ok('subnet.vlsm 分配 3 段', sv.ok && Array.isArray(sv.allocations) && sv.allocations.length === 3 &&
    sv.allocations.every(a => a.network && typeof a.prefix === 'string' && a.prefix.charAt(0) === '/'),
    `alloc=${sv.allocations ? sv.allocations.map(a => a.prefix).join(',') : 'NA'}`);

  ok('subnet.same 同段', tb.subnetSame('192.168.1.10', '192.168.1.20', 24).same === true);
  ok('subnet.same 跨段', tb.subnetSame('192.168.1.10', '192.168.2.10', 24).same === false);

  ok('normalizeUrl 补协议', tb.normalizeUrl('example.com') === 'http://example.com/');
  ok('isPrivateIp 私有', tb.isPrivateIp('10.0.0.1') === true && tb.isPrivateIp('192.168.1.1') === true);
  ok('isPrivateIp 公网', tb.isPrivateIp('8.8.8.8') === false);
  ok('humanBps 换算', /Mbps|bps|Kbps/.test(tb.humanBps(1048576)) && tb.humanBps(1048576) !== '0 bps');
  ok('SNMP 主机与 OID 校验', snmpTools.validHost('sw-core-01.example.local') === 'sw-core-01.example.local' &&
    snmpTools.validHost('bad host;$') === '' && snmpTools.normalizeOid('.1.3.6.1.2.1.1.5.0') === '1.3.6.1.2.1.1.5.0');
  const sgBad = await snmpTools.get({ host: 'bad host;$', version: '2c', community: 'public', oid: '1.3.6.1.2.1.1.5.0' });
  ok('SNMP GET 拒绝非法目标', sgBad.ok === false && /合法/.test(sgBad.error || ''), sgBad.error);
  const swBad = await snmpTools.walk({ host: '127.0.0.1', version: '2c', community: '', oid: 'bad-oid' });
  ok('SNMP WALK 拒绝非法 OID', swBad.ok === false && /OID/.test(swBad.error || ''), swBad.error);

  /* ---------- 本地重定向服务器：redirect + httpCheck ---------- */
  const { srv, port } = await startRedirectServer();
  const base = `http://127.0.0.1:${port}`;
  try {
    const rt = await tb.redirectTrace(base + '/a');
    ok('redirectTrace 追踪跳转', rt.ok && rt.hopCount === 2 && rt.redirectCount === 1 &&
      rt.finalStatus === 200 && Array.isArray(rt.hops),
      `hops=${rt.hopCount} redirect=${rt.redirectCount} final=${rt.finalStatus}`);
    ok('redirectTrace 无跨域/环路误报', rt.ok && !rt.notes.crossDomain && !rt.notes.loop,
      `notes=${JSON.stringify(rt.notes)}`);

    const hc = await tb.httpCheck(base + '/a', { followRedirects: true });
    ok('httpCheck 跟随跳转', hc.ok && hc.status === 200 && typeof hc.ms === 'number' && hc.ms >= 0,
      `status=${hc.status} ms=${hc.ms}`);
  } finally {
    srv.close();
  }

  /* ---------- 本机 OS 探测 ---------- */
  try {
    const pg = await tb.pingTest('127.0.0.1', { count: 3 });
    ok('pingTest 本机', pg.ok && pg.ip === '127.0.0.1' && typeof pg.loss === 'number' && typeof pg.avg === 'number',
      `loss=${pg.loss} avg=${pg.avg} grade=${pg.grade && pg.grade.level}`);
  } catch (e) { skipped('pingTest 本机', String(e.message || e).slice(0, 80)); }

  try {
    const ifs = await tb.ifstat({ intervalMs: 500 });
    ok('ifstat 适配器', ifs.ok && Array.isArray(ifs.adapters) && typeof ifs.totalRxBps === 'number',
      `adapters=${(ifs.adapters || []).length} rxBps=${ifs.totalRxBps}`);
  } catch (e) { skipped('ifstat', String(e.message || e).slice(0, 80)); }

  try {
    const mt = await tb.mtrTrace('127.0.0.1', { probes: 2 });
    ok('mtrTrace 本机', mt.ok && Array.isArray(mt.hops) && mt.hops.length >= 1,
      `hops=${(mt.hops || []).length} last=${mt.destination || (mt.hops && mt.hops[mt.hops.length - 1] && mt.hops[mt.hops.length - 1].ip)}`);
  } catch (e) { skipped('mtrTrace 本机', String(e.message || e).slice(0, 80)); }

  try {
    const fp = await tb.fingerprintHost('127.0.0.1', { ports: [135, 445], timeoutMs: 800 });
    ok('fingerprintHost 本机', fp.ok && typeof fp.openCount === 'number' && Array.isArray(fp.openPorts),
      `open=${fp.openCount} os=${fp.osGuess && fp.osGuess.name}`);
  } catch (e) { skipped('fingerprintHost 本机', String(e.message || e).slice(0, 80)); }

  /* ---------- 外网依赖项（尽力，失败记 skip）---------- */
  await soft('whoisLookup example.com', async () => {
    const r = await tb.whoisLookup('example.com', { timeoutMs: 8000 });
    if (!r.ok) return r;
    r._note = `registrar=${r.registrar || 'NA'} events=${(r.events || []).length}`;
    return r;
  });
  await soft('publicIp 获取', async () => {
    const r = await tb.publicIp({ timeoutMs: 8000 });
    if (!r.ok) return r;
    r._note = `ip=${r.ip}`;
    return r;
  });
  await soft('sslCert www.baidu.com', async () => {
    const r = await tb.sslCert('www.baidu.com', { port: 443, timeoutMs: 8000 });
    if (!r.ok) return r;
    r._note = `issuer=${r.issuer && (r.issuer.CN || r.issuer.O) || 'NA'} daysLeft=${r.daysLeft}`;
    return r;
  });
  await soft('ntpQuery 公共服务器', async () => {
    const r = await tb.ntpQuery({ servers: ['ntp.aliyun.com', 'time.google.com'], timeoutMs: 6000 });
    if (!r.ok) return r;
    r._note = `usable=${r.usableCount}`;
    return r;
  });
  await soft('dnsDiag baidu.com', async () => {
    const r = await tb.dnsDiag('baidu.com', { timeoutMs: 8000 });
    if (!r.ok) return r;
    r._note = `consistent=${r.consistent}`;
    return r;
  });
  await soft('wolWake 构造并发送', async () => {
    const r = await tb.wolWake('00:11:22:33:44:55', { ip: '255.255.255.255', port: 9, timeoutMs: 2000 });
    if (!r.ok) return r;
    r._note = `sentCount=${r.sentCount}`;
    return r;
  });

  /* ---------- 新模块：扫描/发现/安全/无线（engine 级，本机探测）---------- */
  console.log('\n--- 扫描发现模块（本机探测，失败记 skip）---');
  // 纯计算
  const e1 = tbs.expandTargets('192.168.1.0/30');
  ok('expandTargets /30 → 2 主机', Array.isArray(e1) && e1.length === 2 && e1[0] === '192.168.1.1' && e1[1] === '192.168.1.2',
    `len=${Array.isArray(e1) ? e1.length : 'NA'}`);
  const e2 = tbs.expandTargets('192.168.1.1-192.168.1.3');
  ok('expandTargets 范围 → 3 主机', Array.isArray(e2) && e2.length === 3, `len=${Array.isArray(e2) ? e2.length : 'NA'}`);
  const e3 = tbs.expandTargets('10.0.0.1,10.0.0.5');
  ok('expandTargets 逗号组合 → 2 主机', Array.isArray(e3) && e3.length === 2, `len=${Array.isArray(e3) ? e3.length : 'NA'}`);
  const e4 = tbs.expandTargets('192.168.1.0/24');
  ok('expandTargets /24 → 254 主机', Array.isArray(e4) && e4.length === 254, `len=${Array.isArray(e4) ? e4.length : 'NA'}`);
  let tooLarge = '';
  try { tbs.expandTargets('10.0.0.0/8'); } catch (e) { tooLarge = e.message; }
  ok('expandTargets 拒绝超大网段', /上限 4096/.test(tooLarge), tooLarge);
  let invalidIp = '';
  try { tbs.expandTargets('999.1.1.1'); } catch (e) { invalidIp = e.message; }
  ok('expandTargets 拒绝非法 IPv4', /无法解析目标/.test(invalidIp), invalidIp);
  const autoTargets = tbs.expandTargets('auto');
  ok('expandTargets auto 最多扫描 /24', autoTargets.length <= 254, `len=${autoTargets.length}`);
  const pp = tbs.parsePorts('80,443,1000-1002');
  ok('parsePorts 解析', Array.isArray(pp) && pp.length === 5 && pp.includes(1000) && pp.includes(1002),
    `len=${Array.isArray(pp) ? pp.length : 'NA'}`);

  const vl = tbs.vendorLookup('00:0c:29:ab:cd:ef');
  ok('vendorLookup OUI → 厂商', typeof vl === 'string' && vl.length > 0 && /VMware/i.test(vl),
    `vendor=${vl}`);
  const vn = tbs.vendor({ mac: '00:0c:29:ab:cd:ef' });
  ok('vendor() 返回结构', vn.ok === true && vn.oui === '00:0c:29' && /VMware/i.test(vn.vendor), `oui=${vn.oui} vendor=${vn.vendor}`);

  // 本机网络探测（localhost，快速）
  try { const r = await tbs.portscan({ host: '127.0.0.1', ports: '135,445', timeout: 500, banner: false });
    ok('portscan 本机', r.ok === true && typeof r.open === 'number' && r.open === 2 && Array.isArray(r.ports) && r.scanned === 2,
      `open=${r.open} scanned=${r.scanned}`); }
  catch (e) { skipped('portscan 本机', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.hostname({ ip: '127.0.0.1', timeout: 800 });
    ok('hostname 本机', r.ok === true && r.ip === '127.0.0.1', `name=${r.name || 'NA'}`); }
  catch (e) { skipped('hostname 本机', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.security({ target: '127.0.0.1', timeout: 300, ports: '135,445' });
    ok('security 本机', r.ok === true && typeof r.risk_score === 'number' && r.level && r.severity_count,
      `score=${r.risk_score} level=${r.level} findings=${r.findings.length}`); }
  catch (e) { skipped('security 本机', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.session({ host: '127.0.0.1', port: 135, count: 3, timeout: 500, concurrency: 3 });
    ok('session 本机', r.ok === true && r.attempts === 3 && r.success === 3 && typeof r.success_rate === 'number',
      `attempts=${r.attempts} success=${r.success} rate=${r.success_rate}%`); }
  catch (e) { skipped('session 本机', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.discovery({ target: '127.0.0.1', methods: ['tcp'], timeout: 400, threads: 4 });
    ok('discovery 本机', r.ok === true && Array.isArray(r.found), `total=${r.total} found=${r.found.length}`); }
  catch (e) { skipped('discovery 本机', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.ipconflict({ target: '127.0.0.1', timeout: 400 });
    ok('ipconflict 本机', r.ok === true && Array.isArray(r.mappings) && Array.isArray(r.conflicts),
      `total=${r.total} mappings=${r.mappings.length} conflicts=${r.conflicts.length}`); }
  catch (e) { skipped('ipconflict 本机', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.topology({ target: '127.0.0.1' });
    ok('topology 本机', r.ok === true && Array.isArray(r.nodes) && Array.isArray(r.edges), `nodes=${r.nodes.length} edges=${r.edges.length}`); }
  catch (e) { skipped('topology 本机', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.camera({ target: '127.0.0.1', timeout: 400 });
    ok('camera 本机', r.ok === true && Array.isArray(r.devices) && typeof r.scanned === 'number', `devices=${r.devices.length} scanned=${r.scanned}`); }
  catch (e) { skipped('camera 本机', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.wifi();
    ok('wifi 返回结构', r.ok === true && Array.isArray(r.networks), `networks=${r.networks.length}`); }
  catch (e) { skipped('wifi', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.dhcp();
    ok('dhcp 返回结构', r.ok === true && Array.isArray(r.interfaces) && Array.isArray(r.dhcp_servers), `interfaces=${r.interfaces.length} dhcp=${r.dhcp_servers.length}`); }
  catch (e) { skipped('dhcp', String(e.message || e).slice(0, 80)); }

  try { const r = await tbs.netcheck();
    ok('netcheck 返回结构', r.ok === true && typeof r.score === 'number' && r.level && Array.isArray(r.items),
      `score=${r.score} level=${r.level} items=${r.items.length}`); }
  catch (e) { skipped('netcheck', String(e.message || e).slice(0, 80)); }

  /* ============ B 段：接口级（需服务）============ */
  console.log('\n=== 网络运维工具箱自检（B 段：接口级）===');
  let apiReachable = false;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 1500);
    const r = await fetch(BASE + '/healthz', { signal: ctrl.signal });
    clearTimeout(t);
    apiReachable = r.ok;
  } catch { apiReachable = false; }

  if (!apiReachable) {
    console.log('  ⊘ 未检测到服务（' + BASE + '），B 段跳过');
  } else {
    const j = (p, body, token) => fetch(BASE + p, {
      method: body ? 'POST' : 'GET',
      headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}),
      body: body ? JSON.stringify(body) : undefined
    });
    try {
      const login = await (await j('/api/auth/login', { username: 'admin', password: 'admin@123' })).json();
      const tok = login.token;
      ok('B 登录 admin', !!tok);

      const sub = await (await j('/api/toolbox/subnet', { mode: 'analyze', spec: '10.0.0.0/8' }, tok)).json();
      ok('B /toolbox/subnet 路由连通', sub.ok === true && sub.network === '10.0.0.0', `net=${sub.network}`);

      const ping = await j('/api/toolbox/ping', { host: '127.0.0.1', opts: { count: 2 } }, tok);
      ok('B /toolbox/ping 需 scan 权限(admin 可)', ping.status === 200);

      const au = await (await j('/api/auth/login', { username: 'audit', password: 'audit@123' })).json();
      const atok = au.token;
      const pingDeny = await j('/api/toolbox/ping', { host: '127.0.0.1' }, atok);
      ok('B 审计角色无 scan 被拒(403)', pingDeny.status === 403, `http=${pingDeny.status}`);
      const subAllow = await (await j('/api/toolbox/subnet', { mode: 'analyze', spec: '192.168.0.0/16' }, atok)).json();
      ok('B 审计角色可读类工具(200)', subAllow.ok === true, `http=ok`);

      // 新模块 12 个 /toolbox/* 路由：连通性 + scan/auth 门禁
      const newRoutes = [
        ['/api/toolbox/portscan',   'scan', { host: '127.0.0.1', ports: '135', timeout: 400 }],
        ['/api/toolbox/discovery',  'scan', { target: '127.0.0.1', methods: ['tcp'], timeout: 400 }],
        ['/api/toolbox/hostname',   'scan', { ip: '127.0.0.1', timeout: 400 }],
        ['/api/toolbox/vendor',     'auth', { mac: '00:0c:29:ab:cd:ef' }],
        ['/api/toolbox/wifi',       'scan', {}],
        ['/api/toolbox/ipconflict', 'scan', { target: '127.0.0.1', timeout: 400 }],
        ['/api/toolbox/dhcp',       'auth', {}],
        ['/api/toolbox/security',   'scan', { target: '127.0.0.1', ports: '135,445', timeout: 300 }],
        ['/api/toolbox/netcheck',   'auth', {}],
        ['/api/toolbox/topology',   'scan', { target: '127.0.0.1' }],
        ['/api/toolbox/session',    'scan', { host: '127.0.0.1', port: 135, count: 2, timeout: 400 }],
        ['/api/toolbox/camera',     'scan', { target: '127.0.0.1', timeout: 400 }],
        ['/api/toolbox/snmp-get',   'scan', { host: 'bad host;$', version: '2c', community: 'public', oid: '1.3.6.1.2.1.1.5.0' }],
        ['/api/toolbox/snmp-walk',  'scan', { host: '127.0.0.1', version: '2c', community: 'public', oid: 'bad-oid' }],
      ];
      for (const [p, perm, body] of newRoutes) {
        try {
          const r = await j(p, body, tok);
          ok('B ' + p + ' admin 连通', r.status === 200, 'http=' + r.status);
          if (perm === 'scan') {
            const deny = await j(p, body, atok);
            ok('B ' + p + ' 审计被拒(403)', deny.status === 403, 'http=' + deny.status);
          } else {
            const allow = await j(p, body, atok);
            ok('B ' + p + ' 审计可读(200)', allow.status === 200, 'http=' + allow.status);
          }
        } catch (e) { ok('B ' + p, false, String(e.message || e).slice(0, 80)); }
      }
    } catch (e) { ok('B 接口级执行', false, String(e.message || e).slice(0, 80)); }
  }

  console.log(`\n=== 工具箱自检完成：通过 ${pass} 项，失败 ${fail} 项，跳过 ${skip} 项 ===`);
  if (fail) { console.log('失败项：\n - ' + fails.join('\n - ')); process.exit(1); }
  process.exit(0);
})();
