'use strict';
/**
 * 无线勘测自检
 *   A 段（引擎级，无需服务）：信号换算、频率→信道、距离模型、AP 三边定位、采样点持久化、
 *                           无网卡时扫描/探测优雅返回
 *   B 段（接口级，可选）：若本地有服务则登录并验证 /api/wifi/* 路由连通与权限门禁
 *
 * 用法：node tools/wifi-smoke.js [baseUrl]   （默认 http://127.0.0.1:8787）
 */
const http = require('http');

const wifi = require('../server/wifi');

const BASE = (process.argv[2] || 'http://127.0.0.1:8787').replace(/\/+$/, '');

let pass = 0, fail = 0, skip = 0;
const fails = [];
const ok = (n, c, e) => { if (c) { pass++; console.log(`  ✓ ${n}${e ? ' — ' + e : ''}`); } else { fail++; fails.push(n); console.log(`  ✗ ${n}${e ? ' — ' + e : ''}`); } };
const skipped = (n, e) => { skip++; console.log(`  ⊘ ${n}${e ? ' — ' + e : ''}`); };
const section = (t) => console.log('\n◆ ' + t);
const near = (a, b, tol) => Math.abs(a - b) <= tol;

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
  console.log('无线勘测自检');
  console.log('BASE = ' + BASE);

  /* ------------------------- A 段：引擎级 ------------------------- */
  section('A. 信号 / 频率 / 距离换算');
  ok('pctToDbm(92%)=-54dBm', wifi.pctToDbm(92) === -54, String(wifi.pctToDbm(92)));
  ok('pctToDbm(100%)=-50dBm', wifi.pctToDbm(100) === -50);
  const q = wifi.dbmToQuality(-54);
  ok('dbmToQuality(-54) 落在 60~70%', q >= 60 && q <= 70, String(q));
  ok('dbmToQuality(-100)=0%', wifi.dbmToQuality(-100) === 0);
  ok('freqToChannel(2437)=6', wifi.freqToChannel(2437) === 6, String(wifi.freqToChannel(2437)));
  ok('freqToChannel(2412)=1', wifi.freqToChannel(2412) === 1);
  ok('freqToChannel(5180)=36', wifi.freqToChannel(5180) === 36, String(wifi.freqToChannel(5180)));
  ok('rssiToDistance(-40,ref=-40)=1', near(wifi.rssiToDistance(-40, -40, 3), 1, 1e-6));
  ok('rssiToDistance(-70,ref=-40,n=3)=10', near(wifi.rssiToDistance(-70, -40, 3), 10, 1e-6));

  section('A2. netsh 输出解析（真实格式：带序号 / 中英双语 / 隐藏 SSID / 多 BSSID）');
  const NETSH_EN = [
    'Interface name : Wi-Fi',
    'There are 2 networks currently visible.',
    '',
    'SSID 1 : Corp-WiFi',
    '    Network type            : Infrastructure',
    '    Authentication          : WPA2-Personal',
    '    Encryption              : CCMP',
    '    BSSID 1                 : 8c:1a:bf:11:22:33',
    '         Signal             : 90%',
    '         Radio type         : 802.11n',
    '         Channel            : 11',
    '         Basic rates (Mbps) : 1 2 5.5 11',
    '    BSSID 2                 : 8c:1a:bf:11:22:44',
    '         Signal             : 70%',
    '         Radio type         : 802.11n',
    '         Channel            : 11',
    '',
    'SSID 2 : Guest',
    '    Authentication          : Open',
    '    Encryption              : None',
    '    BSSID 1                 : 8c:1a:bf:44:55:66',
    '         Signal             : 40%',
    '         Channel            : 149',
  ].join('\r\n');
  const en = wifi.parseNetsh(NETSH_EN).map(wifi.normalizeAp);
  ok('英文输出解析出 3 个 BSSID（SSID 1/BSSID 1 带序号不再漏匹配）', en.length === 3, `n=${en.length}`);
  ok('英文：BSSID 归一化为大写 MAC', en[0] && en[0].bssid === '8C:1A:BF:11:22:33', en[0] && en[0].bssid);
  ok('英文：name/signal/channel/security 解析正确', en[0] && en[0].ssid === 'Corp-WiFi' && en[0].quality === 90 && en[0].channel === 11 && /WPA2-Personal/.test(en[0].security), JSON.stringify(en[0]));
  ok('英文：多 BSSID 归属同一 SSID', en[1] && en[1].ssid === 'Corp-WiFi' && en[1].channel === 11, JSON.stringify(en[1]));

  const NETSH_ZH = [
    '接口名称 : Wi-Fi',
    '当前有 2 个网络可见。',
    '',
    'SSID 1 : 办公网',
    '    网络类型             : 基础结构',
    '    身份验证             : WPA2 - 个人',
    '    加密                 : CCMP',
    '    BSSID 1              : b0:4e:26:aa:bb:cc',
    '         信号              : 98%',
    '         无线电类型          : 802.11ax',
    '         频道              : 36',
    '         基本速率(Mbps)      : 6 12 24',
    '',
    'SSID 2 :',
    '    身份验证             : WPA3 - 个人',
    '    加密                 : GCMP',
    '    BSSID 1              : b0:4e:26:dd:ee:ff',
    '         信号              : 55%',
    '         频道              : 44',
  ].join('\r\n');
  const zh = wifi.parseNetsh(NETSH_ZH).map(wifi.normalizeAp);
  ok('中文输出解析出 2 个 BSSID（不依赖英文标签）', zh.length === 2, `n=${zh.length}`);
  ok('中文：SSID 中文名保留、信道/信号正确', zh[0] && zh[0].ssid === '办公网' && zh[0].quality === 98 && zh[0].channel === 36, JSON.stringify(zh[0]));
  ok('中文：空 SSID 的 BSSID 标为隐藏网络', zh[1] && zh[1].hidden === true && zh[1].bssid === 'B0:4E:26:DD:EE:FF', JSON.stringify(zh[1]));

  // 真机实测格式（含「波段/Bss 负载/连接的电台/QoS」噪声行）——回归：信道不得被计数行冲成 0
  const NETSH_REAL = [
    '  ',
    '接口名称 : WLAN ',
    '当前有 1 个网络可见。 ',
    '',
    'SSID 1 : ',
    '    Network type            : 结构',
    '    身份验证                : WPA2 - 企业',
    '    加密                    : CCMP ',
    '    BSSID 1                 : 4c:e1:75:1f:81:e6',
    '         信号             : 91%  ',
    '         无线电类型         : 802.11ac',
    '         波段               : 5 GHz',
    '         频道            : 157 ',
    '         Bss 负载:             ',
    '             连接的电台:        19',
    '             频道利用率:        28 (10% )',
    '             中可用容量:  23437 (749984 us/s)',
    '支持的         QoS MSCS： 0',
    '         支持的 QoS 映射 ： 0',
    '         基本速率(Mbps)     : 6 12 24',
    '         其他速率(Mbps)     : 9 18 36 48 54',
  ].join('\r\n');
  const real = wifi.parseNetsh(NETSH_REAL).map(wifi.normalizeAp);
  ok('真机格式：解析出 1 个隐藏 BSSID', real.length === 1 && real[0].hidden === true, `n=${real.length}`);
  ok('真机格式：信道=157（未被「连接的电台/QoS」计数行覆盖）', real[0] && real[0].channel === 157, 'channel=' + (real[0] && real[0].channel));
  ok('真机格式：信号 91% / -54dBm / 802.11ac', real[0] && real[0].quality === 91 && real[0].signal === -54 && real[0].radio === '802.11ac', JSON.stringify(real[0]));

  section('B. AP 三边定位（最小二乘）');
  const APx = 500, APy = 300, REF = -40, N = 3;
  const anchors = [[100, 100], [900, 120], [880, 520], [120, 500], [500, 90]];
  const synth = anchors.map(([x, y]) => {
    const d = Math.hypot(x - APx, y - APy);
    return { x, y, rssi: REF - 10 * N * Math.log10(d) };
  });
  const loc = wifi.locateAp(synth);
  ok('locateAp ok 且返回坐标', loc.ok && loc.x != null && loc.y != null, `(${loc.x}, ${loc.y})`);
  ok('定位接近真值 (500,300) ±30', near(loc.x, APx, 30) && near(loc.y, APy, 30), `err≈${Math.round(Math.hypot(loc.x - APx, loc.y - APy))}`);
  const loc2 = wifi.locateAp([{ x: 1, y: 1, rssi: -50 }, { x: 2, y: 2, rssi: -60 }]);
  ok('少于 3 点优雅报错', loc2.ok === false && /至少需要 3/.test(loc2.error || ''), loc2.error || '');

  section('C. 采样点持久化（data/wifi-samples.json）');
  const payload = { floorImage: '', floorName: 't', samples: [{ ssid: 'TestAP', bssid: 'aa:bb:cc:dd:ee:ff', x: 10, y: 20, rssi: -55 }] };
  const saved = wifi.saveSamples(payload);
  const loaded = wifi.loadSamples();
  ok('saveSamples 归一化并计算 quality', saved.samples.length === 1 && saved.samples[0].quality === wifi.dbmToQuality(-55), `quality=${saved.samples[0].quality}`);
  ok('loadSamples 回读一致', loaded.samples.length === 1 && loaded.samples[0].bssid === 'AA:BB:CC:DD:EE:FF' && loaded.samples[0].x === 10);
  wifi.saveSamples({ floorImage: '', floorName: '', samples: [] });   // 清理
  ok('清理后为 0 个测点', wifi.loadSamples().samples.length === 0);

  section('D. 无无线网卡时的优雅返回');
  const apis = await wifi.getWirelessInterfaces();
  ok('getWirelessInterfaces 返回数组', Array.isArray(apis), `n=${apis.length}`);
  const scan = await wifi.scanWifi();
  ok('scanWifi 返回 ok 且 aps 为数组', scan.ok === true && Array.isArray(scan.aps), `aps=${scan.aps.length} ${scan.note || ''}`);
  const probe = await wifi.probeHidden({});
  ok('probeHidden 空参优雅报错', probe.ok === false && /请提供/.test(probe.error || ''), probe.error || '');
  const probe2 = await wifi.probeHidden({ ssid: 'NotExist-SSID' });
  ok('probeHidden 无命中不崩且 ok', probe2.ok === true && probe2.probed === false, probe2.note || '');

  /* ------------------------- B 段：接口级（可选） ------------------------- */
  section('E. 接口级（需本地服务，可跳过）');
  let token = null;
  try {
    const lr = await req('POST', '/api/auth/login', { username: 'admin', password: 'admin@123' });
    if (lr.status === 200 && lr.data && lr.data.token) { token = lr.data.token; ok('登录成功', true); }
    else skipped('登录失败，跳过接口级', JSON.stringify(lr.data).slice(0, 60));
  } catch (e) { skipped('本地服务不可用，跳过接口级', String(e.message || e).slice(0, 60)); }

  if (token) {
    const ifR = await req('GET', '/api/wifi/interfaces', null, token);
    ok('GET /api/wifi/interfaces 200', ifR.status === 200 && ifR.data && ifR.data.ok, ifR.status + '');
    const scR = await req('POST', '/api/wifi/scan', {}, token);
    ok('POST /api/wifi/scan 200', scR.status === 200 && scR.data && scR.data.ok, scR.status + '');
    const loc3 = await req('POST', '/api/wifi/locate', { samples: synth.map(s => ({ x: s.x, y: s.y, rssi: s.rssi })) }, token);
    ok('POST /api/wifi/locate 200 且定位成功', loc3.status === 200 && loc3.data && loc3.data.ok, loc3.status + '');
    const smR = await req('GET', '/api/wifi/samples', null, token);
    ok('GET /api/wifi/samples 200', smR.status === 200 && smR.data && smR.data.ok, smR.status + '');
    const noAuth = await req('POST', '/api/wifi/scan', {});      // 无 token → 401
    ok('未登录访问 /api/wifi/scan 被拒(401)', noAuth.status === 401, 'status=' + noAuth.status);
  }

  console.log(`\n结果：PASS ${pass} / FAIL ${fail} / SKIP ${skip}`);
  if (fail) { console.log('失败项：\n - ' + fails.join('\n - ')); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error('自检异常：', e); process.exit(2); });
