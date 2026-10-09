'use strict';
/**
 * 无线勘测引擎（跨平台）
 * - 被动扫描：Windows netsh / Linux iw / macOS airport
 * - 隐藏 SSID 定向探测：Linux iw ... scan ssid / macOS airport ... scan / Windows 临时配置文件
 * - AP 三边定位（最小二乘）/ 距离换算 / 信号换算
 *
 * 注意：沙箱通常无无线网卡，所有命令均带 watchdog，无网卡时优雅返回空列表。
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const store = require('./store');

const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';

/* ------------------------------- 输出编码识别 -------------------------------
   Windows 控制台程序（netsh）在中文系统上以本地代码页（GBK/CP936）输出，
   直接 toString('utf8') 会把中文标签变成乱码。这里先按 UTF-8 解，
   一旦出现替换字符（\uFFFD）就退回 GBK/GB18030，保证标签可读。 */
function decodeBuf(buf) {
  if (!buf || !buf.length) return '';
  if (!IS_WIN) return buf.toString('utf8');
  const utf8 = buf.toString('utf8');
  if (!utf8.includes('\uFFFD')) return utf8;
  for (const enc of ['gbk', 'gb18030']) {
    try { return new TextDecoder(enc).decode(buf); } catch (e) { /* ICU 缺失时退到下一步 */ }
  }
  return buf.toString('latin1');
}

/* ------------------------------- 命令执行（带 watchdog） ------------------------------- */
function run(cmd, args, timeoutMs = 9000) {
  return new Promise((resolve) => {
    let settled = false;
    const outBufs = [], errBufs = [];
    let cp;
    try {
      cp = spawn(cmd, args, { windowsHide: true });
    } catch (e) {
      return resolve({ out: '', err: e.message, code: -2 });
    }
    const done = (code, extraErr) => {
      if (settled) return; settled = true; clearTimeout(t);
      resolve({ out: decodeBuf(Buffer.concat(outBufs)), err: decodeBuf(Buffer.concat(errBufs)) + (extraErr || ''), code });
    };
    const t = setTimeout(() => { try { cp.kill('SIGKILL'); } catch (e) {} done(-1, '\n[TIMEOUT]'); }, timeoutMs);
    cp.stdout.on('data', (d) => outBufs.push(Buffer.from(d)));
    cp.stderr.on('data', (d) => errBufs.push(Buffer.from(d)));
    cp.on('close', (code) => done(code, ''));
    cp.on('error', (e) => done(-2, '\n' + e.message));
  });
}

/* ------------------------------- 换算工具 ------------------------------- */
function pctToDbm(pct) { return Math.round((pct || 0) / 2 - 100); }            // Windows netsh 信号% -> dBm
function dbmToQuality(dbm) {                                                   // dBm -> 质量%
  if (dbm == null || isNaN(dbm)) return null;
  const q = Math.round(((dbm + 100) * 100) / 70);
  return Math.max(0, Math.min(100, q));
}
function freqToChannel(freq) {
  if (!freq) return null;
  if (freq >= 2412 && freq <= 2484) return Math.round((freq - 2412) / 5) + 1;   // 2.4G
  if (freq >= 5170 && freq <= 5825) return (freq - 5000) / 5;                    // 5G
  if (freq >= 5955 && freq <= 7115) return (freq - 5955) / 5 + 1;               // 6G
  return null;
}
function rssiToDistance(rssi, ref = -40, n = 3) {
  if (rssi == null || isNaN(rssi)) return null;
  return Math.pow(10, (ref - rssi) / (10 * n));   // 对数距离路径损耗模型
}
function normalizeAp(a) {
  a.ssid = (a.ssid || '').trim();
  a.bssid = (a.bssid || '').toUpperCase().trim();
  a.hidden = !a.ssid;
  if (a.signal == null && a.quality != null) a.signal = pctToDbm(a.quality);
  if (a.quality == null && a.signal != null) a.quality = dbmToQuality(a.signal);
  if (a.channel == null && a.freq) a.channel = freqToChannel(a.freq);
  a.security = a.security || a.auth || '';
  delete a.auth; delete a.enc; delete a.cap; delete a.freq;   // 保留 radio（无线电类型）便于展示
  return a;
}

/* ------------------------------- 接口枚举 ------------------------------- */
async function getWirelessInterfaces() {
  try {
    if (IS_WIN) {
      const r = await run('netsh', ['wlan', 'show', 'interfaces'], 8000);
      const out = r.out + '\n' + r.err;
      if (/no wireless interface|There is no wireless|无线接口|未安装/i.test(out)) return [];
      // 结构化解法：接口块的首条「标签 : 值」其值即接口名（中文系统标签为“名称”，
      // 原实现只认英文 "Name" 会漏）。按空行分块，每块取第一条带值的行。
      const names = [];
      for (const block of out.split(/\n\s*\n/)) {
        for (const raw of block.split(/\r?\n/)) {
          const m = raw.replace(/\t/g, ' ').match(/^\s*[^:：]+[:：]\s*(\S.*?)\s*$/);
          if (m && m[1]) { names.push(m[1]); break; }   // 每块首个属性 = 接口名
        }
      }
      return [...new Set(names)];
    }
    if (IS_MAC) {
      const r = await run('networksetup', ['-listallhardwareports'], 8000);
      const out = r.out + r.err;
      const ports = [];
      const re = /Hardware Port:\s*Wi-Fi[\s\S]*?Device:\s*(\w+)/g; let m;
      while ((m = re.exec(out))) ports.push(m[1]);
      return ports.length ? ports : ['en0'];
    }
    // Linux：遍历 /sys/class/net 找 wireless 目录
    const netDir = '/sys/class/net';
    if (fs.existsSync(netDir)) {
      const ifs = fs.readdirSync(netDir).filter((i) => fs.existsSync(path.join(netDir, i, 'wireless')));
      if (ifs.length) return ifs;
    }
    const r = await run('iw', ['dev'], 6000);
    const out = r.out + r.err;
    const re = /Interface\s+(\w+)/g; const list = []; let m;
    while ((m = re.exec(out))) list.push(m[1]);
    return list;
  } catch (e) {
    return [];
  }
}

/* ------------------------------- 被动扫描 ------------------------------- */
/* 解析 `netsh wlan show networks mode=bssid` 输出。
   设计为「结构化 + 多语言 + 容编码」：
   - 锚点只用 ASCII（SSID / BSSID / NN% / MAC），不依赖本地化标签文本；
   - 支持带序号写法 `SSID 1 :` / `BSSID 1 :`（原实现因正则不允许数字而整行漏匹配）；
   - 中文系统的「信号/频道/身份验证」等标签乱码也不影响解析。
   真实输出形如：
     SSID 1 : MyNet
         网络类型    : 基础结构          （英文系统为 Network type）
         身份验证    : WPA2 - 个人       （Authentication）
         加密        : CCMP              （Encryption）
         BSSID 1     : aa:bb:cc:dd:ee:ff
              信号          : 90%       （Signal）
              无线电类型    : 802.11n    （Radio type）
              频道          : 11         （Channel）
              基本速率(Mbps): 1 2 5.5 11  （Basic rates）
*/
// 标签需“整体匹配”，避免「频道利用率」(channel utilization) 被当成「频道」(channel)
const NETSH_KEY = {
  signal: /^(signal|信号)$/i,
  channel: /^(channel|频道|信道)$/i,
  radio: /^(radio\s*type|无线电类型)$/i,
  auth: /^(authentication|身份验证)$/i,
  enc: /^(encryption|加密)$/i
};
function _pickByKey(arr, re) { for (const it of arr) if (re.test(it.key)) return it.val; return ''; }

function parseNetsh(text) {
  const aps = [];
  let curSsid = '', cur = null, preVals = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/\t/g, ' ');
    if (!line.trim()) continue;

    // SSID 行（可带序号；隐藏网络的值为空）
    let m = line.match(/^\s*SSID\s*\d*\s*[:：]\s*(.*)$/i);
    if (m) { curSsid = m[1].trim(); cur = null; preVals = []; continue; }

    // BSSID 行（可带序号，值为 MAC）
    m = line.match(/^\s*BSSID\s*\d*\s*[:：]\s*([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})/i);
    if (m) {
      cur = {
        ssid: curSsid,
        bssid: m[1].replace(/-/g, ':').toUpperCase(),
        signal: null, quality: null, channel: null, radio: '', security: ''
      };
      // SSID 与首个 BSSID 之间的属性为：网络类型 / 身份验证 / 加密（优先按标签识别，标签乱码时按位置兜底）
      const auth = _pickByKey(preVals, NETSH_KEY.auth) || (preVals.length >= 3 ? preVals[preVals.length - 2].val : (preVals[0] || {}).val);
      const enc = _pickByKey(preVals, NETSH_KEY.enc) || (preVals.length >= 3 ? preVals[preVals.length - 1].val : (preVals[1] || {}).val);
      cur.security = [auth, enc].filter(Boolean).join(' / ');
      aps.push(cur);
      continue;
    }

    // 通用「标签 : 值」行
    const g = line.match(/^\s*([^:：]+?)\s*[:：]\s*(.*)$/);
    if (!g) continue;
    const key = g[1].trim(), val = g[2].trim();

    if (!cur) { if (val) preVals.push({ key, val }); continue; }   // SSID 与首个 BSSID 之间的属性

    // —— BSSID 块内 ——
    if (NETSH_KEY.signal.test(key) || /^\d{1,3}\s*%$/.test(val)) {     // 信号（标签或 NN% 形态）
      const p = parseInt(val, 10);
      if (!isNaN(p)) { cur.quality = p; cur.signal = pctToDbm(p); }
      continue;
    }
    if (NETSH_KEY.channel.test(key)) {                                 // 信道（按标签，取首次）
      const c = parseInt(val, 10); if (!isNaN(c) && cur.channel == null) cur.channel = c;
      continue;
    }
    if (NETSH_KEY.radio.test(key) || /^802\.11/i.test(val)) { cur.radio = val; continue; }  // 无线电类型
    // 兜底（标签乱码时）：块内首个纯整数视为信道；排除「连接的电台/频道利用率/QoS/容量」等计数行，
    // 且已赋值不再覆盖，避免信道被冲成 0/19/28。
    if (cur.channel == null && /^\d+$/.test(val) && !/负载|电台|利用率|容量|qos|mscs|速率|rate/i.test(key)) {
      cur.channel = parseInt(val, 10); continue;
    }
  }
  return aps;
}
function parseIw(text) {
  const aps = []; let cur = null;
  for (const raw of text.split(/\r?\n/)) {
    const t = raw.replace(/\t/g, ' ').trim();
    if (/^BSS /i.test(t)) { const mac = t.split(/\s+/)[1]; cur = { bssid: mac, ssid: '', signal: null, channel: null }; aps.push(cur); continue; }
    if (!cur) continue;
    let m;
    if ((m = t.match(/^SSID:\s*(.*)$/))) cur.ssid = m[1];
    else if ((m = t.match(/^signal:\s*(-?[\d.]+)\s*dBm/))) { cur.signal = Math.round(parseFloat(m[1])); cur.quality = dbmToQuality(cur.signal); }
    else if ((m = t.match(/^freq:\s*(\d+)/))) { cur.freq = parseInt(m[1], 10); cur.channel = freqToChannel(cur.freq); }
    else if ((m = t.match(/^(RSN|WPA):/))) cur.security = (cur.security ? cur.security + ' ' : '') + m[1];
  }
  return aps;
}
function parseAirport(text) {
  const aps = [];
  for (const raw of text.split(/\r?\n/)) {
    const t = raw.replace(/\t/g, ' ').trim();
    if (!t) continue;
    const bm = t.match(/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/);
    if (!bm) continue;
    const bssid = bm[0];
    const parts = t.slice(bm.index + bssid.length).trim().split(/\s+/);
    const rssi = parseInt(parts[0], 10);
    const ch = parts[1] ? parts[1].split(',')[0] : '';
    const ssid = t.slice(0, bm.index).trim();
    aps.push({ bssid, ssid, signal: rssi, quality: dbmToQuality(rssi), channel: parseInt(ch, 10) || null, security: parts.slice(4).join(' ') });
  }
  return aps;
}

async function scanWifi(iface) {
  if (IS_WIN) {
    const r = await run('netsh', ['wlan', 'show', 'networks', 'mode=bssid'], 9000);
    const out = (r.out + '\n' + r.err).trim();
    if (/wlansvc|AutoConfig.*not running|无线自动配置服务|没有运行|not running/i.test(out)) {
      return { ok: true, aps: [], empty: true, note: '无线自动配置服务(WlanSvc)未运行：请以管理员执行 “net start wlansvc” 后重试' };
    }
    if (/no wireless interface|There is no wireless|无线接口|未安装|not supported/i.test(out)) {
      return { ok: true, aps: [], empty: true, note: '未检测到无线网卡（或无管理员权限）' };
    }
    const aps = parseNetsh(out).map(normalizeAp);
    if (!aps.length) {
      // 解析为 0 时保留原始输出，便于定位（编码/权限/服务问题）
      console.log('[wifi.scan] 解析到 0 个 AP，netsh 原始输出片段:\n' + out.slice(0, 1500));
      return { ok: true, aps: [], empty: true, iface: iface || 'Wi-Fi', raw: out.slice(0, 1500), note: '未解析到 AP（可展开原始输出排查：多为无线未开启/服务未运行/无管理员权限）' };
    }
    return { ok: true, aps, iface: iface || 'Wi-Fi' };
  }
  if (IS_MAC) {
    const r = await run('airport', [iface || 'en0', '-s'], 9000);
    const out = r.out + r.err;
    if (!out.trim()) return { ok: true, aps: [], empty: true, note: '未检测到无线网卡' };
    const aps = parseAirport(out).map(normalizeAp);
    return { ok: true, aps, iface: iface || 'en0' };
  }
  // Linux
  const r = await run('iw', ['dev', iface || 'wlan0', 'scan'], 9000);
  const out = r.out + r.err;
  if (/command failed|Operation not permitted|No such device/i.test(out)) return { ok: true, aps: [], empty: true, note: '扫描失败：' + out.trim().split('\n')[0] };
  const aps = parseIw(out).map(normalizeAp);
  return { ok: true, aps, iface: iface || 'wlan0' };
}

/* ------------------------------- 隐藏 SSID 定向探测 ------------------------------- */
async function probeHidden({ ssid, bssid, iface } = {}) {
  if (!ssid && !bssid) return { ok: false, error: '请提供要探测的 SSID 或 BSSID' };
  if (IS_WIN) {
    // 曲线方案：建临时配置文件（hiddenNetwork=true）+ 触发扫描，再从结果里捞
    try {
      const prof = `<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>${ssid}</name><SSIDConfig><SSID><name>${ssid}</name></SSID><hiddenNetwork>true</hiddenNetwork></SSIDConfig><connectionType>ESS</connectionType><connectionMode>manual</connectionMode><MSM><security><authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM></WLANProfile>`;
      const xmlPath = path.join(store.DATA_DIR, `wifi-probe-${Date.now()}.xml`);
      fs.writeFileSync(xmlPath, prof, 'utf8');
      await run('netsh', ['wlan', 'add', 'profile', `filename=${xmlPath}`], 6000);
      await run('netsh', ['wlan', 'scan'], 6000);
      const r = await run('netsh', ['wlan', 'show', 'networks', 'mode=bssid'], 9000);
      const aps = parseNetsh(r.out + r.err).map(normalizeAp);
      const hit = aps.filter(a => (ssid && a.ssid === ssid) || (bssid && a.bssid === bssid.toUpperCase()));
      try { fs.unlinkSync(xmlPath); } catch (e) {}
      return { ok: true, probed: !!hit.length, found: hit, note: hit.length ? '已暴露隐藏 SSID' : '未在当前环境中发现该隐藏网络（可能不在覆盖范围内）' };
    } catch (e) {
      return { ok: true, probed: false, found: [], note: 'Windows 定向探测失败：' + e.message };
    }
  }
  // Linux / macOS 直接定向扫描
  let r;
  if (IS_MAC) r = await run('airport', [iface || 'en0', 'scan', ssid].filter(Boolean), 9000);
  else r = await run('iw', ['dev', iface || 'wlan0', 'scan', 'ssid', ssid].filter(Boolean), 9000);
  const out = r.out + r.err;
  const aps = (IS_MAC ? parseAirport(out) : parseIw(out)).map(normalizeAp);
  const hit = aps.filter(a => (ssid && a.ssid === ssid) || (bssid && a.bssid === bssid.toUpperCase()));
  return { ok: true, probed: !!hit.length, found: hit, note: hit.length ? '已暴露隐藏 SSID' : '未发现该隐藏网络' };
}

/* ------------------------------- AP 三边定位（最小二乘） ------------------------------- */
function locateAp(samples, { ref = -40, n = 3, iters = 60, lr = 0.3 } = {}) {
  const pts = (samples || []).filter(s => s && s.x != null && s.y != null && s.rssi != null)
    .map(s => ({ x: +s.x, y: +s.y, d: rssiToDistance(+s.rssi, ref, n) }));
  if (pts.length < 3) return { ok: false, error: '至少需要 3 个有效测点（含坐标与 RSSI）', x: null, y: null, residual: null };
  // 种子：测点几何中心
  let x = pts.reduce((a, p) => a + p.x, 0) / pts.length;
  let y = pts.reduce((a, p) => a + p.y, 0) / pts.length;
  let residual = 0;
  for (let it = 0; it < iters; it++) {
    let gx = 0, gy = 0;
    residual = 0;
    for (const p of pts) {
      const dist = Math.hypot(p.x - x, p.y - y) || 1e-6;
      const err = dist - p.d;
      residual += err * err;
      const w = err / dist;            // 梯度方向
      gx += (x - p.x) * w;
      gy += (y - p.y) * w;
    }
    x -= lr * gx / pts.length;
    y -= lr * gy / pts.length;
  }
  residual = Math.sqrt(residual / pts.length);
  return { ok: true, x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10, residual: Math.round(residual * 100) / 100, points: pts.length };
}

/* ------------------------------- 采样点持久化 ------------------------------- */
const SAMPLES_FILE = path.join(store.DATA_DIR, 'wifi-samples.json');

function loadSamples() {
  try {
    if (fs.existsSync(SAMPLES_FILE)) return JSON.parse(fs.readFileSync(SAMPLES_FILE, 'utf8'));
  } catch (e) {}
  return { floorImage: '', floorName: '', samples: [] };
}
function saveSamples(obj) {
  const data = {
    floorImage: obj.floorImage || '',
    floorName: obj.floorName || '',
    samples: Array.isArray(obj.samples) ? obj.samples.map(s => ({
      id: s.id || store.uid('w'),
      ssid: (s.ssid || '').trim(),
      bssid: (s.bssid || '').toUpperCase().trim(),
      x: +s.x, y: +s.y,
      rssi: +s.rssi,
      quality: dbmToQuality(+s.rssi),
      channel: s.channel != null ? +s.channel : null,
      note: s.note || '',
      createdAt: s.createdAt || new Date().toISOString()
    })) : []
  };
  fs.writeFileSync(SAMPLES_FILE, JSON.stringify(data, null, 2), 'utf8');
  return data;
}

module.exports = {
  IS_WIN, IS_MAC,
  getWirelessInterfaces,
  scanWifi,
  probeHidden,
  locateAp,
  pctToDbm, dbmToQuality, freqToChannel, rssiToDistance,
  parseNetsh, parseIw, parseAirport, normalizeAp,
  loadSamples, saveSamples
};
