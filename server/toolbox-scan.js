'use strict';
/**
 * 网络运维工具箱 · 第二波能力（扫描发现 / 安全 / 无线 / 网络体检）
 * ---------------------------------------------------------------------------
 * 在 toolbox.js（诊断 / 工具类 12 项）基础上，原生移植 NetToolbox 的其余核心模块。
 * 全部基于 Node 内置模块 + Windows / Linux 系统命令（ping/arp/ipconfig/netsh/route），
 * 不引入任何新的 npm 依赖，pkg 可单文件打包。
 *
 *   portscan      TCP 端口扫描 + Banner/服务/产品识别
 *   discovery     主机发现（ARP 缓存 + ICMP Ping 扫 + TCP 探测）+ MAC/厂商
 *   hostname      反向 DNS 主机名解析
 *   vendor        MAC 厂商 OUI 查询（内置 1494 条常见厂商前缀）
 *   wifi          Wi-Fi 扫描（netsh wlan，含信号/信道/加密）
 *   ipconflict    IP 冲突检测（ARP 缓存比对 + 主动重探）
 *   dhcp          DHCP 信息探测（ipconfig /all 解析 DHCP 服务器/租约）
 *   security      安全自检（暴露面高危端口风险评分）
 *   netcheck      网络健康 7 维体检评分
 *   topology      网络拓扑自动发现（发现 + 厂商/主机名 enrichment）
 *   session       TCP 会话并发承压测试
 *   camera        摄像头 / 监控设备探测与品牌识别
 *
 * 安全边界：所有主动探测接口在 API 层要求 scan 权限；目标由已登录运维人员输入，
 * 请仅在自有或已获授权的网络内使用。
 */
const net = require('net');
const dns = require('dns');
const os = require('os');
const { execFile } = require('child_process');
const path = require('path');

const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const MAX_TARGETS = 4096;
const OUI = loadOui();

function loadOui() {
  try {
    return require('./oui.json');
  } catch {
    return {};
  }
}

/* =========================================================================
   通用工具
   ========================================================================= */
function clamp(v, lo, hi, def) {
  const n = Number(v);
  if (v === undefined || v === null || v === '' || Number.isNaN(n)) return def;
  return Math.max(lo, Math.min(hi, n));
}

/** execFile 的 Promise 版，永不 throw，返回 { ok, stdout, stderr, code } */
function execFileP(cmd, args, timeoutMs = 30000) {
  return new Promise(resolve => {
    execFile(cmd, args, { windowsHide: true, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout, stderr) => resolve({ ok: !err, stdout: stdout || '', stderr: stderr || '', code: err && err.code }));
  });
}

function isIPv4(s) {
  const parts = String(s || '').trim().split('.');
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function macNorm(mac) {
  if (!mac) return '';
  let m = String(mac).trim().toLowerCase().replace(/[^0-9a-f]/g, '');
  if (m.length !== 12) return '';
  return m.replace(/(.{2})/g, '$1:').slice(0, -1);
}

function macBytes(mac) {
  const m = macNorm(mac);
  if (!m) return null;
  return m.split(':').map(h => parseInt(h, 16));
}

/** 并发池：items 按 limit 并发执行 worker(item,index)，返回对齐的结果数组 */
async function runPool(items, limit, worker) {
  const out = new Array(items.length);
  let i = 0;
  const n = Math.min(limit, items.length || 1);
  const runners = Array.from({ length: n }, async () => {
    while (i < items.length) {
      const idx = i++;
      try { out[idx] = await worker(items[idx], idx); } catch { out[idx] = null; }
    }
  });
  await Promise.all(runners);
  return out;
}

/** netmask -> prefixlen */
function maskToPrefix(mask) {
  if (!mask) return 24;
  const p = mask.split('.').map(Number);
  let bits = 0;
  for (const o of p) { bits += Math.clz32(~o & 0xff) - 24 + (o === 0 ? 8 : 0); }
  // 简化：用位计数
  let b = 0, m = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
  while (m & 0x80000000) { b++; m <<= 1; }
  return b;
}

function ipToInt(ip) { return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0; }
function intToIp(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }

/* =========================================================================
   本地接口 / 网关 / 目标展开
   ========================================================================= */
function localInterfaces() {
  const ni = os.networkInterfaces();
  const out = [];
  for (const name of Object.keys(ni)) {
    for (const a of ni[name]) {
      if (a.family === 'IPv4' && !a.internal) {
        const prefix = maskToPrefix(a.netmask);
        const network = intToIp((ipToInt(a.address) & ipToInt(a.netmask)) >>> 0);
        out.push({
          name,
          ip: a.address,
          netmask: a.netmask,
          prefix,
          network,
          cidr: `${network}/${prefix}`,
        });
      }
    }
  }
  return out;
}

async function defaultGateway() {
  if (IS_WIN) {
    const r = await execFileP('route', ['print', '-4'], 8000);
    if (r.ok) {
      let capture = false;
      for (const line of r.stdout.split(/\r?\n/)) {
        if (/^\s*Network Destination/.test(line)) { capture = true; continue; }
        if (capture) {
          const m = line.trim().split(/\s+/);
          if (m.length >= 3 && m[0] === '0.0.0.0' && m[1] === '0.0.0.0' && isIPv4(m[2])) return m[2];
        }
      }
    }
    // 回退：PowerShell
    const ps = await execFileP('powershell', ['-NoProfile', '-Command',
      "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"], 8000);
    if (ps.ok) { const g = ps.stdout.trim(); if (isIPv4(g)) return g; }
    return '';
  }
  if (IS_MAC) {
    const r = await execFileP('route', ['-n', 'get', 'default'], 8000);
    if (r.ok) {
      const m = r.stdout.match(/gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})/i);
      if (m) return m[1];
    }
    const ns = await execFileP('netstat', ['-rn'], 8000);
    if (ns.ok) {
      const m = ns.stdout.match(/^default\s+(\d{1,3}(?:\.\d{1,3}){3})/m);
      if (m) return m[1];
    }
    return '';
  }
  const r = await execFileP('ip', ['route', 'show', 'default'], 8000);
  if (r.ok) {
    const m = r.stdout.split(/\s+/);
    for (let i = 0; i < m.length; i++) if (m[i] === 'via' && isIPv4(m[i + 1])) return m[i + 1];
  }
  return '';
}

/** 把目标字符串展开为 IP 列表；'auto' 取本机主网卡 IP 所在 /24。 */
function expandTargets(target) {
  target = (target || 'auto').trim();
  if (target === 'auto' || target === '') {
    const ifaces = localInterfaces().filter(i => !/docker|vmware|vbox|loopback/i.test(i.name));
    const ifc = ifaces[0] || localInterfaces()[0];
    if (!ifc) throw new Error('无法自动探测本机网段，请手动指定目标');
    target = `${ifc.ip.split('.').slice(0, 3).join('.')}.0/24`;
  }
  const ips = [];
  const ensureCapacity = (count, part) => {
    if (!Number.isSafeInteger(count) || count < 0 || ips.length + count > MAX_TARGETS) {
      throw new Error(`目标 ${part} 展开后超过单次上限 ${MAX_TARGETS}，请缩小网段或分批扫描`);
    }
  };
  for (let part of target.split(',')) {
    part = part.trim();
    if (!part) continue;
    if (part.includes('/')) {
      const segs = part.split('/');
      const base = segs[0];
      const pref = segs[1];
      if (segs.length !== 2 || !isIPv4(base) || !/^\d{1,2}$/.test(pref || '') || Number(pref) > 32) {
        throw new Error('无法解析目标: ' + part);
      }
      const p = Number(pref);
      const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
      const wildcard = (~mask) >>> 0;
      const netint = (ipToInt(base) & mask) >>> 0;
      const broadcast = (netint | wildcard) >>> 0;
      const start = p <= 30 ? netint + 1 : netint;
      const end = p <= 30 ? broadcast - 1 : broadcast;
      ensureCapacity(end - start + 1, part);
      for (let x = start; x <= end && x >= start; x++) ips.push(intToIp(x >>> 0));
    } else if (isIPv4(part)) {
      ensureCapacity(1, part);
      ips.push(part);
    } else if (part.includes('-')) {
      const [a, b] = part.split('-').map(s => s.trim());
      if (isIPv4(a) && isIPv4(b)) {
        let s = ipToInt(a), e = ipToInt(b);
        if (s > e) [s, e] = [e, s];
        ensureCapacity(e - s + 1, part);
        for (let x = s; x <= e; x++) ips.push(intToIp(x >>> 0));
      } else throw new Error('无法解析目标: ' + part);
    } else throw new Error('无法解析目标: ' + part);
  }
  // 去重保序
  const seen = new Set(); const uniq = [];
  for (const ip of ips) if (!seen.has(ip)) { seen.add(ip); uniq.push(ip); }
  return uniq;
}

/* =========================================================================
   TCP 端口扫描（portscan）
   ========================================================================= */
const COMMON_SERVICES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 69: 'tftp', 80: 'http',
  110: 'pop3', 111: 'rpcbind', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns', 138: 'netbios-dgm',
  139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 162: 'snmptrap', 389: 'ldap', 443: 'https',
  445: 'microsoft-ds', 465: 'smtps', 512: 'exec', 513: 'login', 514: 'shell', 587: 'submission',
  631: 'ipp', 636: 'ldaps', 873: 'rsync', 902: 'vmware-auth', 993: 'imaps', 995: 'pop3s',
  1025: 'nfs-or-dce', 1080: 'socks', 1433: 'ms-sql-s', 1521: 'oracle', 1723: 'pptp', 2049: 'nfs',
  2121: 'ccproxy-ftp', 2181: 'zookeeper', 3128: 'squid-http', 3306: 'mysql', 3389: 'ms-wbt-server',
  3690: 'svn', 4369: 'epmd', 5432: 'postgresql', 5555: 'adb', 5900: 'vnc', 5984: 'couchdb',
  6000: 'x11', 6379: 'redis', 7001: 'weblogic', 7070: 'realmserver', 8000: 'http-alt',
  8008: 'http-alt', 8080: 'http-proxy', 8081: 'http-alt', 8443: 'https-alt', 8888: 'http-alt',
  9000: 'sonarqube', 9042: 'cassandra', 9090: 'http-alt', 9100: 'jetdirect', 9200: 'elasticsearch',
  9300: 'elasticsearch', 10000: 'webmin', 11211: 'memcached', 27017: 'mongodb', 28017: 'mongodb-web',
  50000: 'saphostctrl', 50030: 'hadoop', 50070: 'hadoop-web',
};
const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
  512, 513, 514, 587, 631, 636, 873, 993, 995, 1433, 1521, 1723, 2049, 2181, 3306, 3389, 3690,
  5432, 5900, 5984, 6379, 7001, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 11211, 27017, 28017];

function parsePorts(spec) {
  if (Array.isArray(spec)) return Array.from(new Set(spec.map(Number).filter(n => n >= 1 && n <= 65535))).sort((a, b) => a - b);
  const ports = new Set();
  for (const part of String(spec || '').split(',')) {
    const p = part.trim();
    if (!p) continue;
    if (p.includes('-')) {
      const [a, b] = p.split('-').map(s => parseInt(s, 10));
      if (!Number.isNaN(a) && !Number.isNaN(b)) for (let x = a; x <= b; x++) if (x >= 1 && x <= 65535) ports.add(x);
    } else { const n = parseInt(p, 10); if (n >= 1 && n <= 65535) ports.add(n); }
  }
  return Array.from(ports).sort((a, b) => a - b);
}

function tcpConnect(ip, port, timeout) {
  return new Promise(resolve => {
    const s = new net.Socket();
    s.setTimeout(timeout);
    let done = false;
    const fin = v => { if (!done) { done = true; try { s.destroy(); } catch {} resolve(v); } };
    s.connect(port, ip, () => fin(true));
    s.on('timeout', () => fin(false));
    s.on('error', () => fin(false));
  });
}

function guessProduct(banner, service) {
  if (!banner) return '';
  let m = banner.match(/Server:\s*([^\r\n]+)/i);
  if (m) return m[1].trim();
  if (service === 'ssh' || /^ssh-/i.test(banner)) {
    m = banner.match(/SSH-\d[\d.]*-([^\r\n]+)/i);
    if (m) return /openssh/i.test(m[1]) ? 'OpenSSH' : m[1].trim();
  }
  if (service === 'ftp' && banner.startsWith('220')) return banner.slice(3).trim().slice(0, 60);
  if (/mysql/i.test(banner)) return 'MySQL';
  if (banner.startsWith('*') && /redis/i.test(banner)) return 'Redis';
  return banner.split('\r\n')[0].trim().slice(0, 60);
}

async function grabBanner(ip, port, timeout, service) {
  return new Promise(resolve => {
    const s = new net.Socket();
    s.setTimeout(Math.min(timeout, 1200));
    let done = false;
    const out = (service, banner, product) => { if (!done) { done = true; try { s.destroy(); } catch {} resolve({ service, banner, product }); } };
    s.connect(port, ip, () => {
      s.setTimeout(Math.min(timeout, 800));
      s.once('data', chunk => {
        let text = '';
        try { text = chunk.toString('utf8').replace(/\r/g, '').trim(); } catch { text = ''; }
        let svc = service || COMMON_SERVICES[port] || '';
        let probe = null;
        if (!text) {
          if ([80, 8080, 8000, 8888, 8008].includes(port)) {
            probe = `GET / HTTP/1.0\r\nHost: ${ip}\r\nUser-Agent: netops-toolbox\r\n\r\n`;
            svc = svc || 'http';
          } else if ([443, 8443].includes(port)) {
            probe = Buffer.from('1603010075010000710303' + '00'.repeat(32) +
              '0000040023000000' + '20'.repeat(32) + '00'.repeat(33), 'hex');
            svc = svc || 'https';
          } else if (port === 22) { svc = svc || 'ssh'; }
          else if ([25, 587, 465, 110, 143, 993, 995].includes(port)) { svc = svc || 'smtp'; }
        }
        if (probe) {
          s.setTimeout(Math.min(timeout, 1000));
          s.once('data', c2 => {
            const t2 = c2.toString('utf8').replace(/\r/g, '').trim();
            out(svc, text || t2.slice(0, 300), guessProduct(text || t2, svc));
          });
          try { s.write(probe); } catch { out(svc, text.slice(0, 300), guessProduct(text, svc)); }
        } else {
          out(svc, text.slice(0, 300), guessProduct(text, svc));
        }
      });
      if (!text_probe_pending(port, service)) {
        // 无欢迎 Banner 的端口：主动探测
      }
    });
    s.on('timeout', () => out(service || COMMON_SERVICES[port] || '', '', ''));
    s.on('error', () => out(service || COMMON_SERVICES[port] || '', '', ''));
  });
}
function text_probe_pending() { return false; }

async function scanPorts(ip, ports, timeout, banner) {
  const results = [];
  await runPool(ports, 50, async (port) => {
    const open = await tcpConnect(ip, port, timeout);
    if (!open) return;
    let service = COMMON_SERVICES[port] || '';
    let ban = '', product = '';
    if (banner) {
      try {
        const r = await grabBanner(ip, port, timeout, service);
        service = r.service || service; ban = r.banner || ''; product = r.product || '';
      } catch {}
    }
    results.push({ port, protocol: 'tcp', state: 'open', service, banner: ban, product });
  });
  results.sort((a, b) => a.port - b.port);
  return results;
}

function portscan({ host, ports, timeout, banner, threads } = {}) {
  return (async () => {
    if (!isIPv4(host)) return { ok: false, error: '请提供合法 IPv4 地址' };
    const portList = ports ? parsePorts(ports) : DEFAULT_PORTS;
    const to = clamp(timeout, 100, 5000, 500);
    const res = await scanPorts(host, portList, to, banner !== false);
    return { ok: true, host, scanned: portList.length, open: res.length, ports: res };
  })();
}

/* =========================================================================
   主机发现（discovery）
   ========================================================================= */
const PROBE_PORTS = [80, 443, 22, 445, 139, 53, 8080, 23, 3389, 135, 631];

function parseArpTable(stdout) {
  const map = {};
  for (const line of stdout.split(/\r?\n/)) {
    // Windows:  Internet Address   Physical Address   Type
    // Linux:    <ip> dev <if> lladdr <mac>
    // macOS/BSD: ? (192.168.1.1) at 9c:5c:8e:xx:xx:xx on en0 ...
    let m = line.match(/(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:[\s:-][0-9a-f]{2}){5})/i);
    if (!m) m = line.match(/\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i);
    if (!m) m = line.match(/(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+\S+\s+lladdr\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i);
    if (m) {
      const ip = m[1];
      const mac = macNorm(m[2]);
      if (mac && ip !== '0.0.0.0' && !ip.startsWith('127.')) map[ip] = mac;
    }
  }
  return map;
}

async function readArpCache() {
  const cmd = IS_WIN ? 'arp' : (IS_MAC ? 'arp' : 'ip');
  const args = IS_WIN ? ['-a'] : (IS_MAC ? ['-an'] : ['neigh']);
  const r = await execFileP(cmd, args, 8000);
  return r.ok ? parseArpTable(r.stdout) : {};
}

function parsePingWin(stdout) {
  if (/Reply from/i.test(stdout)) {
    const m = stdout.match(/time[<=]\s*(\d+(?:\.\d+)?)\s*ms/i);
    return { alive: true, latency: m ? parseFloat(m[1]) : -1 };
  }
  return { alive: false, latency: -1 };
}
function parsePingNix(stdout) {
  if (/bytes from|icmp_seq/i.test(stdout)) {
    const m = stdout.match(/time[<=]\s*([\d.]+)\s*ms/i);
    return { alive: true, latency: m ? parseFloat(m[1]) : -1 };
  }
  return { alive: false, latency: -1 };
}

async function pingOne(ip, timeout) {
  const w = Math.max(300, timeout);
  const args = IS_WIN ? ['-n', '1', '-w', String(w), ip] : ['-c', '1', '-W', String(Math.ceil(w / 1000)), ip];
  const r = await execFileP('ping', args, w + 3000);
  if (!r.ok && r.code !== 1) { // code 1 = 100% loss（仍算执行成功）
    if (!/未知主机|could not find|name or service/.test(r.stderr + r.stdout)) return { alive: false, latency: -1 };
  }
  return IS_WIN ? parsePingWin(r.stdout) : parsePingNix(r.stdout);
}

function tcpProbe(ip, ports, timeout) {
  return new Promise(resolve => {
    let best = -1;
    let i = 0;
    const tryNext = () => {
      if (i >= ports.length) return resolve({ alive: false, latency: -1 });
      const p = ports[i++];
      const t0 = Date.now();
      const s = net.connect(p, ip);
      const to = setTimeout(() => { try { s.destroy(); } catch {} tryNext(); }, timeout);
      s.on('connect', () => { clearTimeout(to); const lat = Date.now() - t0; try { s.destroy(); } catch {} resolve({ alive: true, latency: lat }); });
      s.on('error', () => { clearTimeout(to); tryNext(); });
    };
    tryNext();
  });
}

async function discovery({ target, methods, timeout, threads } = {}) {
  return (async () => {
    let hosts;
    try { hosts = expandTargets(target); } catch (e) { return { ok: false, error: e.message }; }
    const ms = methods ? String(methods).split(',').map(s => s.trim()) : ['arp', 'ping', 'tcp'];
    const to = clamp(timeout, 100, 3000, 500);
    const limit = clamp(threads, 8, 256, 64);
    const found = {};

    // 1) ARP 缓存
    if (ms.includes('arp')) {
      const cache = await readArpCache();
      for (const ip of hosts) if (cache[ip]) found[ip] = { alive: true, mac: cache[ip], method: 'arp', latency_ms: -1 };
    }

    // 2) Ping + TCP
    const remaining = hosts.filter(ip => !found[ip]);
    await runPool(remaining, limit, async (ip) => {
      let alive = false, lat = -1, method = '';
      if (!alive && ms.includes('ping')) { const r = await pingOne(ip, to); if (r.alive) { alive = true; lat = r.latency; method = 'ping'; } }
      if (!alive && ms.includes('tcp')) { const r = await tcpProbe(ip, PROBE_PORTS, to); if (r.alive) { alive = true; lat = r.latency; method = 'tcp'; } }
      if (alive) found[ip] = { alive: true, mac: found[ip] ? found[ip].mac : '', method, latency_ms: lat };
    });

    // 3) 再次读取 ARP 缓存补全 MAC
    const cache2 = await readArpCache();
    for (const ip of Object.keys(found)) if (!found[ip].mac && cache2[ip]) found[ip].mac = cache2[ip];

    const list = Object.keys(found).map(ip => ({
      ip, mac: found[ip].mac, vendor: vendorLookup(found[ip].mac), method: found[ip].method, latency_ms: found[ip].latency_ms,
    }));
    return { ok: true, target, total: hosts.length, found: list, count: list.length };
  })();
}

/* =========================================================================
   主机名解析（hostname）
   ========================================================================= */
function resolveHostname(ip, timeout) {
  return new Promise(resolve => {
    const t = setTimeout(() => resolve(''), timeout + 500);
    dns.reverse(ip, (err, domains) => {
      clearTimeout(t);
      if (!err && domains && domains.length) resolve(domains[0]);
      else resolve('');
    });
  });
}

function hostname({ ip, timeout } = {}) {
  return (async () => {
    if (!isIPv4(ip)) return { ok: false, error: '请提供合法 IPv4 地址' };
    const name = await resolveHostname(ip, clamp(timeout, 200, 3000, 600));
    return { ok: true, ip, hostname: name };
  })();
}

/* =========================================================================
   MAC 厂商查询（vendor）
   ========================================================================= */
function vendorLookup(mac) {
  const m = macNorm(mac);
  if (!m) return '';
  const oui = m.slice(0, 8); // xx:xx:xx
  return OUI[oui] || '';
}

function vendor({ mac } = {}) {
  const m = macNorm(mac);
  if (!m) return { ok: false, error: '请提供合法 MAC 地址' };
  return { ok: true, mac: m, oui: m.slice(0, 8), vendor: vendorLookup(m) };
}

/* =========================================================================
   Wi-Fi 扫描（wifi）
   ========================================================================= */
function parseNetshNetworks(stdout) {
  const nets = [];
  let cur = null;
  for (const line of stdout.split(/\r?\n/)) {
    const bssid = line.match(/BSSID\s+(\d+)\s*:\s*([0-9a-f:]{17})/i);
    const ssid = line.match(/SSID\s+\d+\s*:\s*(.*)/);
    if (ssid) {
      if (cur) nets.push(cur);
      cur = { ssid: (ssid[1] || '').trim() || '<隐藏>', bssid: '', signal: null, channel: null, freq: null, security: 'OPEN', quality: 0 };
      continue;
    }
    if (bssid && cur) { cur.bssid = bssid[2].toUpperCase(); continue; }
    if (!cur) continue;
    let m;
    if ((m = line.match(/Signal\s*:\s*(\d+)%/))) { cur.signal = parseInt(m[1], 10); cur.quality = parseInt(m[1], 10); }
    else if ((m = line.match(/Channel\s*:\s*(\d+)/))) cur.channel = parseInt(m[1], 10);
    else if ((m = line.match(/Radio type|PHY type\s*:\s*(\S+)/))) { /* n/a */ }
    else if ((m = line.match(/Authentication\s*:\s*(.+)/))) {
      const a = m[1].trim().toUpperCase();
      cur.security = /WPA3/i.test(a) ? 'WPA3' : /WPA2/i.test(a) ? 'WPA2' : /WPA/i.test(a) ? 'WPA' : /OPEN/i.test(a) ? 'OPEN' : a;
    }
  }
  if (cur) nets.push(cur);
  // 去重：同 BSSID 保留信号最强
  const best = {};
  for (const n of nets) { const k = n.bssid || n.ssid; if (!best[k] || (n.signal || -1) > (best[k].signal || -1)) best[k] = n; }
  return Object.values(best);
}

function parseNetshInterfaces(stdout) {
  const ifaces = [];
  let cur = null;
  for (const line of stdout.split(/\r?\n/)) {
    const name = line.match(/^\s*Name\s*:\s*(.+)/);
    if (name) { if (cur) ifaces.push(cur); cur = { name: name[1].trim(), state: '', bssid: '', ssid: '', signal: null }; continue; }
    if (!cur) continue;
    let m;
    if ((m = line.match(/^\s*State\s*:\s*(.+)/))) cur.state = m[1].trim();
    else if ((m = line.match(/^\s*BSSID\s*:\s*([0-9a-f:]{17})/i))) cur.bssid = m[1].toUpperCase();
    else if ((m = line.match(/^\s*SSID\s*:\s*(.+)/))) cur.ssid = m[1].trim();
    else if ((m = line.match(/^\s*Signal\s*:\s*(\d+)%/))) cur.signal = parseInt(m[1], 10);
  }
  if (cur) ifaces.push(cur);
  return ifaces;
}

function parseAirportScan(stdout) {
  const nets = [];
  const lines = stdout.split(/\r?\n/);
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const m = line.match(/^(\S+)\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+(-?\d+)\s+(\d+)\s+\S+\s+\S+\s*(.*)$/i);
    if (m) nets.push({
      ssid: m[1], bssid: m[2], rssi: Number(m[3]), channel: m[4],
      security: (m[5] || '').trim() || '开放', signal: '', auth: (m[5] || '').trim()
    });
  }
  return nets;
}

function wifi() {
  return (async () => {
    if (IS_WIN) {
      const ifaces = parseNetshInterfaces((await execFileP('netsh', ['wlan', 'show', 'interfaces'], 8000)).stdout);
      const r = await execFileP('netsh', ['wlan', 'show', 'networks', 'mode=bssid'], 12000);
      if (!r.ok) return { ok: true, note: '无线网卡不可用或未开启（需管理员/驱动支持）', interfaces: ifaces, networks: [], count: 0 };
      const nets = parseNetshNetworks(r.stdout);
      return { ok: true, interfaces: ifaces, networks: nets, count: nets.length };
    }
    if (IS_MAC) {
      const airport = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';
      const r = await execFileP(airport, ['-s'], 12000);
      if (r.ok) {
        const nets = parseAirportScan(r.stdout);
        return { ok: true, interfaces: [], networks: nets, count: nets.length };
      }
      return { ok: true, note: '当前环境不支持 Wi-Fi 扫描（需 airport 工具或 Wi-Fi 已关闭）', interfaces: [], networks: [], count: 0 };
    }
    // Linux 回退到 iw / nmcli
    let r = await execFileP('iw', ['dev'], 5000);
    if (r.ok) {
      const iface = (r.stdout.match(/Interface\s+(\w+)/) || [])[1];
      if (iface) {
        const s = await execFileP('iw', ['dev', iface, 'scan'], 12000);
        // 简化：仅返回接口信息
        return { ok: true, note: 'Linux 环境，请使用 iw 查看明细', interfaces: [{ name: iface }], networks: [], count: 0 };
      }
    }
    return { ok: true, note: '当前环境不支持 Wi-Fi 扫描', interfaces: [], networks: [], count: 0 };
  })();
}

/* =========================================================================
   IP 冲突检测（ipconflict）
   ========================================================================= */
async function ipconflict({ target, timeout } = {}) {
  return (async () => {
    let hosts;
    try { hosts = expandTargets(target); } catch (e) { return { ok: false, error: e.message }; }
    const to = clamp(timeout, 200, 2000, 600);
    // 读取初始 ARP 缓存，再对目标做一次 Ping 扫（并发），最后再读一次缓存做比对。
    // 避免对每台主机单独执行 arp（否则 /24 会产生上百次进程调用而极慢）。
    const map0 = await readArpCache();
    await runPool(hosts, 64, async (ip) => { await pingOne(ip, to); });
    const map1 = await readArpCache();
    const combined = {};
    for (const m of [map0, map1]) for (const ip in m) { (combined[ip] = combined[ip] || new Set()).add(m[ip]); }
    const conflicts = [], mappings = [];
    for (const ip in combined) {
      const macs = Array.from(combined[ip]);
      mappings.push({ ip, mac: macs[0], mac_count: macs.length });
      if (macs.length > 1) conflicts.push({ ip, macs });
    }
    return { ok: true, target, total: hosts.length, mappings, conflicts, count: mappings.length };
  })();
}

/* =========================================================================
   DHCP 信息探测（dhcp）
   ========================================================================= */
function parseIpconfig(stdout) {
  const blocks = stdout.split(/\r?\n\r?\n/);
  const out = [];
  for (const blk of blocks) {
    if (!/adapter/i.test(blk) && !/适配器/i.test(blk)) continue;
    const name = (blk.match(/适配器 (.+?):/) || blk.match(/adapter (.+?):/i) || [])[1];
    if (!name) continue;
    const get = re => { const m = blk.match(re); return m ? m[1].trim() : ''; };
    const dhcpEnabled = /DHCP 已启用[.\s:]*是|DHCP Enabled[.\s:]*Yes/i.test(blk);
    const server = get(/DHCP 服务器[.\s:]*([\d.]+)|DHCP Server[.\s:]*([\d.]+)/i);
    const ip = get(/IPv4 地址[.\s:]*([\d.]+)|IPv4 Address[.\s:]*([\d.]+)/i);
    const mask = get(/子网掩码[.\s:]*([\d.]+)|Subnet Mask[.\s:]*([\d.]+)/i);
    const gw = get(/默认网关[.\s:]*([\d.]+)|Default Gateway[.\s:]*([\d.]+)/i);
    const dns = (blk.match(/DNS 服务器[.\s:]*([\d.\s]+)|DNS Servers[.\s:]*([\d.\s]+)/i) || [])[1] || '';
    const leaseOb = get(/租约获得时间[.\s:]*([^\r\n]+)|Lease Obtained[.\s:]*([^\r\n]+)/i);
    const leaseEx = get(/租约过期时间[.\s:]*([^\r\n]+)|Lease Expires[.\s:]*([^\r\n]+)/i);
    if (ip) out.push({
      name: name.trim(), dhcp_enabled: dhcpEnabled, dhcp_server: server,
      ip, mask, gateway: gw, dns: dns.replace(/\s+/g, ' ').trim(),
      lease_obtained: leaseOb, lease_expires: leaseEx,
    });
  }
  return out;
}

function dhcp() {
  return (async () => {
    const cmd = IS_WIN ? 'ipconfig' : 'ifconfig';
    const args = IS_WIN ? ['/all'] : ['-a'];
    const r = await execFileP(cmd, args, 8000);
    if (!r.ok) return { ok: false, error: '无法读取网络配置', stderr: r.stderr };
    const ifaces = parseIpconfig(r.stdout);
    const servers = ifaces.filter(i => i.dhcp_server).map(i => i.dhcp_server);
    return { ok: true, interfaces: ifaces, dhcp_servers: Array.from(new Set(servers)), count: ifaces.length };
  })();
}

/* =========================================================================
   安全自检（security）
   ========================================================================= */
const RISK = {
  23: ['Telnet', '明文传输、易劫持', '高危'], 21: ['FTP', '明文账号密码', '中危'],
  512: ['rexec', '远程明文执行', '高危'], 513: ['rlogin', '明文远程登录', '高危'],
  514: ['rsh', '明文远程 shell', '高危'], 69: ['TFTP', '无认证文件传输', '中危'],
  161: ['SNMP', '默认团体名可被读配置', '中危'], 139: ['NetBIOS', '共享信息泄露', '中危'],
  445: ['SMB', '永恒之蓝等漏洞面', '中危'], 3389: ['RDP', '远程桌面暴露', '高危'],
  1433: ['MSSQL', '数据库公网暴露', '高危'], 3306: ['MySQL', '数据库公网暴露', '高危'],
  5432: ['PostgreSQL', '数据库公网暴露', '高危'], 27017: ['MongoDB', '常因无认证被入侵', '高危'],
  6379: ['Redis', '常因无认证被入侵', '高危'], 8080: ['HTTP管理后台', '明文管理通道', '中危'],
  8081: ['HTTP管理后台', '明文管理通道', '中危'], 8000: ['HTTP服务', '明文', '低危'],
  80: ['HTTP', '明文传输', '低危'],
};
const SEV_SCORE = { '高危': 3, '中危': 2, '低危': 1 };

async function security({ target, timeout, ports } = {}) {
  return (async () => {
    let hosts;
    try { hosts = expandTargets(target); } catch (e) { return { ok: false, error: e.message }; }
    const scanPortsList = ports ? parsePorts(ports) : Object.keys(RISK).map(Number);
    const to = clamp(timeout, 100, 3000, 800);
    const findings = [];
    await runPool(hosts, 80, async (ip) => {
      const open = await scanPorts(ip, scanPortsList, to, false);
      for (const p of open) {
        const info = RISK[p.port] || [String(p.port), '未知服务', '低危'];
        findings.push({ ip, port: p.port, service: info[0], severity: info[2], detail: info[1] });
      }
    });
    const sev = { '高危': 0, '中危': 0, '低危': 0 };
    for (const f of findings) sev[f.severity]++;
    let score = sev['高危'] * 34 + sev['中危'] * 12 + sev['低危'] * 3;
    score = Math.min(100, score);
    const level = score >= 70 ? '严重' : score >= 40 ? '较高' : score >= 15 ? '一般' : '良好';
    return { ok: true, target, hosts: hosts.length, findings, risk_score: score, level, severity_count: sev, scanned_ports: scanPortsList.length };
  })();
}

/* =========================================================================
   网络健康体检（netcheck）
   ========================================================================= */
async function netcheck() {
  return (async () => {
    const items = [];
    // 1) 网卡状态
    const ifaces = localInterfaces();
    const up = ifaces.filter(i => i.ip);
    items.push({ key: 'nic', name: '网卡状态', score: up.length ? 10 : 0, max: 10, status: up.length ? 'ok' : 'fail',
      detail: up.length ? `在线接口 ${up.length} 个：` + up.slice(0, 3).map(i => `${i.name}(${i.ip})`).join('、') : '无可用接口' });

    // 2) 网关连接
    const gw = await defaultGateway();
    let gwOk = false;
    if (gw) { const r = await pingOne(gw, 1000); gwOk = r.alive; }
    items.push({ key: 'gateway', name: '网关连接', score: gwOk ? 20 : 0, max: 20, status: gwOk ? 'ok' : 'warn',
      detail: gw ? `默认网关 ${gw}：` + (gwOk ? '可达' : '不可达') : '未探测到默认网关' });

    // 3) DNS 解析
    const dnsTargets = ['www.baidu.com', 'www.qq.com', 'www.microsoft.com'];
    let dOk = 0; const dRes = [];
    await runPool(dnsTargets, 5, async (d) => { try { const a = await dns.promises.lookup(d); if (a && a.address) { dOk++; dRes.push(`${d}→${a.address}`); } } catch {} });
    items.push({ key: 'dns', name: 'DNS解析', score: Math.round(dOk / dnsTargets.length * 30), max: 30,
      status: dOk === dnsTargets.length ? 'ok' : (dOk ? 'warn' : 'fail'), detail: `成功 ${dOk}/${dnsTargets.length}，${dRes.slice(0, 2).join('；') || '全部失败'}` });

    // 4) 外网连接
    const ext = [['8.8.8.8', 53], ['1.1.1.1', 53], ['www.baidu.com', 443], ['www.qq.com', 443]];
    let eOk = 0;
    await runPool(ext, 8, async ([h, p]) => { if (await tcpConnect(h, p, 2000)) eOk++; });
    items.push({ key: 'external', name: '外网连接', score: Math.round(eOk / ext.length * 20), max: 20, status: eOk ? 'ok' : 'fail', detail: `可连通 ${eOk}/${ext.length} 个公网节点` });

    // 5) 网络延迟
    let lat = null;
    if (gw) { const r = await pingOne(gw, 1500); if (r.alive && r.latency > 0) lat = r.latency; }
    if (lat == null) { const r = await pingOne('www.baidu.com', 2000); if (r.alive && r.latency > 0) lat = r.latency; }
    let latScore, latStatus;
    if (lat == null) { latScore = 0; latStatus = 'fail'; }
    else if (lat < 10) { latScore = 10; latStatus = 'ok'; }
    else if (lat < 30) { latScore = 8; latStatus = 'ok'; }
    else if (lat < 60) { latScore = 5; latStatus = 'warn'; }
    else if (lat < 100) { latScore = 3; latStatus = 'warn'; }
    else { latScore = 1; latStatus = 'fail'; }
    items.push({ key: 'latency', name: '网络延迟', score: latScore, max: 10, status: latStatus, detail: lat != null ? `平均往返 ${lat} ms` : '无法测量' });

    // 6) 网络速度（best-effort：短时出现下载估算）
    let spScore = 0, spDetail = '测速跳过（环境受限）';
    try {
      const t0 = Date.now();
      const r = await new Promise(resolve => {
        const http = require('http');
        let bytes = 0; let done = false;
        let req;
        let timer;
        const cleanup = () => {
          clearTimeout(timer);
          if (req && !req.destroyed) req.destroy();
        };
        const finish = v => {
          if (done) return;
          done = true;
          cleanup();
          resolve(v);
        };
        req = http.get('http://www.example.com/', resp => {
          resp.on('data', c => { bytes += c.length; });
          resp.on('end', () => finish(bytes));
          resp.resume();
        });
        req.on('error', () => finish(bytes));
        timer = setTimeout(() => finish(bytes), 3000);
      });
      const sec = (Date.now() - t0) / 1000;
      if (sec > 0 && r > 0) { const mbps = (r * 8) / sec / 1e6; spDetail = `约 ${mbps.toFixed(1)} Mbps`; spScore = mbps >= 30 ? 5 : mbps >= 5 ? 3 : mbps >= 1 ? 2 : 1; }
    } catch {}
    items.push({ key: 'speed', name: '网络速度', score: spScore, max: 5, status: spScore >= 3 ? 'ok' : 'warn', detail: spDetail });

    // 7) 环路检测（IP 冲突）
    let loopScore = 5, loopStatus = 'ok', loopDetail = '未检测到 IP 冲突';
    if (gw) {
      const ifc = localInterfaces().find(i => i.ip &&
        ((ipToInt(gw) & ipToInt(i.netmask)) >>> 0) === ((ipToInt(i.ip) & ipToInt(i.netmask)) >>> 0));
      // 体检是快速健康检查，不应在 /16、/8 等大网段上主动 Ping 数万地址。
      const cidr = ifc && ifc.prefix >= 24
        ? ifc.cidr
        : (gw.split('.').slice(0, 3).join('.') + '.0/24');
      try {
        const c = await ipconflict({ target: cidr, timeout: 400 });
        if (c.conflicts && c.conflicts.length) { loopScore = 0; loopStatus = 'fail'; loopDetail = `发现 ${c.conflicts.length} 处 IP 冲突：` + c.conflicts.slice(0, 3).map(x => `${x.ip}↔${x.macs.join(',')}`).join('；'); }
      } catch {}
    }
    items.push({ key: 'loop', name: '环路检测(IP冲突)', score: loopScore, max: 5, status: loopStatus, detail: loopDetail });

    const score = items.reduce((a, i) => a + i.score, 0);
    const level = score >= 90 ? '优秀' : score >= 75 ? '良好' : score >= 60 ? '一般' : '较差';
    return { ok: true, score, total: 100, level, items, gateway: gw };
  })();
}

/* =========================================================================
   网络拓扑自动发现（topology）
   ========================================================================= */
async function topology({ target, with_snmp } = {}) {
  return (async () => {
    let hosts;
    try { hosts = expandTargets(target); } catch (e) { return { ok: false, error: e.message }; }
    if (hosts.length > 512) hosts = hosts.slice(0, 512);
    const gw = await defaultGateway();
    const cache = await readArpCache();
    const alive = [];
    await runPool(hosts, 64, async (ip) => {
      const r = await pingOne(ip, 1000);
      if (r.alive) alive.push(ip);
    });
    const arp2 = await readArpCache();
    const nodes = [];
    const seen = new Set();
    await runPool(alive, 32, async (ip) => {
      const mac = arp2[ip] || cache[ip] || '';
      const ven = vendorLookup(mac);
      const host = await resolveHostname(ip, 600);
      nodes.push({ ip, mac, vendor: ven, hostname: host, role: ip === gw ? 'gateway' : 'host' });
      seen.add(ip);
    });
    if (gw && !seen.has(gw)) nodes.push({ ip: gw, mac: arp2[gw] || cache[gw] || '', vendor: vendorLookup(arp2[gw] || cache[gw] || ''), hostname: '', role: 'gateway' });
    const edges = nodes.filter(n => n.role !== 'gateway').map(n => ({ from: n.ip, to: gw }));
    return { ok: true, network: target === 'auto' ? (localInterfaces()[0] || {}).cidr : target, gateway: gw, count: nodes.length, nodes, edges };
  })();
}

/* =========================================================================
   TCP 会话并发承压测试（session）
   ========================================================================= */
async function session({ host, port, count, timeout, concurrency } = {}) {
  return (async () => {
    if (!isIPv4(host) || !port) return { ok: false, error: '请提供合法 host 与 port' };
    count = clamp(count, 1, 500, 20);
    const to = clamp(timeout, 200, 5000, 2000);
    // 并发执行 count 次连接，统计成功数与 RTT
    const results = await runPool(Array.from({ length: count }), Math.min(64, count), async () => {
      const t0 = Date.now();
      const ok = await tcpConnect(host, port, to);
      const dt = Date.now() - t0;
      return ok ? dt : null;
    });
    const rtts = results.filter(x => x != null);
    const ok = rtts.length;
    const avg = rtts.length ? rtts.reduce((a, b) => a + b, 0) / rtts.length : null;
    // 并发承压：从 10 起步翻倍，直到成功率 < 90%
    let maxConcurrent = null;
    if (rtts.length) {
      let n = 10;
      while (n <= 512) {
        const opened = await runPool(Array.from({ length: n }), n, async () => (await tcpConnect(host, port, 500)) ? 1 : 0);
        const succ = opened.reduce((a, b) => a + (b || 0), 0);
        if (succ / n >= 0.9) { maxConcurrent = succ; n *= 2; } else break;
      }
    }
    return {
      ok: true, host, port: Number(port),
      attempts: count, success: ok, success_rate: Math.round(ok / count * 1000) / 10,
      avg_connect_ms: avg != null ? Math.round(avg * 100) / 100 : null,
      max_concurrent: maxConcurrent,
    };
  })();
}

/* =========================================================================
   摄像头 / 监控设备探测（camera）
   ========================================================================= */
const CAM_PORTS = [554, 8554, 80, 8080, 8000, 8008, 8081, 81, 88, 443, 37777, 34567, 5000, 9000, 34599, 6789, 6667, 1400, 23, 5001];
const CAM_BRANDS = [
  ['Hikvision', ['hikvision', 'isapi', 'hik_', 'hikvision-webs']],
  ['Dahua', ['dahua', 'dh-httpsrv', 'customized-http-server', 'dahua technology']],
  ['Axis', ['axis', 'axis communications', 'vidarch']],
  ['UNV(宇视)', ['uniview', 'unv']],
  ['Foscam', ['foscam']],
  ['TP-Link', ['tp-link', 'tp-link surveillance']],
  ['Reolink', ['reolink']],
];

async function camera({ target, timeout } = {}) {
  return (async () => {
    let hosts;
    try { hosts = expandTargets(target); } catch (e) { return { ok: false, error: e.message }; }
    const to = clamp(timeout, 200, 2000, 800);
    const devices = [];
    await runPool(hosts, 80, async (ip) => {
      const open = await scanPorts(ip, CAM_PORTS, to, true);
      if (!open.length) return;
      const text = open.map(p => (p.banner || '').toLowerCase()).join(' ');
      let brand = null;
      for (const [name, sigs] of CAM_BRANDS) if (sigs.some(s => text.includes(s))) { brand = name; break; }
      if (!brand) {
        if (open.some(p => [554, 8554].includes(p.port))) brand = 'RTSP设备(疑似摄像头)';
        else if (open.some(p => [37777, 34567].includes(p.port))) brand = '监控设备(私有端口特征)';
      }
      const isCam = !!brand || open.some(p => [554, 8554, 37777, 34567, 8000].includes(p.port));
      devices.push({ ip, open_ports: open.map(p => p.port), brand: brand || (open.length ? '未知设备' : null), is_camera: isCam,
        note: open.map(p => (p.banner || '').slice(0, 120)).filter(Boolean).join(' | ').slice(0, 200) });
    });
    return { ok: true, target, devices, scanned: hosts.length };
  })();
}

module.exports = {
  portscan, discovery, hostname, vendorLookup, vendor, wifi, ipconflict, dhcp,
  security, netcheck, topology, session, camera,
  // 对外辅助
  expandTargets, defaultGateway, localInterfaces, parsePorts,
};
