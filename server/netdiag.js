'use strict';
/**
 * 网络诊断工具箱（P3）
 *
 * 六个检测器，每个都支持「本机 / 指定网段」两种目标模式：
 *   camera     摄像头扫描   端口指纹 → HTTP 标题 → RTSP/ONVIF 探测，判未鉴权与暴露面
 *   ipconflict IP 冲突检测  多轮 ARP 表采样（主动）+ 旁路 ARP 嗅探（被动）交叉取证
 *   loop       环路检测     旁路抓包，找「同 IP-ID 不同 TTL」的重复帧与广播风暴
 *   logaudit   日志审计     Syslog 接收入库 + 审计规则聚合 + 本机事件日志
 *   speedtest  外网测速     多线程下行 / 定长上行 + 延迟抖动丢包，对比网关基线
 *   dhcp       DHCP 检测    主动 OFFER 探测 + 被动嗅探 + 本机租约核对，找 Rogue DHCP
 *
 * 设计约定：
 *  - 复用而不重造：ICMP 用 netutil.pingOnce、TCP 探测用 netutil.tcpConnect、
 *    抓包可执行文件用 netutil.findTshark、本机网卡用 netutil.localInterfaces、
 *    目标展开与端口解析直接用 scanner 的实现。
 *  - 每个检测器只产出「问题清单（findings）」，由 run() 统一打分、入库、联动告警，
 *    这样风险口径与网络扫描模块保持一致，前端也只需一套渲染逻辑。
 *  - 主动发包类检测器（摄像头/IP 冲突/环路/测速/DHCP）需要 scan 权限；
 *    日志审计属只读检索，view 即可。
 */
const net = require('net');
const os = require('os');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { spawn, execFile } = require('child_process');
const store = require('./store');
const db = require('./db');
const netutil = require('./netutil');
const scanner = require('./scanner');

const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const SCHED_LEAD = 5000;                 // 调度巡检间隔
const MAX_HOSTS = 1024;                  // 单次目标展开上限
const DEFAULT_TIMEOUT = 1500;            // 单次 TCP 探测超时
const LOG_KEEP = 50000;                  // 审计日志内存/表内保留条数

const running = new Map();               // taskId -> 时间戳
let timer = null;

/* ============================== 通用小工具 ============================== */
const LEVEL_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const LEVEL_TEXT = { critical: '极高危', high: '高危', medium: '中危', low: '低危', info: '提示' };
const PENALTY = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };
const worstLevel = (ls) => ls.reduce((a, b) => ((LEVEL_ORDER[b] || 0) > (LEVEL_ORDER[a] || 0) ? b : a), 'info');

/** 汇总问题清单 → 0~100 健康分（问题越重扣越多） */
function scoreOf(findings) {
  let s = 100;
  for (const f of findings) s -= (PENALTY[f.level] || 0);
  return Math.max(0, Math.round(s));
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/** 保序限并发的执行池（与 scanner 里那个同构，避免一次性开满连接） */
async function pool(items, size, worker) {
  const out = new Array(items.length);
  let cursor = 0;
  const n = Math.max(1, Math.min(size, items.length || 1));
  const runners = [];
  for (let w = 0; w < n; w++) {
    runners.push((async () => {
      for (;;) {
        const i = cursor++;
        if (i >= items.length) return;
        try { out[i] = await worker(items[i], i); }
        catch (e) { out[i] = { error: e.message }; }
      }
    })());
  }
  await Promise.all(runners);
  return out;
}

function execFileP(cmd, args, timeoutMs = 15000) {
  return new Promise(resolve => {
    execFile(cmd, args, { windowsHide: true, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({
        ok: !err, code: err && typeof err.code === 'number' ? err.code : (err ? -1 : 0),
        out: String(stdout || ''), err: String(stderr || (err && err.message) || '')
      });
    });
  });
}

const normMac = (m) => String(m || '').toLowerCase().replace(/-/g, ':');
const fmtMac = (d, o) => [d[o], d[o + 1], d[o + 2], d[o + 3], d[o + 4], d[o + 5]]
  .map(x => x.toString(16).padStart(2, '0')).join(':');
const fmtIp = (d, o) => `${d[o] & 255}.${d[o + 1] & 255}.${d[o + 2] & 255}.${d[o + 3] & 255}`;
const ipToInt = (ip) => {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const s of p) { const v = Number(s); if (!Number.isInteger(v) || v < 0 || v > 255) return null; n = (n << 8 | v) >>> 0; }
  return n;
};
const intToIp = (n) => `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;

/**
 * 按配额枚举一个网段（含网络号与广播地址，语义与 scanner.expandTargets 一致）。
 * 只在 expandTargets 因超上限抛错时使用：那里是「宁可报错也不悄悄少扫」，
 * 而「本机网段」这个默认动作如果也报错，用户会莫名其妙扫不到东西，所以这里截断并留下说明。
 */
function enumerateCidr(cidr, limit = MAX_HOSTS) {
  const m = String(cidr || '').match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
  if (!m) return [];
  const prefix = Number(m[2]);
  if (!Number.isInteger(prefix) || prefix < 8 || prefix > 32) return [];
  const base = (ipToInt(m[1]) & ((prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0) >>> 0)) >>> 0;
  const size = prefix >= 31 ? 1 : (1 << (32 - prefix));
  const n = Math.min(size, Math.max(1, limit));
  const out = [];
  for (let k = 0; k < n; k++) out.push(intToIp((base + k) >>> 0));
  return out;
}

/* ============================== 目标解析 ============================== */
/** 本机活动网卡与其所在网段（用于「本机」模式自动圈定范围） */
function localNets() {
  const out = [];
  for (const i of netutil.localInterfaces()) {
    if (i.internal || !i.address || i.address.startsWith('127.')) continue;
    let prefix = 24;
    if (i.cidr && i.cidr.includes('/')) prefix = Number(i.cidr.split('/')[1]);
    if (!Number.isInteger(prefix) || prefix < 8 || prefix > 30) prefix = 24;
    const mask = (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0) >>> 0;
    const base = (ipToInt(i.address) & mask) >>> 0;
    // netmask 一并带出去：界面上「192.168.110.0/24（255.255.255.0）」比只给前缀更好懂
    out.push({
      iface: i.name, address: i.address, mac: normMac(i.mac),
      prefix, netmask: intToIp(mask), cidr: `${intToIp(base)}/${prefix}`
    });
  }
  return out;
}

/**
 * 统一目标解析
 * @param {string} mode  'local' 本机所在网段 | 'range' 指定网段
 * @param {string} input 网段表达式（仅 range 模式需要）
 * @returns {{ targets:string[], nets:object[], ifaces:object[], note:string }}
 */
async function resolveScope(mode, input, maxHosts = MAX_HOSTS) {
  const ifaces = netutil.localInterfaces().filter(i => !i.internal && !i.address.startsWith('127.'));
  if (mode === 'local') {
    const nets = localNets();
    if (!nets.length) throw new Error('未找到活动网卡（只有回环地址），无法确定本机网段，请改为指定网段');
    const seen = new Set(), targets = [], parts = [];
    let note = '';
    for (const n of nets) {
      if (n.prefix >= 31) { if (!seen.has(n.address)) { seen.add(n.address); targets.push(n.address); } continue; }
      // 每个网段单独展开，避免一个 /16 吃掉全部配额
      const quota = Math.max(16, Math.floor(maxHosts / nets.length));
      const total = 1 << (32 - n.prefix);
      let list = [];
      let truncated = false;
      try {
        list = await scanner.expandTargets(n.cidr, quota);
      } catch {
        // expandTargets 超上限是抛错而非截断。这里要的是「截断到配额 + 说明」，
        // 直接沿用会退化成只扫本机一个地址，界面上还看不出少了什么。
        list = enumerateCidr(n.cidr, quota);
        truncated = true;
      }
      // 截断时别把自己切出去：本机网段扫不到自己，结果就完全没意义了
      if (truncated && !list.includes(n.address)) {
        list = [n.address, ...list.filter(x => x !== n.address).slice(0, Math.max(1, quota - 1))];
      }
      if (list.length < total) truncated = true;
      if (truncated) {
        const tail = list.includes(n.address) ? `已包含本机地址 ${n.address}；` : '';
        parts.push(`本机网段 ${n.cidr} 共 ${total} 个地址，已按单次上限 ${quota} 截断，${tail}要扫全段请上调单次目标上限`);
      } else {
        parts.push(`本机网段 ${n.cidr}（${n.netmask}）共 ${list.length} 个地址`);
      }
      for (const ip of list) if (!seen.has(ip)) { seen.add(ip); targets.push(ip); }
    }
    note = parts.join('；');
    return { targets, nets, ifaces, note };
  }
  const raw = String(input || '').trim();
  if (!raw) throw new Error('请填写诊断目标，例如 192.168.1.0/24 或 192.168.1.1-60');
  const list = await scanner.expandTargets(raw, maxHosts);
  const nets = localNets().filter(n => {
    const base = ipToInt(n.cidr.split('/')[0]);
    const mask = (0xffffffff << (32 - n.prefix)) >>> 0;
    return list.some(ip => ((ipToInt(ip) & mask) >>> 0) === base);
  });
  return { targets: list, nets, ifaces, note: '' };
}

/* ============================== 网络底层原语 ============================== */
/** 一次 HTTP 请求（探测摄像头 Web 端口 / 测速端点都走它） */
function httpRequest(url, { method = 'GET', headers = {}, body = null, timeoutMs = 2000, maxBytes = 32768 } = {}) {
  return new Promise(resolve => {
    let u; try { u = new URL(url); } catch { return resolve({ error: 'URL 不合法' }); }
    const lib = u.protocol === 'https:' ? https : http;
    let done = false;
    const fin = (r) => { if (done) return; done = true; resolve(r); };
    let req;
    try {
      req = lib.request({
        protocol: u.protocol, hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search, method,
        headers: { 'User-Agent': 'NetOpsDiag/1.0', Connection: 'close', ...headers },
        timeout: timeoutMs, rejectUnauthorized: false
      }, res => {
        const chunks = []; let n = 0;
        res.on('data', d => {
          n += d.length;
          chunks.push(n <= maxBytes ? d : d.subarray(0, Math.max(0, maxBytes - (n - d.length))));
          if (n >= maxBytes) { try { req.destroy(); } catch { } }
        });
        const finish = () => fin({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8'), bytes: n });
        res.on('end', finish);
        res.on('close', finish);
      });
    } catch (e) { return fin({ error: e.message }); }
    req.on('timeout', () => { try { req.destroy(); } catch { } fin({ error: 'timeout' }); });
    req.on('error', e => fin({ error: e.code || e.message }));
    if (body) req.write(body);
    req.end();
  });
}

/** RTSP 原生探测：DESCRIBE 不带 Authorization，能拿到 SDP 就说明可未授权拉流 */
function rtspRequest(ip, port, urlPath, method = 'DESCRIBE', timeoutMs = 2000) {
  return new Promise(resolve => {
    const s = new net.Socket();
    let buf = '', done = false;
    const fin = (r) => { if (done) return; done = true; try { s.destroy(); } catch { } resolve(r); };
    s.setTimeout(timeoutMs);
    s.once('connect', () => {
      s.write(`${method} rtsp://${ip}:${port}${urlPath} RTSP/1.0\r\nCSeq: 1\r\n`
        + (method === 'DESCRIBE' ? 'Accept: application/sdp\r\n' : '')
        + 'User-Agent: NetOpsDiag/1.0\r\n\r\n');
    });
    s.on('data', d => {
      buf += d.toString('utf8');
      if (/RTSP\/1\.0/.test(buf) && (/\r\n\r\n/.test(buf) || buf.length > 4096)) fin({ text: buf });
    });
    s.once('timeout', () => fin(buf ? { text: buf } : { error: 'timeout' }));
    s.once('error', e => fin({ error: e.code || e.message }));
    s.once('close', () => fin({ text: buf }));
    s.connect(port, ip);
  });
}

/** 本机 ARP 表（Windows/Linux 双平台解析） */
async function arpTable() {
  const r = await execFileP('arp', [IS_WIN ? '-a' : '-an'], 8000);
  const map = new Map();
  for (const line of r.out.split(/\r?\n/)) {
    // Windows:   192.168.1.1       9c-5c-8e-xx-xx-xx     动态
    let m = line.match(/^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})\s*(\S*)/i);
    // Linux(arp -an):  ? (192.168.1.1) at 9c:5c:8e:xx:xx:xx [ether] on eth0
    if (!m) m = line.match(/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i);
    if (m) map.set(m[1], normMac(m[2]));
  }
  return map;
}

/** 清本机 ARP 缓存（需要管理员，失败就跳过——不影响检测，只是采样翻转不明显） */
async function arpFlush(ip) {
  const args = ip ? ['-d', ip] : ['-d', '*'];
  const r = await execFileP('arp', IS_WIN ? args : (ip ? ['-d', ip] : ['-d', '-a']), 5000);
  return r.ok;
}

/** 默认网关（中英文 Windows / Linux 都能解析） */
async function defaultGateway() {
  if (IS_WIN) {
    const r = await execFileP('ipconfig', [], 8000);
    const m = r.out.match(/(?:默认网关|Default Gateway)[^\n:]*:\s*(\d+\.\d+\.\d+\.\d+)/i);
    if (m) return m[1];
    const m2 = r.out.match(/0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)/);
    return m2 ? m2[1] : '';
  }
  if (IS_MAC) {
    const r = await execFileP('route', ['-n', 'get', 'default'], 5000);
    if (r.ok) {
      const m = r.out.match(/gateway:\s*(\d+\.\d+\.\d+\.\d+)/i);
      if (m) return m[1];
    }
    const r2 = await execFileP('netstat', ['-rn'], 5000);
    const m2 = r2.out.match(/^default\s+(\d+\.\d+\.\d+\.\d+)/m);
    return m2 ? m2[1] : '';
  }
  const r = await execFileP('ip', ['route'], 5000);
  const m = r.out.match(/^default via (\d+\.\d+\.\d+\.\d+)/m);
  if (m) return m[1];
  const r2 = await execFileP('route', ['-n'], 5000);
  const m2 = r2.out.match(/^0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)/m);
  return m2 ? m2[1] : '';
}

/** 本机主用网卡的 MAC（拼 DHCP 探测报文用） */
function localMac() {
  const ifs = netutil.localInterfaces().filter(i => !i.internal && !i.address.startsWith('127.'));
  const m = ifs.find(i => i.mac && !/^00:00:00/.test(i.mac));
  return m ? normMac(m.mac) : '00:11:22:33:44:55';
}

/* ============================== pcap 读取与解码 ============================== */
/**
 * 读经典 pcap 的所有帧。
 * 注意：dpi.parsePcap 只解 IPv4 会话，ARP/DHCP/STP 拿不到，
 * 所以这里自带一个帧级迭代器（抓包时统一加 -F pcap，避免 tshark 默认写 pcapng）。
 */
function readPcapFrames(file) {
  const out = { frames: [], linkType: 0, truncated: false, error: '' };
  let buf;
  try { buf = fs.readFileSync(file); } catch (e) { out.error = e.message; return out; }
  if (buf.length < 24) { out.error = '文件过小，不是有效 pcap'; return out; }
  const magic = buf.readUInt32LE(0);
  let be, nsec;
  if (magic === 0xa1b2c3d4) { be = false; nsec = false; }
  else if (magic === 0xd4c3b2a1) { be = true; nsec = false; }
  else if (magic === 0xa1b2cd34) { be = false; nsec = true; }
  else if (magic === 0x34cdb2a1) { be = true; nsec = true; }
  else { out.error = '不是经典 pcap（tshark 默认写 pcapng，需加 -F pcap）'; return out; }
  out.linkType = buf.readUInt32LE(20);
  const u32 = be ? (o) => buf.readUInt32BE(o) : (o) => buf.readUInt32LE(o);
  let off = 24, guard = 0;
  while (off + 16 <= buf.length && guard++ < 800000) {
    const capLen = u32(off + 8);
    if (capLen <= 0 || off + 16 + capLen > buf.length) { out.truncated = true; break; }
    const tsSec = u32(off), tsFrac = u32(off + 4);
    out.frames.push({
      t: nsec ? tsSec + tsFrac / 1e9 : tsSec + tsFrac / 1e6,
      data: buf.subarray(off + 16, off + 16 + capLen)
    });
    off += 16 + capLen;
  }
  return out;
}

/** 以太网帧解到 L3 起点；返回 null 表示链路层类型不认识 */
function decodeEth(d, linkType) {
  let p = 0;
  if (linkType === 1) {
    if (d.length < 14) return null;
    const type = d.readUInt16BE(12);
    return { dst: fmtMac(d, 0), src: fmtMac(d, 6), type, p: 14, vlan: type === 0x8100 };
  }
  if (linkType === 113) return { dst: '', src: '', type: d.length > 14 ? d.readUInt16BE(14) : 0, p: 16 };
  if (linkType === 0 || linkType === 12 || linkType === 101) {
    const d2 = d.length >= 20 ? (d[0] >> 4) : 0;
    return { dst: '', src: '', type: 0x0800, p: 0, rawIp: d2 === 4 || d2 === 6 };
  }
  return null;
}

/** IPv4 头（只解首片：分片状态下后面的载荷可能不完整） */
function decodeIpv4(d, p) {
  if (d.length < p + 20) return null;
  const ihl = (d[p] & 0x0f) * 4;
  if (ihl < 20 || d.length < p + ihl) return null;
  const frag = d.readUInt16BE(p + 6);
  return {
    src: fmtIp(d, p + 12), dst: fmtIp(d, p + 16),
    id: d.readUInt16BE(p + 4), ttl: d[p + 8], proto: d[p + 9],
    totalLen: d.readUInt16BE(p + 2),
    mf: !!(frag & 0x2000), fragOffset: frag & 0x1fff,
    p: p + ihl
  };
}

/** ARP（20 字节固定头，含 IPv4 over Ethernet） */
function decodeArp(d, p) {
  if (d.length < p + 28) return null;
  return {
    op: d.readUInt16BE(p + 6),
    sha: fmtMac(d, p + 8), spa: fmtIp(d, p + 14),
    tha: fmtMac(d, p + 18), tpa: fmtIp(d, p + 24)
  };
}

function decodeUdp(d, p) {
  if (d.length < p + 8) return null;
  return { sport: d.readUInt16BE(p), dport: d.readUInt16BE(p + 2), payload: d.subarray(p + 8) };
}

/** DHCP 报文解析（RFC2131 + 常用 option） */
function parseDhcp(b) {
  if (!b || b.length < 240) return null;
  if (b.readUInt32BE(236) !== 0x63825363) return null;
  const o = {
    op: b[0], htype: b[1], hlen: b[2], xid: b.readUInt32BE(4),
    secs: b.readUInt16BE(8), flags: b.readUInt16BE(10),
    ciaddr: fmtIp(b, 12), yiaddr: fmtIp(b, 16), siaddr: fmtIp(b, 20), giaddr: fmtIp(b, 24),
    chaddr: fmtMac(b, 28), msgType: 0, serverId: '', options: {}
  };
  let i = 240;
  while (i < b.length) {
    const code = b[i++];
    if (code === 0) continue;
    if (code === 255) break;
    if (i >= b.length) break;
    let len = b[i++];
    if (i + len > b.length) len = b.length - i;
    const v = b.subarray(i, i + len);
    i += len;
    switch (code) {
      case 53: o.msgType = v[0]; break;
      case 54: o.serverId = v.length === 4 ? fmtIp(v, 0) : ''; break;
      case 1: o.options.mask = v.length === 4 ? fmtIp(v, 0) : ''; break;
      case 3: o.options.routers = []; for (let k = 0; k + 4 <= v.length; k += 4) o.options.routers.push(fmtIp(v, k)); break;
      case 6: o.options.dns = []; for (let k = 0; k + 4 <= v.length; k += 4) o.options.dns.push(fmtIp(v, k)); break;
      case 12: o.options.hostname = v.toString('utf8').replace(/\0+$/, ''); break;
      case 15: o.options.domain = v.toString('utf8').replace(/\0+$/, ''); break;
      case 51: o.options.lease = v.length === 4 ? v.readUInt32BE(0) : 0; break;
      case 58: o.options.renew = v.length === 4 ? v.readUInt32BE(0) : 0; break;
      case 59: o.options.rebind = v.length === 4 ? v.readUInt32BE(0) : 0; break;
      default: o.options['opt' + code] = v.toString('hex').slice(0, 40);
    }
  }
  return o;
}

const DHCP_MSG = { 1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM' };

/** 拼一个 DHCPDISCOVER */
function buildDiscover(xid, mac, hostname) {
  const b = Buffer.alloc(548);
  b[0] = 1; b[1] = 1; b[2] = 6; b[3] = 0;
  b.writeUInt32BE(xid >>> 0, 4);
  b.writeUInt16BE(0, 8);
  b.writeUInt16BE(0x8000, 10);              // 广播应答位
  const mb = mac.split(':').map(x => parseInt(x, 16) & 255);
  for (let i = 0; i < 6; i++) b[28 + i] = mb[i] || 0;
  b.writeUInt32BE(0x63825363, 236);
  const opts = [53, 1, 1, 61, 7, 1, ...mb.slice(0, 6), 55, 8, 1, 3, 6, 15, 28, 51, 58, 59];
  if (hostname) { const h = Buffer.from(String(hostname).slice(0, 32), 'utf8'); opts.push(12, h.length, ...h); }
  opts.push(255);
  let off = 240;
  for (const x of opts) { if (off < b.length) b[off++] = x; }
  // 必须整包返回：subarray(0, off) 只留下选项区，发出去是 BOOTP 固定头都没有的裸选项块，
  // DHCP 服务器会直接丢弃，主动 OFFER 探测就永远探不到东西。
  return b;
}

/* ============================== 抓包（本地 tshark） ============================== */
/** 抓一段包到临时文件；统一加 -F pcap，保证后续能按帧解（pcapng 解不了） */
function captureFrames({ iface, filter, seconds = 8, exe }) {
  const engine = exe || netutil.findTshark();
  if (!engine) {
    const e = new Error('未检测到 tshark / dumpcap，无法本机抓包。请安装 Wireshark（含 Npcap），或在系统设置里指定路径');
    e.code = 'NO_CAPTURE_ENGINE';
    throw e;
  }
  const file = path.join(store.CAP_DIR, `${store.uid('diag_')}.pcap`);
  const args = ['-i', String(iface || '1'), '-F', 'pcap', '-w', file, '-a', `duration:${Math.max(1, seconds)}`];
  if (filter) args.push('-f', filter);
  return new Promise((resolve, reject) => {
    const p = spawn(engine, args, { windowsHide: true });
    let log = '';
    p.stdout.on('data', d => log += d.toString());
    p.stderr.on('data', d => log += d.toString());
    p.on('error', e => reject(e));
    p.on('close', () => resolve({ file, engine, log: log.slice(-2000) }));
  });
}

/** 抓一包 → 解帧，返回帧数组（用完删文件，避免占盘） */
async function sniffFrames({ iface, filter, seconds }) {
  const cap = await captureFrames({ iface, filter, seconds });
  const r = readPcapFrames(cap.file);
  try { fs.unlinkSync(cap.file); } catch { }
  if (r.error) throw new Error(`pcap 解析失败：${r.error}`);
  return { frames: r.frames, linkType: r.linkType, truncated: r.truncated, log: cap.log };
}

/* ======================================================================== *
 *                        检测器 1：摄像头扫描
 * ======================================================================== */
const CAM_MARK_PORTS = [554, 37777, 34567, 10554, 6036, 8000, 5000];   // 命中即高度可疑
const CAM_SIGS = [
  { re: /hikvision|海康|dvrdvs|webcomponents/i, vendor: '海康威视 Hikvision' },
  { re: /dahua|大华/i, vendor: '大华 Dahua' },
  { re: /uniview|宇视|netvideo|nv-?ipc/i, vendor: '宇视 Uniview' },
  { re: /xmeye|xiongmai|雄迈/i, vendor: '雄迈 XM' },
  { re: /tp-?link/i, vendor: 'TP-LINK' },
  { re: /axis/i, vendor: 'Axis' },
  { re: /bosch/i, vendor: 'Bosch' },
  { re: /vivotek/i, vendor: 'Vivotek' },
  { re: /d-link/i, vendor: 'D-Link' },
  { re: /i-?cam|ipcamera|ip cam|network camera|nvr|dvr|web viewer|surveillance|监控|摄像/i, vendor: '通用 IPC' }
];
/** 常见 RTSP 取流路径：未鉴权时能直接 DESCRIBE 出 SDP */
const RTSP_PATHS = [
  { path: '/', tag: '通用' },
  { path: '/Streaming/Channels/101', tag: '海康' },
  { path: '/cam/realmonitor?channel=1&subtype=0', tag: '大华' },
  { path: '/media/video1', tag: '宇视' },
  { path: '/onvif1', tag: 'ONVIF' }
];

async function onvifInfo(ip, port, timeoutMs) {
  const body = '<?xml version="1.0" encoding="UTF-8"?>'
    + '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    + '<s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>';
  const r = await httpRequest(`http://${ip}:${port}/onvif/device_service`, {
    method: 'POST', body, timeoutMs,
    headers: { 'Content-Type': 'application/soap+xml; charset=utf-8', 'Content-Length': Buffer.byteLength(body) }
  });
  if (!r || r.error) return null;
  const text = r.text || '';
  // 401/403 说明服务在但需要鉴权；200 且带 Manufacturer 说明未鉴权可读设备信息
  const pick = (tag) => (text.match(new RegExp(`<(?:[a-z0-9]+:)?${tag}>([^<]+)<`, 'i')) || [])[1] || '';
  const man = pick('Manufacturer'), model = pick('Model'), fw = pick('FirmwareVersion');
  if (!man && !model) return { status: r.status, unauthenticated: false };
  return { status: r.status, manufacturer: man, model, firmware: fw, unauthenticated: r.status === 200 };
}

async function probeCameraHost(ip, { ports, timeoutMs = DEFAULT_TIMEOUT }) {
  const opens = [];
  const rs = await pool(ports, Math.min(8, ports.length), async (port) => {
    const r = await netutil.tcpConnect(ip, port, timeoutMs);
    return r.ok ? { port, ms: r.ms } : null;
  });
  for (const r of rs) if (r) opens.push(r);
  if (!opens.length) return null;

  const openPorts = opens.map(o => o.port).sort((a, b) => a - b);
  const host = {
    ip, mac: '', vendor: '', model: '', kind: '', openPorts,
    httpTitle: '', onvif: null, rtspOpen: [], rtspNoAuth: [],
    authFree: false, marks: []
  };

  // 命中「摄像头专属端口」直接标记
  for (const p of CAM_MARK_PORTS) if (openPorts.includes(p)) host.marks.push(`专属端口 ${p}`);

  // HTTP 标题 + ONVIF
  const webPorts = openPorts.filter(p => ![554, 37777, 34567, 10554, 6036].includes(p)).slice(0, 4);
  for (const p of webPorts) {
    if (!host.httpTitle) {
      const r = await httpRequest(`http://${ip}:${p}/`, { timeoutMs, maxBytes: 16384 });
      if (r && !r.error && r.text) {
        const t = (r.text.match(/<title[^>]*>([^<]{1,120})<\/title>/i) || [])[1];
        if (t) host.httpTitle = t.trim();
        if (!t && /camera|nvr|dvr|监控/i.test(r.text)) host.httpTitle = '(页面含监控关键字)';
        // 登录页/401/403 说明有鉴权；直接 200 且非登录页 = 未鉴权可达
        const loginish = /login|password|passwd|登录|验证/i.test(r.text.slice(0, 4000));
        host.authFree = host.authFree || (r.status === 200 && !loginish);
      }
    }
    if (!host.onvif && [80, 8000, 8080, 8001, 8081, 88].includes(p)) {
      const o = await onvifInfo(ip, p, timeoutMs);
      if (o && (o.manufacturer || o.model)) { host.onvif = { port: p, ...o }; }
    }
  }

  // RTSP
  if (openPorts.includes(554)) {
    host.rtspOpen.push(554);
    const opt = await rtspRequest(ip, 554, '/', 'OPTIONS', timeoutMs);
    if (opt && opt.text) {
      const m = opt.text.match(/Server:\s*([^\r\n]+)/i) || opt.text.match(/Public:\s*([^\r\n]+)/i);
      if (m) host.rtspServer = m[1].trim();
    }
    for (const rp of RTSP_PATHS) {
      const r = await rtspRequest(ip, 554, rp.path, 'DESCRIBE', timeoutMs);
      if (!r || !r.text) continue;
      if (/RTSP\/1\.0 200/.test(r.text) && /m=(video|audio)/i.test(r.text)) {
        host.rtspNoAuth.push({ path: rp.path, tag: rp.tag });
      } else if (/RTSP\/1\.0 401/.test(r.text)) {
        host.needAuth = true;
      }
    }
  }

  // 是否判定为摄像头
  const titleHit = CAM_SIGS.find(s => s.re.test(host.httpTitle) || (host.rtspServer && s.re.test(host.rtspServer)));
  if (titleHit) { host.vendor = titleHit.vendor; host.kind = 'IPC/NVR'; }
  if (host.onvif && host.onvif.manufacturer) {
    const v = CAM_SIGS.find(s => s.re.test(host.onvif.manufacturer + ' ' + host.onvif.model));
    host.vendor = v ? v.vendor : host.onvif.manufacturer;
    host.model = host.onvif.model || '';
    host.kind = host.kind || 'IPC/NVR';
    host.firmware = host.onvif.firmware;
  }
  const isCam = !!titleHit || !!host.onvif || host.rtspOpen.length > 0
    || host.marks.length > 0 || /摄像|监控|camera|nvr|dvr/i.test(host.httpTitle);
  return isCam ? host : null;
}

async function detectCamera(opts) {
  const { targets } = opts;
  const cfg = (db.settingsSync() || {}).netdiag || {};
  const ports = Array.isArray(opts.ports) && opts.ports.length
    ? opts.ports.map(Number).filter(Boolean)
    : ((cfg.camera && cfg.camera.ports) || [554, 80, 81, 8000, 8080, 37777]);
  const timeoutMs = Math.max(300, Math.min(6000, Number(opts.timeoutMs || DEFAULT_TIMEOUT)));
  const hosts = [];
  const findings = [];

  // 第一轮：端口面（把 (主机×端口) 打平，一次池化，比逐台扫快一个量级）
  const pairs = [];
  for (const ip of targets) for (const p of ports) pairs.push({ ip, port: p });
  const alive = new Set();
  await pool(pairs, Math.min(256, Math.max(32, Number(opts.concurrency || 192))), async (pr) => {
    const r = await netutil.tcpConnect(pr.ip, pr.port, timeoutMs);
    if (r.ok) alive.add(pr.ip);
  });

  if (!alive.size) {
    findings.push({
      level: 'info', category: '摄像头扫描', target: `${targets.length} 个地址`,
      title: '未发现摄像头相关端口开放',
      detail: `在 ${targets.length} 个地址上探测了 ${ports.length} 个端口，没有开着的。`,
      advice: '如果确定网段里有摄像头，确认摄像头与本机在同一广播域、没有被 VLAN 或 ACL 隔断，并核对端口列表。'
    });
    return { findings, hosts, summary: { scanned: targets.length, alive: 0, cameras: 0 } };
  }

  const aliveList = [...alive];
  const results = await pool(aliveList, Math.min(24, Math.max(4, Number(opts.probeConcurrency || 16))), async (ip) => {
    try { return await probeCameraHost(ip, { ports, timeoutMs }); } catch { return null; }
  });
  for (const h of results) if (h) hosts.push(h);

  for (const h of hosts) {
    const where = h.vendor ? `${h.vendor}${h.model ? ' ' + h.model : ''}` : '疑似视频设备';
    const portTxt = h.openPorts.join(', ');
    const ev = { openPorts: h.openPorts, httpTitle: h.httpTitle, rtspServer: h.rtspServer, onvif: h.onvif, rtspNoAuth: h.rtspNoAuth };

    if (h.rtspNoAuth.length) {
      h.riskLevel = 'critical';
      h.riskDesc = 'RTSP 可未鉴权拉流';
      findings.push({
        level: 'critical', category: '视频监控', target: h.ip,
        title: `${h.ip} 摄像头可未授权拉取视频流`,
        detail: `${where}，RTSP(554) 用 DESCRIBE 未带任何凭据就返回了 SDP（命中路径：${h.rtspNoAuth.map(x => x.tag + x.path).join('、')}），`
          + '任何人只要能访问 554 端口就能直接看到画面。开放端口：'
          + portTxt + (h.httpTitle ? `，Web 标题「${h.httpTitle}」` : ''),
        advice: '① 立即给摄像头设强口令并关闭匿名/ONVIF 无鉴权访问；② 把 NVR/摄像头划进独立 VLAN，只允许 NVR 与运维终端访问；'
          + '③ 出口防火墙禁止 554/8000/37777 等端口从外网进来；④ 固件升级到厂商最新版。',
        evidence: ev
      });
    } else if (h.authFree || (h.onvif && h.onvif.unauthenticated)) {
      h.riskLevel = 'high';
      h.riskDesc = '管理面未鉴权可达';
      findings.push({
        level: 'high', category: '视频监控', target: h.ip,
        title: `${h.ip} 摄像头管理面未鉴权可达`,
        detail: `${where}，${h.onvif && h.onvif.unauthenticated ? 'ONVIF GetDeviceInformation 未带凭据即返回设备信息；' : ''}`
          + `HTTP 首页未做登录拦截。开放端口：${portTxt}${h.httpTitle ? `，标题「${h.httpTitle}」` : ''}`,
        advice: '① 收紧管理面鉴权并修改默认口令；② 摄像头管理网与管理终端同 VLAN，不要暴露到办公网；③ 需要外网看画面时用 NVR 转发或 VPN，别做端口映射。',
        evidence: ev
      });
    } else {
      h.riskLevel = 'medium';
      h.riskDesc = '视频设备暴露面';
      findings.push({
        level: 'medium', category: '视频监控', target: h.ip,
        title: `${h.ip} 发现视频监控设备（已鉴权）`,
        detail: `${where}，开放端口：${portTxt}${h.httpTitle ? `，标题「${h.httpTitle}」` : ''}${h.rtspServer ? `，RTSP Server: ${h.rtspServer}` : ''}`,
        advice: '① 纳入资产台账并登记责任人；② 确认口令强度与固件版本；③ 限制访客网段访问；④ 打开登录失败告警。',
        evidence: ev
      });
    }
  }

  // 资产台账联动：把发现的摄像头并进设备补充信息
  for (const h of hosts) {
    try {
      const cur = await db.inventoryGet(h.ip);
      await db.inventorySet(h.ip, {
        zone: (cur && cur.zone) || netdiagZone(h.ip),
        role: '视频监控',
        brand: (cur && cur.brand) || h.vendor || '',
        model: (cur && cur.model) || h.model || '',
        note: `由摄像头扫描发现（${h.openPorts.length} 个开放端口${h.riskLevel !== 'medium' ? `，风险 ${LEVEL_TEXT[h.riskLevel]}` : ''}）`,
        scannedAt: new Date().toISOString()
      });
    } catch { /* 台账失败不影响主流程 */ }
  }

  const noAuth = hosts.filter(h => h.riskLevel === 'critical').length;
  return {
    findings, hosts,
    summary: { scanned: targets.length, alive: aliveList.length, cameras: hosts.length, noAuth }
  };
}

function netdiagZone(ip) {
  if (/^10\.252\./.test(ip)) return '管理网段';
  const a = ip.split('.')[0];
  if (a === '10') return '10 网段';
  if (a === '172') return '172 网段';
  if (a === '192') return '192 网段';
  return '未分组';
}

/* ======================================================================== *
 *                        检测器 2：IP 冲突检测
 * ======================================================================== */
async function detectIpConflict(opts) {
  const { targets } = opts;
  const cfg = (db.settingsSync() || {}).netdiag || {};
  const rounds = Math.max(1, Math.min(6, Number(opts.rounds || (cfg.conflict && cfg.conflict.rounds) || 3)));
  const timeoutMs = Math.max(300, Math.min(4000, Number(opts.timeoutMs || 1200)));
  const findings = [];
  const hosts = [];

  const seen = new Map();          // ip -> Set<mac>
  const flushable = await arpFlush();   // 清缓存能让「谁在答这个 IP」暴露得更彻底
  for (let r = 0; r < rounds; r++) {
    await pool(targets, Math.min(64, Math.max(8, Number(opts.concurrency || 48))), async (ip) => {
      await netutil.pingOnce(ip, timeoutMs);
    });
    await sleep(250);
    const tab = await arpTable();
    for (const [ip, mac] of tab) {
      if (!ipToInt(ip)) continue;
      if (!seen.has(ip)) seen.set(ip, new Set());
      seen.get(ip).add(mac);
    }
    if (r < rounds - 1) await sleep(600);
  }

  // 反查：同一 MAC 对应多个 IP（可能是路由器/NAT/代理，也可能是误配）
  const macToIps = new Map();
  for (const [ip, macs] of seen) for (const mac of macs) {
    if (!macToIps.has(mac)) macToIps.set(mac, new Set());
    macToIps.get(mac).add(ip);
  }

  const conflicts = [];
  for (const [ip, macs] of seen) {
    if (macs.size >= 2) conflicts.push({ ip, macs: [...macs] });
  }

  // 被动交叉验证：ARP 应答/通告里同一个 IP 被两个 MAC 声明（最权威的证据）
  let passive = null;
  const exe = netutil.findTshark();
  if (exe && opts.passive !== false && targets.length) {
    try {
      const { frames, linkType } = await sniffFrames({ iface: opts.iface, filter: 'arp', seconds: Math.max(3, Math.min(20, Number(opts.seconds || 6))) });
      const claim = new Map();
      let arpCount = 0, garp = 0;
      for (const f of frames) {
        const e = decodeEth(f.data, linkType);
        if (!e || e.type !== 0x0806) continue;
        const a = decodeArp(f.data, e.p);
        if (!a) continue;
        arpCount++;
        const isAnnounce = a.op === 2 || (a.op === 1 && a.spa === a.tpa);
        if (isAnnounce && a.spa && a.spa !== '0.0.0.0') {
          garp++;
          if (!claim.has(a.spa)) claim.set(a.spa, new Set());
          claim.get(a.spa).add(a.sha);
        }
      }
      passive = { arpCount, garp, frames: frames.length };
      for (const [ip, macs] of claim) {
        if (macs.size >= 2 && !conflicts.some(c => c.ip === ip)) conflicts.push({ ip, macs: [...macs], passive: true });
      }
    } catch (e) {
      passive = { error: e.message };
    }
  }

  for (const c of conflicts) {
    const alias = c.macs.map(m => m).join(' / ');
    hosts.push({
      ip: c.ip, mac: alias, vendor: '', model: '', kind: 'IP 冲突',
      riskLevel: 'critical', riskDesc: `同一 IP 被 ${c.macs.length} 个 MAC 声明`,
      data: { macs: c.macs, passive: !!c.passive }
    });
    findings.push({
      level: 'critical', category: '地址冲突', target: c.ip,
      title: `${c.ip} 存在 IP 地址冲突`,
      detail: `在 ${rounds} 轮采样中，${c.ip} 被 ${c.macs.length} 个不同 MAC 应答：${alias}`
        + (c.passive ? '（旁路抓包也抓到了同一 IP 的多个 ARP 通告，证据确凿）' : '')
        + '。冲突时业务表现为时通时断、连接随机失败。',
      advice: `① 用 arp -a ${c.ip} 反复观察，或登录接入交换机 show mac address-table | include ${ipToMacTail(c.macs)} 定位两个 MAC 各自的端口；`
        + '② 找到私接地址的设备后改成 DHCP 或换地址；③ 在核心交换机上开启 IP Source Guard / DAI，DHCP 环境用 DHCP Snooping 从根上防止地址被抢。',
      evidence: { macs: c.macs, rounds, passive }
    });
  }

  // 多 IP 同 MAC：常见于私接路由器/NAT，把整个网段带跑偏
  for (const [mac, ips] of macToIps) {
    if (ips.size < 2) continue;
    const list = [...ips];
    if (list.length > 32) continue;                  // 数量太大通常是网关/三层设备，不算异常
    const isConflictMac = conflicts.some(c => c.macs.includes(mac));
    if (isConflictMac) continue;
    findings.push({
      level: 'medium', category: '地址冲突', target: list[0],
      title: `${list.length} 个 IP 共用 MAC ${mac}`,
      detail: `MAC ${mac} 同时出现在 ${list.slice(0, 12).join('、')}${list.length > 12 ? ' 等' : ''}。`
        + '常见于私接路由器/NAT 设备、代理或用 MAC 克隆的旁路设备。',
      advice: '① 用交换机 MAC 表定位该 MAC 的接入端口；② 若是私接路由器，按管理规约处理；③ 若这是合法的三层设备/防火墙，可忽略。',
      evidence: { mac, ips: list }
    });
    hosts.push({
      ip: list[0], mac, vendor: '', model: '', kind: '多 IP 同 MAC',
      riskLevel: 'medium', riskDesc: `${list.length} 个 IP 共用 MAC`, data: { ips: list }
    });
  }

  if (!conflicts.length) {
    findings.push({
      level: 'info', category: '地址冲突', target: `${targets.length} 个地址`,
      title: '未发现 IP 地址冲突',
      detail: `完成 ${rounds} 轮 ARP 采样，覆盖 ${targets.length} 个地址，每个 IP 只对应一个 MAC。`
        + (flushable ? '' : '（注意：本次没清掉 ARP 缓存，权限不足时冲突可能被旧表掩盖，建议以管理员身份运行）')
        + (passive && !passive.error ? `旁路 ARP 嗅探 ${passive.seconds || ''}${passive.arpCount} 条 ARP 报文，未见重复声明。` : ''),
      advice: '冲突往往只在特定时刻出现，建议配成定时任务每小时跑一次，并把结果接进告警。',
      evidence: { rounds, passive }
    });
  }

  return { findings, hosts, summary: { scanned: targets.length, conflicts: conflicts.length, sampledRounds: rounds, arpEntries: seen.size, passive } };
}

function ipToMacTail(macs) {
  return (macs[0] || '').replace(/:/g, '').slice(-4).toLowerCase();
}

/* ======================================================================== *
 *                        检测器 3：环路检测
 * ======================================================================== */
async function detectLoop(opts) {
  const { targets } = opts;
  const cfg = (db.settingsSync() || {}).netdiag || {};
  const seconds = Math.max(2, Math.min(30, Number(opts.seconds || (cfg.loop && cfg.loop.seconds) || 8)));
  const findings = [];

  let frames, linkType, log = '';
  try {
    const r = await sniffFrames({
      iface: opts.iface,
      filter: 'arp or ether broadcast or ether dst 01:80:c2:00:00:00',
      seconds
    });
    frames = r.frames; linkType = r.linkType; log = r.log;
  } catch (e) {
    return {
      findings: [{
        level: 'info', category: '环路检测', target: '本机',
        title: '环路检测需要本机抓包能力',
        detail: `未能抓包：${e.message}`,
        advice: '安装 Wireshark（含 Npcap）后重试，或在「系统管理 → 抓包」里指定 tshark.exe 路径。'
          + '没有本机抓包时，也可以登录接入交换机执行 show interfaces counters broadcast / display interface | include broadcast 观察广播计数是否异常增长。',
        evidence: { error: e.message }
      }],
      hosts: [],
      summary: { error: e.message, seconds }
    };
  }

  const st = {
    total: 0, bcast: 0, mcast: 0, arp: 0, stp: 0, ipv4: 0,
    bcastSrc: new Map(),          // 源 MAC → 广播帧数
    bcastSrcIps: new Map(),       // 源 MAC → Set<源 IP>（一个 MAC 挂多个 IP 常见于环路/NAT）
    idTtl: new Map(),             // srcIp|dstIp|id|proto|len|秒 → Set<TTL>
    dup: new Map(),               // 帧指纹 → 次数
    arpDup: new Map()             // spa|tpa → 次数
  };
  const nets = opts.nets || [];
  const netOf = (ip) => {
    const n = ipToInt(ip);
    if (n === null) return '';
    for (const x of nets) {
      const base = ipToInt(x.cidr.split('/')[0]);
      const mask = (0xffffffff << (32 - x.prefix)) >>> 0;
      if (((n & mask) >>> 0) === base) return x.cidr;
    }
    return '';
  };
  const bcastNet = new Map();

  for (const f of frames) {
    st.total++;
    const e = decodeEth(f.data, linkType);
    if (!e) continue;
    const isBcast = e.dst === 'ff:ff:ff:ff:ff:ff';
    const isMcast = !!e.dst && e.dst !== 'ff:ff:ff:ff:ff:ff' && (parseInt(e.dst.slice(0, 2), 16) & 1) === 1;
    if (isBcast) st.bcast++; else if (isMcast) st.mcast++;

    // STP/BPDU：目的 MAC 01:80:c2:00:00:00，或 LLC DSAP 0x42
    if (e.dst === '01:80:c2:00:00:00' || (e.type <= 1500 && f.data[e.p] === 0x42)) { st.stp++; continue; }

    if (e.type === 0x0806) {
      const a = decodeArp(f.data, e.p);
      if (a) {
        st.arp++;
        const k = `${a.spa}|${a.tpa}`;
        st.arpDup.set(k, (st.arpDup.get(k) || 0) + 1);
      }
      continue;
    }
    if (e.type !== 0x0800) continue;

    const ip = decodeIpv4(f.data, e.p);
    if (!ip) continue;
    st.ipv4++;
    // 同 IP-ID 不同 TTL：同一帧从两条路径到达，环路的教科书特征
    const bucket = Math.floor(f.t);
    const key = `${ip.src}|${ip.dst}|${ip.id}|${ip.proto}|${ip.totalLen}|${bucket}`;
    if (!st.idTtl.has(key)) st.idTtl.set(key, new Set());
    st.idTtl.get(key).add(ip.ttl);
    // 重复帧指纹
    const head = f.data.subarray(ip.p, Math.min(f.data.length, ip.p + 16)).toString('hex');
    const fp = `${e.src}|${ip.id}|${ip.proto}|${ip.totalLen}|${head}`;
    st.dup.set(fp, (st.dup.get(fp) || 0) + 1);

    if (isBcast) {
      st.bcastSrc.set(e.src, (st.bcastSrc.get(e.src) || 0) + 1);
      if (!st.bcastSrcIps.has(e.src)) st.bcastSrcIps.set(e.src, new Set());
      st.bcastSrcIps.get(e.src).add(ip.src);
      const n = netOf(ip.src);
      if (n) bcastNet.set(n, (bcastNet.get(n) || 0) + 1);
    }
  }

  const ttlAnomalies = [...st.idTtl.entries()].filter(([, s]) => s.size >= 2);
  const dupFrames = [...st.dup.entries()].filter(([, c]) => c >= 3);
  const bcastRatio = st.total ? st.bcast / st.total : 0;
  const bcastPps = st.bcast / seconds;
  const arpStorm = [...st.arpDup.entries()].filter(([, c]) => c >= 8).sort((a, b) => b[1] - a[1]);
  const heavyTalkers = [...st.bcastSrc.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const multiIpMac = [...st.bcastSrcIps.entries()].filter(([, s]) => s.size >= 6);

  const rate = (v) => `${(v * 100).toFixed(1)}%`;
  const base = {
    seconds, frames: st.total, broadcast: st.bcast, broadcastRatio: +bcastRatio.toFixed(4),
    broadcastPps: Math.round(bcastPps), multicast: st.mcast, arp: st.arp, stp: st.stp, ipv4: st.ipv4,
    ttlMismatch: ttlAnomalies.length, duplicateFrames: dupFrames.length,
    topTalkers: heavyTalkers.map(([mac, n]) => ({ mac, frames: n, ips: [...(st.bcastSrcIps.get(mac) || [])].slice(0, 8) })),
    byNet: [...bcastNet.entries()].map(([cidr, n]) => ({ cidr, broadcast: n })),
    iface: opts.iface || '自动'
  };

  if (ttlAnomalies.length) {
    const sample = ttlAnomalies.slice(0, 3).map(([k, s]) => {
      const [src, dst, id] = k.split('|');
      return `${src} → ${dst}（IP-ID ${id}，TTL ${[...s].sort((a, b) => a - b).join('/')}）`;
    });
    findings.push({
      level: 'critical', category: '二层环路', target: opts.iface || '本机',
      title: `检测到 ${ttlAnomalies.length} 组「同 IP-ID 不同 TTL」的重复帧，二层环路高度可疑`,
      detail: `同一份数据帧从两条不同长度的路径到达本机（TTL 不同说明多经过了一跳），这是环路最典型的特征。示例：${sample.join('；')}。`
        + `抓包 ${seconds}s，共 ${st.total} 帧，广播占比 ${rate(bcastRatio)}（${Math.round(bcastPps)} 帧/秒）。`,
      advice: '① 先在接入层按端口看广播计数：Cisco `show interfaces | include broadcast`、华为 `display interface | include broadcast`，异常增长的那个口就是环路方向；'
        + '② 对比 MAC 地址表看同一 MAC 是否在两个端口间漂移：`show mac address-table address <mac>`；'
        + '③ 定位后在接入交换机上开启 STP/RSTP 与 BPDU Guard、Edge Port，并把私接的交换机/小路由改成不转发 BPDU 的哑设备；'
        + '④ 临时处置可按端口错峰 shutdown 缩小范围。',
      evidence: { ...base, samples: ttlAnomalies.slice(0, 8).map(([k, s]) => ({ key: k, ttls: [...s] })) }
    });
  } else if (bcastRatio > 0.25 || bcastPps > 300) {
    findings.push({
      level: 'high', category: '广播风暴', target: opts.iface || '本机',
      title: `广播流量异常：占比 ${rate(bcastRatio)}，${Math.round(bcastPps)} 帧/秒`,
      detail: `抓包 ${seconds}s 共 ${st.total} 帧，广播 ${st.bcast} 帧。正常办公网广播占比通常在 5% 以内。`
        + (heavyTalkers.length ? `广播最多的源 MAC：${heavyTalkers.slice(0, 3).map(([m, n]) => `${m}(${n} 帧)`).join('、')}。` : '')
        + (dupFrames.length ? `另有 ${dupFrames.length} 组完全重复的帧。` : ''),
      advice: '① 先在接入层找广播源端口（看广播计数增量最大的口）；② 检查是否有私接交换机形成环、或设备网卡/驱动故障疯狂发包；'
        + '③ 划分 VLAN 缩小广播域，接入端口开风暴抑制（storm-control / broadcast-suppression）；④ 若广播源是单一 MAC，直接拔掉该终端验证。',
      evidence: { ...base, duplicates: dupFrames.slice(0, 8).map(([k, c]) => ({ key: k, count: c })) }
    });
  } else if (dupFrames.length || bcastRatio > 0.10 || arpStorm.length) {
    const bits = [];
    if (dupFrames.length) bits.push(`${dupFrames.length} 组帧完全重复`);
    if (bcastRatio > 0.10) bits.push(`广播占比 ${rate(bcastRatio)} 偏高`);
    if (arpStorm.length) bits.push(`ARP 请求重复（最多一组重复 ${arpStorm[0][1]} 次）`);
    findings.push({
      level: 'medium', category: '二层环路', target: opts.iface || '本机',
      title: `存在可疑的重复流量：${bits.join('，')}`,
      detail: `抓包 ${seconds}s 共 ${st.total} 帧，广播 ${st.bcast} 帧（${rate(bcastRatio)}）。未发现「同 IP-ID 不同 TTL」的确证特征，`
        + '但不能完全排除环路或二层冗余转发。',
      advice: '① 延长抓包时间到 30s 再复测（环路特征在空闲时段更明显）；② 在接入交换机上开启 STP 并检查是否有端口反复 topology change；'
        + '③ 检查网卡是否做了桥接/双网卡同时接入同一网段。',
      evidence: { ...base, duplicates: dupFrames.slice(0, 8).map(([k, c]) => ({ key: k, count: c })) }
    });
  } else {
    findings.push({
      level: 'info', category: '二层环路', target: opts.iface || '本机',
      title: '未发现环路特征',
      detail: `抓包 ${seconds}s 共 ${st.total} 帧，广播 ${st.bcast} 帧（${rate(bcastRatio)}，${Math.round(bcastPps)} 帧/秒），`
        + `ARP ${st.arp} 帧、STP/BPDU ${st.stp} 帧，无重复帧与 TTL 异常。`,
      advice: '网络二层转发正常。建议把环路检测配成定时任务（如每 10 分钟一次），环路往往在有人私接设备时才出现。',
      evidence: base
    });
  }

  if (multiIpMac.length) {
    const [mac, ips] = multiIpMac[0];
    findings.push({
      level: 'low', category: '二层环路', target: mac,
      title: `MAC ${mac} 后面挂了 ${ips.size} 个源 IP`,
      detail: `一个源 MAC 发出大量广播却带 ${ips.size} 个不同源 IP，通常是该口下接了交换机/路由器（存在环路或私接子网），`
        + `也可能是开了代理 ARP。地址：${[...ips].slice(0, 8).join('、')}。`,
      advice: '用接入交换机的 MAC 地址表定位该 MAC 所在端口，确认该端口下是否私接了交换机；有条件时在接入口启用 BPDU Guard 与端口安全（port-security 限制 MAC 数）。',
      evidence: { mac, ips: [...ips].slice(0, 16) }
    });
  }

  return { findings, hosts: [], summary: { ...base, captureLog: log.slice(0, 400) } };
}

/* ======================================================================== *
 *                        检测器 4：日志审计
 * ======================================================================== */
/** Syslog 审计规则：命中即归类，并给出处置建议 */
const LOG_RULES = [
  { key: 'auth.bruteforce', re: /(failed password|authentication fail|login fail|invalid user|auth\.?fail|密码错误|认证失败|登录失败|login incorrect)/i, level: 'high', category: '登录审计', title: '登录失败', advice: '确认是否为口令暴力破解：锁定源 IP、启用登录失败锁定与双因素，核对是否有弱口令账号。' },
  { key: 'cfg.change', re: /(configured from|config(uration)? (changed|modified|saved)|commit(?!ted)|write memory|copy run start|保存配置|配置变更|user (added|removed))/i, level: 'medium', category: '配置变更', title: '设备配置发生变更', advice: '核对变更是否走过审批，并对比配置备份差异；建议开启配置自动备份与变更审计。' },
  { key: 'link.flap', re: /(link (down|up)|line protocol.*(down|up)|interface .*(down|up)|端口 down|端口 up|链路(断开|恢复))/i, level: 'medium', category: '链路状态', title: '接口 up/down', advice: '抖动频繁多为光模块劣化、网线接触不良或对端设备重启，检查光功率与错包计数。' },
  { key: 'power.fan.temp', re: /(fan (fail|fault|bad)|power supply.*(fail|fault|absent)|over ?temperature|temperature.*(high|over|critical)|温度过高|风扇故障|电源故障)/i, level: 'critical', category: '硬件健康', title: '硬件告警（风扇/电源/温度）', advice: '立即现场检查：清理风道、确认双电源都接通、必要时降载或更换备件，这类告警拖久了会直接宕机。' },
  { key: 'reboot', re: /(system (restarted|reboot)|warm start|cold start|reload(ing)?|reboot|重启|重新启动)/i, level: 'high', category: '设备状态', title: '设备重启', advice: '确认是计划内重启还是意外掉电。意外重启要查电源、UPS 与温度记录。' },
  { key: 'stp.change', re: /(topology change|spanning.?tree.*(change|root)|STP.*(change|blocked)|生成树.*(变化|变更))/i, level: 'high', category: '二层环路', title: '生成树拓扑变更', advice: '拓扑反复变更多为环路或链路抖动，配合「环路检测」工具定位；接入口要开 BPDU Guard。' },
  { key: 'routing.flap', re: /(neighbor.*(down|up)|adjacency.*(down|up)|bgp.*(down|reset)|ospf.*(down|dead)|邻居.*(中断|恢复))/i, level: 'high', category: '路由协议', title: '路由邻居状态变化', advice: '检查互联链路质量（错包/丢包）与 MTU、认证配置，抖动会导致路由震荡。' },
  { key: 'acl.deny', re: /(denied|deny|blocked|dropped|drop |拒绝|丢弃)/i, level: 'low', category: '安全策略', title: '策略命中/丢包', advice: '量少属正常。若某一源地址短时间大量命中，可能是扫描或误配，建议核查。' },
  { key: 'sec.log.clear', re: /(audit log.*(clear|deleted)|event log.*cleared|日志.{0,4}(清除|清空))/i, level: 'critical', category: '登录审计', title: '日志被清除', advice: '这是典型的入侵痕迹清理动作，立即排查是谁在什么时候做的，并检查其它主机是否也有同类行为。' },
  { key: 'vpn.tunnel', re: /(tunnel (down|up)|ipsec.*(down|up|fail)|vpn.*(disconnect|fail))/i, level: 'medium', category: '链路状态', title: 'VPN/IPsec 隧道状态变化', advice: '核对对端设备与预共享密钥，检查出口带宽与 DPD 参数。' },
  { key: 'dhcp.event', re: /(dhcp.*(conflict|nak|denied)|地址冲突)/i, level: 'high', category: '地址冲突', title: 'DHCP 冲突/NAK', advice: '说明地址池内有冲突或被抢用，配合「IP 冲突检测」定位，并检查是否有私接 DHCP 服务器。' },
  { key: 'disk.mem.cpu', re: /(memory.*(high|exhaust|critical)|cpu.*(high|utilization)|disk.*(full|fail)|内存.{0,4}(不足|溢出)|磁盘.{0,4}(满|故障))/i, level: 'high', category: '性能容量', title: '资源使用率异常', advice: '查进程占用与最近变更；控制平面高占用常见于环路、路由震荡或攻击。' }
];

/** 解析一条 syslog 文本 → 结构化 */
function parseSyslog(text, fromIp) {
  let rest = String(text || '').replace(/\0+$/, '').trim();
  let severity = 6, facility = 'user';
  const pri = rest.match(/^<(\d{1,3})>/);
  if (pri) { const v = Number(pri[1]); severity = v % 8; facility = String(Math.floor(v / 8)); rest = rest.slice(pri[0].length); }
  // RFC5424: <PRI>1 2024-01-01T00:00:00Z host app procid msgid - msg
  let host = '', tag = '', msg = rest;
  const rfc5424 = rest.match(/^1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S*)\s*([\s\S]*)$/);
  if (rfc5424) {
    // RFC5424 字段序：VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]
    // 所以组号是 1版本 2主机名 3 APP-NAME(tag) 4 PROCID 5 MSGID 6 结构化数据 7 消息
    host = rfc5424[2] === '-' ? '' : rfc5424[2];
    tag = rfc5424[3] === '-' ? '' : rfc5424[3];
    msg = rfc5424[7] || '';
  } else {
    // RFC3164: Mon DD HH:MM:SS HOST TAG: MSG
    const m = rest.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\s\S]*)$/);
    if (m) {
      host = m[2] === '-' ? '' : m[2];
      const t = (m[3] || '').match(/^([A-Za-z0-9_\-./]{1,32})(?:\[\d+\])?:\s*([\s\S]*)$/);
      if (t) { tag = t[1]; msg = t[2]; } else msg = m[3] || '';
    }
  }
  return { host: host || fromIp || 'unknown', tag, msg: msg.slice(0, 2000), severity, facility };
}

function classifyLog(row) {
  const text = `${row.tag || ''} ${row.msg || ''}`;
  for (const r of LOG_RULES) {
    if (r.re.test(text)) return { rule: r.key, level: r.level, category: r.category, title: r.title, advice: r.advice };
  }
  // 没命中规则时按 syslog 严重度兜底（0 emerg / 1 alert / 2 crit / 3 err）
  const sevMap = { 0: 'critical', 1: 'critical', 2: 'high', 3: 'medium', 4: 'low' };
  return { rule: '', level: sevMap[row.severity] || 'info', category: '其他', title: '', advice: '' };
}

/** Windows 事件日志 → 统一日志行（本机也要能审计，不然没设备发日志时这个工具就是空的） */
const WIN_EVENT_RULES = {
  1102: { level: 'critical', rule: 'sec.log.clear', title: '安全日志被清除', advice: '这是入侵痕迹清理的典型动作，立即排查操作来源并检查其它主机。' },
  4719: { level: 'high', rule: 'cfg.change', title: '审计策略被修改', advice: '确认变更审批，审计策略被关掉等于失去追溯能力。' },
  4625: { level: 'medium', rule: 'auth.bruteforce', title: '登录失败', advice: '单次属正常；短时间大量出现即为口令爆破，需锁定源 IP。' },
  4720: { level: 'medium', rule: 'cfg.change', title: '创建账号', advice: '核对账号是否经过审批，检查其权限组。' },
  4726: { level: 'medium', rule: 'cfg.change', title: '删除账号', advice: '确认为计划内操作，避免离职流程外的删号。' },
  4672: { level: 'info', rule: '', title: '分配特权', advice: '' },
  4624: { level: 'info', rule: '', title: '登录成功', advice: '' },
  7045: { level: 'medium', rule: 'reboot', title: '安装系统服务', advice: '确认服务来源可信，恶意软件常以服务方式驻留。' },
  1074: { level: 'high', rule: 'reboot', title: '系统被重启', advice: '确认是计划内操作，非计划内的要查发起进程与账号。' },
  6008: { level: 'high', rule: 'reboot', title: '意外关机', advice: '查电源/UPS 与温度记录。' },
  41: { level: 'high', rule: 'reboot', title: '非正常断电（Kernel-Power）', advice: '查电源与 UPS，频繁出现会损伤硬件。' },
  7031: { level: 'medium', rule: 'power.fan.temp', title: '服务意外终止', advice: '查看该服务的日志与崩溃转储，确认是否与资源不足有关。' },
  7034: { level: 'medium', rule: 'power.fan.temp', title: '服务意外终止', advice: '同上，关注是否反复出现。' }
};

async function readLocalEventLog({ limit = 200 } = {}) {
  if (!IS_WIN) {
    return { rows: [], error: '当前平台不是 Windows，本机事件日志审计仅支持 Windows（Linux 可读 journalctl，暂未接入）' };
  }
  const rows = [];
  const errors = [];
  for (const logName of ['Security', 'System']) {
    const r = await execFileP('wevtutil', ['qe', logName, `/c:${Math.max(1, Math.min(1000, limit))}`, '/rd:true', '/f:text'],
      30000);
    if (!r.ok) { errors.push(`${logName}: ${(r.err || '').split('\n')[0].slice(0, 120)}`); continue; }
    const blocks = r.out.split(/\r?\n\r?\n+/);
    for (const b of blocks) {
      const idM = b.match(/Event ID:\s*(\d+)/i);
      if (!idM) continue;
      const id = Number(idM[1]);
      const timeM = b.match(/Time Created:\s*([^\n]+)/i) || b.match(/Date:\s*([^\n]+)/i);
      const descM = b.match(/Description:\s*([\s\S]*)$/i);
      const raw = (descM ? descM[1] : b).replace(/\s+/g, ' ').trim();
      const meta = WIN_EVENT_RULES[id];
      rows.push({
        source: 'local', host: os.hostname(), srcIp: '',
        facility: logName === 'Security' ? 'security' : 'system',
        severity: meta ? (meta.level === 'critical' ? 2 : meta.level === 'high' ? 3 : meta.level === 'medium' ? 4 : 6) : 6,
        tag: `${logName}/${id}`,
        message: raw.slice(0, 500) || `事件 ID ${id}`,
        rule: meta ? meta.rule : '', level: meta ? meta.level : 'info',
        logAt: timeM ? safeDate(timeM[1]) : new Date().toISOString(),
        eventId: id
      });
    }
  }
  return { rows, error: errors.join('；') };
}

function safeDate(s) {
  const d = new Date(String(s).trim());
  return isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

/** 审计聚合：把原始日志按规则汇总成问题清单，避免几万条日志变成几万条问题 */
function auditAggregate(logs, { windowMinutes = 0, minCount = {} } = {}) {
  const findings = [];
  const byRule = new Map();
  let from = Infinity, to = 0;
  for (const l of logs) {
    const t = Date.parse(l.logAt || l.createdAt || '') || 0;
    if (t) { from = Math.min(from, t); to = Math.max(to, t); }
  }
  const span = to > from ? (to - from) / 60000 : 0;
  for (const l of logs) {
    if (!l.level || l.level === 'info') continue;
    const key = l.rule || `${l.level}:${l.tag || 'unknown'}`;
    if (!byRule.has(key)) {
      byRule.set(key, {
        key, level: l.level, rule: l.rule, tag: l.tag, hosts: new Map(), count: 0, sample: l.message || ''
      });
    }
    const e = byRule.get(key);
    e.count++;
    e.hosts.set(l.host || '-', (e.hosts.get(l.host || '-') || 0) + 1);
    if ((LEVEL_ORDER[l.level] || 0) > (LEVEL_ORDER[e.level] || 0)) e.level = l.level;
  }
  const DEF_MIN = { high: 3, medium: 5, low: 10 };
  for (const e of byRule.values()) {
    const need = minCount[e.level] !== undefined ? minCount[e.level] : (DEF_MIN[e.level] || 0);
    if (e.count < need) continue;
    const rule = LOG_RULES.find(r => r.key === e.rule);
    const hosts = [...e.hosts.entries()].sort((a, b) => b[1] - a[1]);
    findings.push({
      level: e.level, category: (rule && rule.category) || '其他日志',
      target: hosts[0] ? hosts[0][0] : '多台设备',
      title: `${(rule && rule.title) || e.tag || '日志告警'} × ${e.count}`,
      detail: `窗口内命中 ${e.count} 条（涉及 ${hosts.length} 台设备：${hosts.slice(0, 5).map(([h, n]) => `${h}(${n})`).join('、')}${hosts.length > 5 ? ' 等' : ''}）。`
        + `最近一条：${String(e.sample).slice(0, 300)}`,
      advice: (rule && rule.advice) || '结合设备侧日志与变更记录人工确认。',
      evidence: { rule: e.rule, count: e.count, hosts: hosts.slice(0, 20), minutes: +span.toFixed(1), sample: String(e.sample).slice(0, 500) }
    });
  }
  return findings;
}

async function detectLogAudit(opts) {
  const src = String(opts.source || 'auto');        // auto | syslog | local
  const limit = Math.max(20, Math.min(2000, Number(opts.limit || 500)));
  const findings = [];
  const logs = [];
  const summary = { source: src, fetched: 0, rules: LOG_RULES.length };

  // 1) 本机事件日志（可选用；默认 auto 时也读，让工具开箱有料）
  if (src === 'local' || src === 'auto') {
    const lr = await readLocalEventLog({ limit: Math.min(limit, 500) });
    if (lr.rows.length) {
      for (const r of lr.rows) logs.push({ ...r, runId: opts.runId || '' });
      summary.localEvents = lr.rows.length;
    }
    if (lr.error) summary.localError = lr.error;
    if (src === 'local' && !lr.rows.length) {
      findings.push({
        level: 'info', category: '日志审计', target: os.hostname(),
        title: '未能读取本机事件日志',
        detail: `读取失败：${lr.error || '未知原因'}。读取 Security 日志需要管理员权限。`,
        advice: '以管理员身份启动控制台（或改用 Syslog 接收模式，让网络设备把日志发过来）。',
        evidence: { error: lr.error }
      });
    }
  }

  // 2) 已接收并入库的 Syslog
  if (src === 'syslog' || src === 'auto') {
    const from = opts.from || (opts.hours ? new Date(Date.now() - Number(opts.hours) * 3600e3).toISOString() : '');
    const r = await db.netdiagLogSearch({ source: 'syslog', from, limit, offset: 0 });
    summary.syslogRows = r.total;
    for (const row of r.rows) logs.push(row);
    const st = await db.netdiagLogStats({ from });
    summary.byLevel = st.byLevel;
    summary.byHost = st.byHost;
    summary.byRule = st.byRule;
  }

  // 入库本机事件日志（syslog 是接收时就入库的，本机事件日志在这里入库）
  const fresh = logs.filter(l => l.source === 'local');
  if (fresh.length) {
    await db.netdiagLogInsert(fresh.map(l => ({
      id: store.uid('ndl_'), runId: opts.runId || '', source: 'local',
      host: l.host, srcIp: '', facility: l.facility, severity: l.severity,
      tag: l.tag, message: l.message, rule: l.rule, level: l.level,
      logAt: l.logAt, createdAt: new Date().toISOString()
    })));
  }

  // 3) 重新分类（历史日志可能是规则升级前入库的）
  for (const l of logs) {
    if (!l.level || l.level === 'info') {
      const c = classifyLog(l);
      if (c.rule) { l.rule = c.rule; l.level = c.level; }
    }
  }

  const agg = auditAggregate(logs, { minCount: opts.minCount || {} });
  findings.push(...agg);
  summary.fetched = logs.length;
  summary.hit = logs.filter(l => l.level && l.level !== 'info').length;

  if (!findings.length) {
    findings.push({
      level: 'info', category: '日志审计', target: os.hostname(),
      title: '窗口内没有命中审计规则',
      detail: `共审计 ${logs.length} 条日志（本机事件 ${summary.localEvents || 0} 条，Syslog ${summary.syslogRows || 0} 条），`
        + `${LOG_RULES.length} 条规则均未命中（或命中数未达阈值）。`,
      advice: '建议在网络设备上把日志指向本机（logging host <本机IP>），并在「诊断工具箱 → 日志审计」里开启 Syslog 接收，才能持续覆盖设备侧事件。',
      evidence: summary
    });
  }

  return { findings, hosts: [], logs: fresh, summary };
}

/* ======================================================================== *
 *                        检测器 5：外网测速
 * ======================================================================== */
/** 定长下载：并行拉流，去掉前 1 秒预热，按实际收到的字节算带宽 */
function downloadTest(url, { seconds = 8, parallel = 4, timeoutMs = 20000 } = {}) {
  return new Promise(resolve => {
    let total = 0, warmBytes = 0, warmAt = 0, finished = 0, errors = [];
    let settled = false;
    const t0 = Date.now();
    const warmMs = 1000;
    const fin = () => {
      if (settled) return;
      settled = true;
      const elapsed = (Date.now() - warmAt) / 1000;
      const bytes = Math.max(0, total - warmBytes);
      resolve({
        bytes: total, warmBytes, elapsed: +elapsed.toFixed(2),
        bps: elapsed > 0.2 ? bytes * 8 / elapsed : (total * 8 / ((Date.now() - t0) / 1000 || 1)),
        errors
      });
    };
    let reqs = [];
    for (let i = 0; i < Math.max(1, parallel); i++) {
      const u = url.includes('{bytes}') ? url.replace('{bytes}', String(8 * 1024 * 1024)) : url;
      let req;
      try {
        const p = new URL(u);
        const lib = p.protocol === 'https:' ? https : http;
        req = lib.get({
          protocol: p.protocol, hostname: p.hostname, port: p.port || (p.protocol === 'https:' ? 443 : 80),
          path: p.pathname + p.search, headers: { 'User-Agent': 'NetOpsDiag/1.0', 'Cache-Control': 'no-cache' },
          timeout: timeoutMs, rejectUnauthorized: false
        }, res => {
          if (res.statusCode >= 400) { errors.push(`HTTP ${res.statusCode}`); }
          res.on('data', d => {
            const now = Date.now();
            if (!warmAt) { warmAt = now; warmBytes = total; }
            if (now - warmAt < warmMs) warmBytes += d.length;
            total += d.length;
            if (now - t0 >= seconds * 1000) { try { req.destroy(); } catch { } }
          });
          res.on('error', e => errors.push(e.code || e.message));
          res.on('close', () => { finished++; if (finished >= reqs.length) fin(); });
        });
      } catch (e) { errors.push(e.message); continue; }
      req.on('error', e => { errors.push(e.code || e.message); finished++; if (finished >= reqs.length) fin(); });
      req.on('timeout', () => { try { req.destroy(); } catch { } });
      reqs.push(req);
    }
    if (!reqs.length) return fin();
    if (!warmAt) warmAt = t0;
    setTimeout(fin, seconds * 1000 + 800);
  });
}

/** 定长上传：先定一个大小，够了就加码重测，保证既不过慢也不过粗 */
async function uploadTest(url, { seconds = 6, parallel = 2, sizeBytes = 4 * 1024 * 1024, maxBytes = 48 * 1024 * 1024 } = {}) {
  let size = sizeBytes, best = null;
  for (let round = 0; round < 3; round++) {
    const chunk = Buffer.alloc(256 * 1024, 0x61);
    let sentTotal = 0;
    const t0 = Date.now();
    const tasks = [];
    for (let i = 0; i < Math.max(1, parallel); i++) {
      tasks.push(new Promise(resolve => {
        let u;
        try { u = new URL(url); } catch (e) { return resolve({ error: e.message }); }
        const lib = u.protocol === 'https:' ? https : http;
        let done = false;
        const fin = (r) => { if (done) return; done = true; resolve(r); };
        const req = lib.request({
          protocol: u.protocol, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
          path: u.pathname + u.search, method: 'POST',
          headers: { 'User-Agent': 'NetOpsDiag/1.0', 'Content-Type': 'application/octet-stream', 'Content-Length': size, Connection: 'close' },
          timeout: Math.max(15000, seconds * 3000), rejectUnauthorized: false
        }, res => { res.on('data', () => { }); res.on('end', () => fin({ status: res.statusCode })); res.on('close', () => fin({ status: res.statusCode })); });
        req.on('error', e => fin({ error: e.code || e.message }));
        req.on('timeout', () => { try { req.destroy(); } catch { } fin({ error: 'timeout' }); });
        let sent = 0;
        const pump = () => {
          while (sent < size) {
            const n = Math.min(chunk.length, size - sent);
            const ok = req.write(n === chunk.length ? chunk : chunk.subarray(0, n));
            sent += n; sentTotal += n;
            if (!ok) { req.once('drain', pump); return; }
          }
          req.end();
        };
        pump();
      }));
    }
    const rs = await Promise.all(tasks);
    const sec = (Date.now() - t0) / 1000;
    const okBytes = sentTotal;
    const bps = sec > 0 ? okBytes * 8 / sec : 0;
    best = { bps, bytes: okBytes, seconds: +sec.toFixed(2), rounds: round + 1, errors: rs.filter(r => r.error).map(r => r.error).slice(0, 3) };
    // 测得太快说明没压满链路，加码再来一轮
    if (sec < 2 && size < maxBytes) { size = Math.min(maxBytes, size * 4); continue; }
    break;
  }
  return best;
}

async function detectSpeed(opts) {
  const cfg = (db.settingsSync() || {}).netdiag || {};
  const sc = cfg.speed || {};
  const durationSec = Math.max(3, Math.min(30, Number(opts.seconds || sc.durationSec || 8)));
  const parallel = Math.max(1, Math.min(16, Number(opts.parallel || sc.parallel || 4)));
  const findings = [];
  const gw = await defaultGateway();
  const pingHost = String(opts.pingHost || sc.pingHost || '1.1.1.1');

  /* 基线：网关和内网 DNS 的延迟丢包，用来区分「出口问题」和「内网问题」 */
  const baseline = {};
  if (gw) baseline.gateway = await netutil.ping(gw, { count: 10, intervalMs: 200, timeoutMs: 1200 });
  baseline.target = await netutil.ping(pingHost, { count: 20, intervalMs: 200, timeoutMs: 1500 });

  const endpoints = Array.isArray(opts.endpoints) && opts.endpoints.length
    ? opts.endpoints.map(e => (typeof e === 'string' ? { key: e, name: e, down: e, up: '' } : e))
    : (sc.endpoints || []);

  const results = [];
  for (const ep of endpoints) {
    const item = { key: ep.key || ep.name, name: ep.name || ep.key, down: null, up: null, error: '' };
    try {
      if (ep.down) {
        const d = await downloadTest(ep.down, { seconds: durationSec, parallel });
        item.down = { bps: d.bps, bytes: d.bytes, seconds: d.elapsed, errors: d.errors.slice(0, 3) };
        if (!d.bytes) item.error = '未收到任何数据（可能被防火墙拦截或没有外网）';
      }
      if (ep.up) {
        const u = await uploadTest(ep.up, { seconds: Math.min(durationSec, 8), parallel: Math.min(2, parallel), sizeBytes: 2 * 1024 * 1024 });
        item.up = u;
      }
    } catch (e) { item.error = e.message; }
    results.push(item);
  }

  const ok = results.filter(r => r.down && r.down.bps > 0);
  const downBps = ok.length ? Math.max(...ok.map(r => r.down.bps)) : 0;
  const upBps = results.map(r => (r.up && r.up.bps) || 0).sort((a, b) => b - a)[0] || 0;
  const downMbps = +(downBps / 1e6).toFixed(2);
  const upMbps = +(upBps / 1e6).toFixed(2);
  const pk = baseline.target || {};

  const summary = {
    downloadMbps: downMbps, uploadMbps: upMbps,
    latencyMs: pk.avg, minMs: pk.min, maxMs: pk.max, jitterMs: pk.jitter, lossPct: pk.loss,
    gateway: gw, gatewayLatencyMs: baseline.gateway ? baseline.gateway.avg : null,
    gatewayLossPct: baseline.gateway ? baseline.gateway.loss : null,
    pingHost, endpoints: results, durationSec, parallel
  };

  if (!ok.length) {
    findings.push({
      level: 'high', category: '出口带宽', target: pingHost,
      title: '外网测速失败，没有任何测速端点返回数据',
      detail: `尝试的端点：${endpoints.map(e => e.name || e.key).join('、') || '（未配置）'}。`
        + (pk.avg !== null && pk.avg !== undefined ? `到 ${pingHost} 的 ICMP 平均延迟 ${pk.avg}ms（丢包 ${pk.loss}%）。` : `到 ${pingHost} 的 ICMP 也没有响应。`)
        + '这通常意味着：出口链路中断、被上游限速/封禁、需要走代理，或测速端点本身不可达。',
      advice: '① 先 ping 网关确认内网通；② 再 ping 8.8.8.8 / 114.114.114.114 判断是 DNS 还是路由问题；'
        + '③ 在「系统管理」里把测速端点改成你单位实际可访问的地址（如 IDC 的 100MB 静态文件）；④ 若走代理，请给 Node 进程配置 HTTP_PROXY。',
      evidence: summary
    });
    return { findings, hosts: [], summary };
  }

  if (pk.avg > 150) {
    findings.push({
      level: 'medium', category: '出口带宽', target: pingHost,
      title: `外网延迟偏高：平均 ${pk.avg}ms`,
      detail: `到 ${pingHost} 平均 ${pk.avg}ms（最小 ${pk.min}ms / 最大 ${pk.max}ms，抖动 ${pk.jitter}ms，丢包 ${pk.loss}%）。`
        + '办公上网问题不大，但会明显影响视频会议、远程桌面与实时业务。',
      advice: '① 对比网关延迟（本次 ' + (summary.gatewayLatencyMs ?? '-') + 'ms）：若网关就慢则是内网/本机问题；'
        + '② 用 mtr/路由追踪看是哪一跳开始变慢；③ 检查出口带宽是否被大流量占满（看「会话与流量」）。',
      evidence: summary
    });
  }
  if (pk.loss >= 2) {
    findings.push({
      level: 'high', category: '出口带宽', target: pingHost,
      title: `外网丢包 ${pk.loss}%`,
      detail: `20 次探测丢失 ${(pk.loss / 5).toFixed(0)} 次（最小延迟 ${pk.min}ms / 最大 ${pk.max}ms）。丢包会让 TCP 频繁重传，体感就是"时快时慢"。`,
      advice: '① 先测网关是否也丢包，区分内网还是出口；② 检查出口链路带宽是否跑满、光模块收发光功率是否正常；③ 联系运营商确认线路质量。',
      evidence: summary
    });
  }
  if (pk.jitter > 30) {
    findings.push({
      level: 'medium', category: '出口带宽', target: pingHost,
      title: `网络抖动偏大：${pk.jitter}ms`,
      detail: `延迟波动 ${pk.jitter}ms（最小 ${pk.min}ms / 最大 ${pk.max}ms）。抖动大对语音/视频质量影响最大。`,
      advice: '① 检查出口是否有突发大流量造成排队；② 在出口设备上为实时业务配置 QoS 优先级；③ 若抖动来自无线，检查 AP 信道干扰。',
      evidence: summary
    });
  }
  if (downMbps && downMbps < 20) {
    findings.push({
      level: downMbps < 5 ? 'high' : 'medium', category: '出口带宽', target: `${downMbps} Mbps`,
      title: `外网下行带宽偏低：${downMbps} Mbps`,
      detail: `${parallel} 并发测 ${durationSec}s，实测下行 ${downMbps} Mbps${upMbps ? `、上行 ${upMbps} Mbps` : ''}。`
        + '若与开通带宽差距明显，需要排查出口设备性能瓶颈或运营商限速。',
      advice: '① 确认测速时段是否有其它大流量业务；② 检查出口设备的 CPU/会话数是否打满；③ 单线程测一次与多线程对比，差距大说明存在单流限速或链路聚合不均衡。',
      evidence: summary
    });
  }
  if (upMbps && upMbps < 3) {
    findings.push({
      level: 'medium', category: '出口带宽', target: `${upMbps} Mbps`,
      title: `外网上行带宽偏低：${upMbps} Mbps`,
      detail: `实测上行 ${upMbps} Mbps。上行偏小会明显影响视频会议、云备份、远程办公。`,
      advice: '① 检查是否被出口策略限速；② 确认运营商标称的上行带宽；③ 上行小是多数企业宽带的固有特点，必要时申请专线。',
      evidence: summary
    });
  }

  if (!findings.length) {
    findings.push({
      level: 'info', category: '出口带宽', target: pingHost,
      title: `出口质量正常：下行 ${downMbps} Mbps / 上行 ${upMbps || '-'} Mbps / 延迟 ${pk.avg}ms`,
      detail: `到 ${pingHost} 平均 ${pk.avg}ms，抖动 ${pk.jitter}ms，丢包 ${pk.loss}%`
        + (baseline.gateway ? `；到网关 ${gw} 平均 ${baseline.gateway.avg}ms。` : '。'),
      advice: '把外网测速配成定时任务（如每天 9:00 / 14:00 / 20:00 各一次），可以留下带宽趋势，遇到运营商降速时就是证据。',
      evidence: summary
    });
  }

  return { findings, hosts: [], summary };
}

/* ======================================================================== *
 *                        检测器 6：DHCP 检测
 * ======================================================================== */
/** 本机 DHCP 租约（Windows 走 ipconfig /all，Linux 尽力而为） */
async function localLease() {
  if (IS_WIN) {
    const r = await execFileP('ipconfig', ['/all'], 10000);
    if (!r.ok) return { error: 'ipconfig 执行失败' };
    const out = r.out;
    const block = out.split(/\r?\n\r?\n+/).find(b => /(DHCP 已启用|DHCP Enabled)[^\n]*[:：]\s*(是|Yes)/i.test(b)) || '';
    const g = (re) => (block.match(re) || [])[1];
    const en = /(DHCP 已启用|DHCP Enabled)[^\n]*[:：]\s*(是|Yes)/i.test(block);
    return {
      enabled: en,
      server: (g(/(?:DHCP 服务器|DHCP Server)[^\n]*[:：]\s*(\d+\.\d+\.\d+\.\d+)/i) || '').trim(),
      ip: (g(/(?:IPv4 地址|IPv4 Address)[^\n]*[:：]\s*(\d+\.\d+\.\d+\.\d+)/i) || '').trim(),
      mask: (g(/(?:子网掩码|Subnet Mask)[^\n]*[:：]\s*(\d+\.\d+\.\d+\.\d+)/i) || '').trim(),
      gw: (g(/(?:默认网关|Default Gateway)[^\n]*[:：]\s*(\d+\.\d+\.\d+\.\d+)/i) || '').trim(),
      obtained: (g(/(?:获得租约的时间|Lease Obtained)[^\n]*[:：]\s*([^\r\n]+)/i) || '').trim(),
      expires: (g(/(?:租约过期的时间|Lease Expires)[^\n]*[:：]\s*([^\r\n]+)/i) || '').trim(),
      iface: (block.match(/^([^\r\n:]+adapter[^\r\n:]*|[^\r\n:]+适配器[^\r\n:]*)/im) || [])[0] || ''
    };
  }
  if (IS_MAC) {
    const r = await execFileP('ifconfig', [], 10000);
    const ip = (r.out.match(/inet (\d+\.\d+\.\d+\.\d+)/) || [])[1] || '';
    const gw = await defaultGateway();
    return { enabled: null, ip, gw, note: 'macOS 下未能确认是否 DHCP 获取，请以设备侧 lease 记录为准' };
  }
  const r = await execFileP('ip', ['-4', 'addr'], 5000);
  const ip = (r.out.match(/inet (\d+\.\d+\.\d+\.\d+)\/(\d+)/) || [])[1] || '';
  const gw = await defaultGateway();
  return { enabled: null, ip, gw, note: 'Linux 下未能确认是否 DHCP 获取，请以设备侧 lease 记录为准' };
}

async function detectDhcp(opts) {
  const cfg = (db.settingsSync() || {}).netdiag || {};
  const seconds = Math.max(3, Math.min(30, Number(opts.seconds || (cfg.dhcp && cfg.dhcp.seconds) || 6)));
  const findings = [];
  const lease = await localLease();
  const offers = [];
  const active = { attempted: false, ok: false, error: '', sentTo: [] };

  /* --- 主动：发 DISCOVER 收集所有 OFFER（能直接暴露私接的 DHCP 服务器） --- */
  if (opts.active !== false) {
    active.attempted = true;
    const mac = localMac();
    const xid = (Math.random() * 0xffffffff) >>> 0;
    const msg = buildDiscover(xid, mac, os.hostname());
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const targets = ['255.255.255.255'];
    const nets = localNets();
    for (const n of nets) {
      const base = ipToInt(n.cidr.split('/')[0]);
      const mask = (0xffffffff << (32 - n.prefix)) >>> 0;
      targets.push(intToIp((base | (~mask >>> 0)) >>> 0));
    }
    const bound = await new Promise(resolve => {
      const t = setTimeout(() => resolve(false), 1500);
      sock.once('error', () => { clearTimeout(t); resolve(false); });
      sock.bind(68, () => { clearTimeout(t); resolve(true); });
    });
    if (!bound) {
      active.error = '无法绑定 UDP 68（通常被系统 DHCP 客户端占用），已跳过主动探测';
      try { sock.close(); } catch { }
    } else {
      try { sock.setBroadcast(true); } catch { }
      await new Promise(resolve => {
        const t = setTimeout(resolve, seconds * 1000);
        sock.on('message', (buf, rinfo) => {
          const d = parseDhcp(buf);
          if (!d) return;
          if (d.op !== 2 || (d.msgType !== 2 && d.msgType !== 5)) return;   // 只看 OFFER / ACK
          offers.push({
            serverId: d.serverId || rinfo.address, from: rinfo.address,
            offered: d.yiaddr, mask: d.options.mask, routers: d.options.routers,
            dns: d.options.dns, leaseSec: d.options.lease, domain: d.options.domain,
            msgType: DHCP_MSG[d.msgType] || String(d.msgType)
          });
        });
        for (const to of targets) {
          try { sock.send(msg, 67, to); active.sentTo.push(to); } catch { }
        }
        active.ok = true;
        setTimeout(() => { clearTimeout(t); resolve(); }, seconds * 1000);
      });
      try { sock.close(); } catch { }
    }
  }

  /* --- 被动：抓 UDP 67/68，能看到别人申请地址的过程与所有 DHCP 服务器 --- */
  let passive = null;
  if (opts.passive !== false && netutil.findTshark()) {
    try {
      const { frames, linkType } = await sniffFrames({ iface: opts.iface, filter: 'udp port 67 or udp port 68', seconds });
      const servers = new Map(), clients = new Map();
      let dhcpFrames = 0;
      for (const f of frames) {
        const e = decodeEth(f.data, linkType);
        if (!e || e.type !== 0x0800) continue;
        const ip = decodeIpv4(f.data, e.p);
        if (!ip || ip.proto !== 17) continue;
        const u = decodeUdp(f.data, ip.p);
        if (!u) continue;
        if (!((u.sport === 67 && u.dport === 68) || (u.sport === 68 && u.dport === 67))) continue;
        const d = parseDhcp(u.payload);
        if (!d) continue;
        dhcpFrames++;
        if (d.op === 2) {
          const sid = d.serverId || ip.src;
          if (!servers.has(sid)) servers.set(sid, { serverId: sid, mac: e.src, offers: 0, clients: new Set() });
          const s = servers.get(sid);
          if (d.msgType === 2 || d.msgType === 5) s.offers++;
          if (d.chaddr) s.clients.add(d.chaddr);
        } else if (d.op === 1) {
          clients.set(d.chaddr || e.src, { mac: d.chaddr || e.src, msgType: DHCP_MSG[d.msgType] || d.msgType, host: d.options.hostname || '', yiaddr: d.yiaddr });
        }
      }
      passive = {
        frames: dhcpFrames,
        servers: [...servers.values()].map(s => ({ ...s, clients: s.clients.size })),
        clients: [...clients.values()].slice(0, 50)
      };
    } catch (e) {
      passive = { error: e.message };
    }
  }

  /* --- 汇总判定 --- */
  const serverMap = new Map();
  for (const o of offers) {
    if (!serverMap.has(o.serverId)) serverMap.set(o.serverId, { serverId: o.serverId, source: '主动探测', offer: o });
  }
  for (const s of ((passive && passive.servers) || [])) {
    if (!serverMap.has(s.serverId)) serverMap.set(s.serverId, { serverId: s.serverId, source: '被动嗅探', mac: s.mac, offers: s.offers, clients: s.clients });
  }
  const servers = [...serverMap.values()];

  const summary = {
    lease, servers, active, passive, seconds,
    serverCount: servers.length,
    offered: offers.map(o => ({ server: o.serverId, ip: o.offered, mask: o.mask, routers: o.routers, dns: o.dns, leaseSec: o.leaseSec }))
  };

  if (servers.length >= 2) {
    const gateways = new Set(offers.map(o => (o.routers || [])[0]).filter(Boolean));
    findings.push({
      level: 'high', category: 'DHCP', target: servers.map(s => s.serverId).join(', '),
      title: `网内发现 ${servers.length} 个 DHCP 服务器，存在私接/Rogue DHCP 风险`,
      detail: `应答或通告的服务器：${servers.map(s => `${s.serverId}（${s.source}${s.mac ? '，' + s.mac : ''}）`).join('；')}。`
        + (gateways.size > 1 ? `不同服务器下发的网关不一致（${[...gateways].join(' / ')}）——这正是 Rogue DHCP 抢答的典型特征。` : '')
        + (lease.server ? `本机当前租约来自 ${lease.server}。` : ''),
      advice: '① 在接入交换机所有用户端口开启 DHCP Snooping（trusted 只给上联口），从交换机层面直接堵住私接 DHCP；'
        + '② 找未授权的那个 DHCP 服务器：用它的 MAC 查交换机 MAC 表定位端口；'
        + '③ 办公网别让家用路由器直接接上来（关闭其 DHCP 或改成 AP 模式）。',
      evidence: summary
    });
  } else if (servers.length === 1) {
    const s = servers[0];
    const mine = lease.server || '';
    const rogue = mine && s.serverId && s.serverId !== mine;
    findings.push({
      level: rogue ? 'high' : 'info', category: 'DHCP', target: s.serverId,
      title: rogue ? `DHCP 应答来源与本机租约不一致（可能是私接服务器）` : `DHCP 服务器正常：${s.serverId}`,
      detail: rogue
        ? `探测到 ${s.serverId} 在应答，但本机租约上记录的是 ${mine}。同一广播域里出现两台服务器（或中继指向了另一台），需要确认哪台是合规的。`
        : `仅探测到 ${s.serverId} 一个 DHCP 服务器（来源：${s.source}）${lease.server ? `，与本机租约记录一致` : ''}。`
          + (offers[0] ? `下发的网关 ${(offers[0].routers || [])[0] || '-'}、DNS ${(offers[0].dns || []).join('/') || '-'}、租期 ${Math.round((offers[0].leaseSec || 0) / 3600)} 小时。` : ''),
      advice: rogue
        ? '① 确认哪台是正规 DHCP；② 排查非法那台的接入端口；③ 用户口开 DHCP Snooping。'
        : 'DHCP 环境正常。建议定期跑一次，一旦出现第二台服务器就能立刻发现。',
      evidence: summary
    });

    // 与租约的对照检查（网关/DNS 是否被人改过）
    if (offers[0] && lease.gw && (offers[0].routers || []).length && !offers[0].routers.includes(lease.gw)) {
      findings.push({
        level: 'medium', category: 'DHCP', target: s.serverId,
        title: 'DHCP 下发的网关与本机当前网关不一致',
        detail: `服务器下发网关 ${offers[0].routers.join('/')}，本机当前使用 ${lease.gw}。若本机是静态地址可忽略；否则说明配置被改过。`,
        advice: '核对 DHCP 作用域的 option 3，并确认本机地址是静态还是动态。',
        evidence: { offered: offers[0], lease }
      });
    }
  } else {
    const why = [
      active.error || '',
      passive && passive.error ? `被动嗅探失败：${passive.error}` : '',
      lease.enabled === false ? '本机使用静态地址，主动探测意义有限' : '',
      !netutil.findTshark() ? '未安装 tshark，无法被动嗅探' : '',
      passive && passive.frames === 0 ? '抓包窗口内没有任何 DHCP 交互' : ''
    ].filter(Boolean);
    findings.push({
      level: 'info', category: 'DHCP', target: '本机',
      title: '未发现 DHCP 服务器应答',
      detail: `本机 DHCP：${lease.enabled === null ? '未知' : (lease.enabled ? '启用' : '未启用（静态地址）')}`
        + `${lease.server ? `，租约服务器 ${lease.server}` : ''}。原因可能：${why.join('；') || '本网段没有 DHCP 服务器，或服务器/中继在其它网段'}。`,
      advice: lease.enabled === false
        ? '本机是静态地址，主动探测可能收不到应答；建议开启 Syslog 接收，通过监听客户端申请过程来判断。'
        : '① 在客户端刚开机 / 续租的时候重跑一次（DHCP 交互是突发流量，抓包窗口没赶上也正常）；'
          + '② 确认本机与 DHCP 服务器在同一广播域，跨网段需要 DHCP 中继；③ 若使用私有 DHCP 服务（如 Docker/libvirt），会被本机网卡内绑定，不影响物理网段。',
      evidence: summary
    });
  }

  return { findings, hosts: [], summary };
}

/* ======================================================================== *
 *                              工具注册表
 * ======================================================================== */
const TOOLS = [
  {
    key: 'camera', name: '摄像头扫描', icon: 'camera', needsTargets: true,
    desc: '发现网内 IPC / NVR / DVR，识别厂商型号，并检测未鉴权拉流与管理面暴露',
    risk: '关键：RTSP 未鉴权可直接看画面',
    options: [
      { key: 'timeoutMs', label: '单端口超时(ms)', type: 'number', def: 1500 },
      { key: 'concurrency', label: '并发数', type: 'number', def: 192 }
    ]
  },
  {
    key: 'ipconflict', name: 'IP 冲突检测', icon: 'alert', needsTargets: true,
    desc: '多轮 ARP 采样 + 旁路 ARP 嗅探，找出同一 IP 被多个 MAC 抢占的冲突地址',
    risk: '关键：时通时断、连接随机失败',
    options: [
      { key: 'rounds', label: '采样轮次', type: 'number', def: 3 },
      { key: 'seconds', label: '被动嗅探(秒)', type: 'number', def: 6 }
    ]
  },
  {
    key: 'loop', name: '环路检测', icon: 'refresh', needsTargets: false,
    desc: '旁路抓包找「同 IP-ID 不同 TTL」的重复帧与广播风暴，定位二层环路',
    risk: '关键：整段网络瘫痪、丢包严重',
    options: [
      { key: 'seconds', label: '抓包时长(秒)', type: 'number', def: 8 },
      { key: 'iface', label: '网卡编号(如 1)', type: 'text', def: '' }
    ]
  },
  {
    key: 'logaudit', name: '日志审计', icon: 'clipboard', needsTargets: false,
    desc: 'Syslog 接收入库 + 12 条审计规则聚合，并读取本机安全/系统事件日志',
    risk: '关键：登录爆破、配置变更、日志被清除',
    options: [
      { key: 'source', label: '来源', type: 'select', def: 'auto', choices: [{ v: 'auto', t: '自动（本机+已收 Syslog）' }, { v: 'local', t: '仅本机事件日志' }, { v: 'syslog', t: '仅已收 Syslog' }] },
      { key: 'limit', label: '读取条数', type: 'number', def: 500 }
    ]
  },
  {
    key: 'speedtest', name: '外网测速', icon: 'globe', needsTargets: false,
    desc: '多线程下行 / 定长上行 + 延迟抖动丢包，并与网关基线对比定位瓶颈',
    risk: '关键：出口带宽不足、丢包抖动',
    options: [
      { key: 'seconds', label: '测试时长(秒)', type: 'number', def: 8 },
      { key: 'parallel', label: '并发流数', type: 'number', def: 4 }
    ]
  },
  {
    key: 'dhcp', name: 'DHCP 检测', icon: 'wifi', needsTargets: false,
    desc: '主动 OFFER 探测 + 被动嗅探 + 本机租约核对，发现 Rogue DHCP 与下发参数异常',
    risk: '关键：私接 DHCP 抢答导致断网',
    options: [
      { key: 'seconds', label: '探测/嗅探(秒)', type: 'number', def: 6 },
      { key: 'iface', label: '网卡编号(如 1)', type: 'text', def: '' }
    ]
  }
];

function toolMeta(key) { return TOOLS.find(t => t.key === key) || null; }

/* ======================================================================== *
 *                              统一执行入口
 * ======================================================================== */
const DETECTORS = { camera: detectCamera, ipconflict: detectIpConflict, loop: detectLoop, logaudit: detectLogAudit, speedtest: detectSpeed, dhcp: detectDhcp };

/**
 * 跑一次诊断：解析目标 → 执行检测器 → 入库 → 联动告警
 * @param {string} tool   检测器 key
 * @param {object} opts   { mode, targets, iface, ... 各检测器自己的参数 }
 * @param {string} user   触发人
 */
async function run(tool, opts = {}, user = 'system') {
  const meta = toolMeta(tool);
  if (!meta) throw new Error(`未知的诊断工具：${tool}`);
  if (running.has(tool) && opts.allowConcurrent !== true) {
    const e = new Error(`「${meta.name}」正在执行中，请等这一轮结束`);
    e.code = 'BUSY';
    throw e;
  }
  running.set(tool, Date.now());

  const t0 = Date.now();
  const runId = store.uid('ndr_');
  const startedAt = new Date(t0).toISOString();
  const mode = String(opts.mode || 'local') === 'range' ? 'range' : 'local';

  try {
    const cfg = (db.settingsSync() || {}).netdiag || {};
    const maxHosts = Math.max(16, Math.min(MAX_HOSTS, Number(opts.maxHosts || cfg.maxHosts || MAX_HOSTS)));
    let scope = { targets: [], nets: [], ifaces: [], note: '' };
    if (meta.needsTargets) scope = await resolveScope(mode, opts.targets, maxHosts);

    await db.netdiagRunSave({
      id: runId, taskId: opts.taskId || '', tool, mode,
      targets: meta.needsTargets ? (mode === 'local' ? `本机网段 ${scope.nets.map(n => n.cidr).join(' / ')}` : String(opts.targets || '')) : (opts.iface ? `网卡 ${opts.iface}` : '本机'),
      status: 'running', startedAt, targetsTotal: scope.targets.length, targetsDone: 0,
      data: { options: redactOpts(opts), scope: { nets: scope.nets, count: scope.targets.length, note: scope.note } }
    });

    const ctx = { ...opts, mode, targets: scope.targets, nets: scope.nets, ifaces: scope.ifaces, runId, user };
    const out = await DETECTORS[tool](ctx);

    const findings = (out.findings || []).map(f => ({
      id: store.uid('ndf_'), runId, tool,
      level: f.level || 'info', category: f.category || meta.name,
      target: String(f.target || ''), title: String(f.title || ''), detail: String(f.detail || ''),
      advice: String(f.advice || ''), evidence: f.evidence || {},
      createdAt: new Date().toISOString()
    }));
    const hosts = (out.hosts || []).map(h => ({
      id: store.uid('ndh_'), runId, tool,
      ip: h.ip, mac: h.mac || '', vendor: h.vendor || '', model: h.model || '',
      kind: h.kind || '', riskLevel: h.riskLevel || 'info', riskDesc: h.riskDesc || '',
      data: h.data || { openPorts: h.openPorts, httpTitle: h.httpTitle, rtspServer: h.rtspServer, rtspNoAuth: h.rtspNoAuth, onvif: h.onvif, firmware: h.firmware },
      createdAt: new Date().toISOString()
    }));

    if (findings.length) await db.netdiagFindingInsert(findings);
    if (hosts.length) await db.netdiagHostInsert(hosts);
    if (out.logs && out.logs.length) { /* 日志审计内部已自行入库，避免重复 */ }

    const level = worstLevel(findings.map(f => f.level));
    const score = scoreOf(findings);
    const endedAt = new Date().toISOString();

    await db.netdiagRunSave({
      id: runId, tool, mode, status: 'done',
      targets: meta.needsTargets ? (mode === 'local' ? `本机网段 ${scope.nets.map(n => n.cidr).join(' / ')}` : String(opts.targets || '')) : (opts.iface ? `网卡 ${opts.iface}` : '本机'),
      score, level, findingsCount: findings.length,
      targetsTotal: scope.targets.length, targetsDone: scope.targets.length,
      startedAt, endedAt, durationMs: Date.now() - t0,
      data: { options: redactOpts(opts), scope: { nets: scope.nets, count: scope.targets.length, note: scope.note }, summary: out.summary || {} }
    });

    const alarms = await raiseAlarms(findings, meta, runId, user);

    store.audit({
      user, action: `diag.${tool}`, target: findings[0] ? String(findings[0].target || '') : '',
      detail: `${meta.name} · ${scope.targets.length || '-'} 目标 · ${findings.length} 条问题 · 等级 ${level} · ${Date.now() - t0}ms`
    });

    return {
      ok: true, runId, tool, mode, ms: Date.now() - t0,
      targets: scope.targets.length, nets: scope.nets, note: scope.note,
      score, level, levelText: LEVEL_TEXT[level], findings, hosts,
      summary: out.summary || {}, alarms
    };
  } catch (e) {
    await db.netdiagRunSave({
      id: runId, tool, mode, status: 'error', startedAt,
      endedAt: new Date().toISOString(), durationMs: Date.now() - t0,
      data: { error: e.message, options: redactOpts(opts) }
    }).catch(() => { });
    throw e;
  } finally {
    running.delete(tool);
  }
}

/** 落库前把可能很长的选项裁一裁（网卡列表之类不进库） */
function redactOpts(o) {
  const r = {};
  for (const k of ['mode', 'targets', 'iface', 'seconds', 'rounds', 'parallel', 'source', 'limit', 'timeoutMs', 'concurrency', 'pingHost']) {
    if (o[k] !== undefined) r[k] = o[k];
  }
  return r;
}

/** 高危/极高危问题 → 告警中心（同一目标同一问题只报一条，上限 20 条防刷屏） */
async function raiseAlarms(findings, meta, runId, user) {
  const sevMap = { critical: 'disaster', high: 'high' };
  let created = 0;
  const seen = new Set();
  for (const f of findings) {
    const sev = sevMap[f.level];
    if (!sev) continue;
    const key = `${f.title}|${f.target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (created >= 20) break;
    try {
      await db.alarmsCreate({
        source: 'netdiag', severity: sev, host: f.target || '本机',
        title: `[${meta.name}] ${f.title}`,
        message: `${f.detail}\n\n处置建议：${f.advice}`,
        status: 'open', clock: store.nowSec(), runId,
        tool: meta.key, category: f.category,
        createdAt: new Date().toISOString()
      });
      created++;
    } catch { /* 告警写入失败不影响诊断主流程 */ }
  }
  return { created };
}

/* ======================================================================== *
 *                          Syslog 接收（日志审计用）
 * ======================================================================== */
let syslogSock = null;
let syslogState = { running: false, port: 514, proto: 'udp', received: 0, dropped: 0, lastAt: null, error: '', boundAt: null };
let logBuffer = [];
let flushTimer = null;

function syslogConfig() {
  const cfg = (db.settingsSync() || {}).netdiag || {};
  return { ...{ enabled: false, port: 514, proto: 'udp', retainDays: 30 }, ...(cfg.syslog || {}) };
}

function onSyslogMessage(buf, rinfo) {
  syslogState.received++;
  syslogState.lastAt = new Date().toISOString();
  const text = buf.toString('utf8');
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const p = parseSyslog(line, rinfo && rinfo.address);
    const c = classifyLog({ ...p, msg: p.msg });
    logBuffer.push({
      id: store.uid('ndl_'), runId: '', source: 'syslog',
      host: p.host, srcIp: rinfo ? rinfo.address : '',
      facility: p.facility, severity: p.severity, tag: p.tag,
      message: p.msg, rule: c.rule, level: c.level,
      logAt: new Date().toISOString(), createdAt: new Date().toISOString()
    });
    if (logBuffer.length > 5000) { logBuffer.shift(); syslogState.dropped++; }
  }
  if (!flushTimer) flushTimer = setTimeout(flushLogs, 1000);
}

async function flushLogs() {
  flushTimer = null;
  const batch = logBuffer;
  logBuffer = [];
  if (!batch.length) return;
  try { await db.netdiagLogInsert(batch); } catch (e) { console.error('[netdiag] syslog 入库失败：', e.message); }
}

/** 起 Syslog 接收（端口被占/UDP 514 需管理员时给出明确提示） */
function startSyslog({ port, proto } = {}) {
  stopSyslog();
  const cfg = syslogConfig();
  const p = Number(port || cfg.port || 514);
  const kind = String(proto || cfg.proto || 'udp');
  syslogState = { running: false, port: p, proto: kind, received: syslogState.received, dropped: syslogState.dropped, lastAt: null, error: '', boundAt: null };
  if (kind === 'tcp') {
    // TCP syslog：设备侧少见，这里只做占位说明，避免误以为已监听
    syslogState.error = 'TCP Syslog 暂未实现，请用 UDP（设备侧绝大多数用 UDP 514）';
    return syslogState;
  }
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  syslogSock = sock;
  sock.on('message', onSyslogMessage);
  sock.on('error', (e) => {
    syslogState.error = /EADDRINUSE/.test(e.code || '') || /EACCES/.test(e.code || '')
      ? `端口 ${p} 被占用或无权限（UDP 514 与 syslog 服务冲突；非管理员无法绑定 1024 以下端口）。请在系统设置里改用 5140 等高位端口，并让设备指向该端口`
      : (e.code || e.message);
    try { sock.close(); } catch { }
    syslogSock = null;
    syslogState.running = false;
  });
  try {
    sock.bind(p, () => {
      syslogState.running = true;
      syslogState.boundAt = new Date().toISOString();
      console.log(`  日志审计  Syslog 接收已启动 · UDP ${p}`);
    });
  } catch (e) {
    syslogState.error = e.message;
  }
  return syslogState;
}

function stopSyslog() {
  if (syslogSock) { try { syslogSock.close(); } catch { } syslogSock = null; }
  syslogState.running = false;
}

function syslogStatus() {
  const cfg = syslogConfig();
  return {
    ...syslogState,
    config: cfg,
    buffer: logBuffer.length,
    // 给一句直接的落地指引，前端原样展示
    hint: cfg.enabled
      ? `设备侧配置示例：Cisco「logging host <本机IP>」，华为/H3C「info-center loghost <本机IP>」，通用「*.* @<本机IP>:${cfg.port}」`
      : '未启用。启用后网络设备可以把日志发到本控制台，日志审计才覆盖得到设备侧事件'
  };
}

/* ======================================================================== *
 *                              调度与生命周期
 * ======================================================================== */
async function tick() {
  try {
    const tasks = await db.netdiagTaskList();
    for (const t of tasks) {
      if (!t.enabled || running.has(t.id) || running.has(t.tool)) continue;
      const gap = Number(t.intervalSec || 3600);
      const last = t.lastStartedAt ? new Date(t.lastStartedAt).getTime() : 0;
      if (Date.now() - last < gap * 1000) continue;
      running.set(t.id, Date.now());
      runTask(t).catch(e => {
        console.error(`[netdiag] 任务 ${t.name} 执行失败：`, e.message);
        db.netdiagTaskSave({ id: t.id, status: 'error' }).catch(() => { });
      }).finally(() => running.delete(t.id));
    }
  } catch (e) { console.error('[netdiag] 调度异常：', e.message); }
}

async function runTask(t) {
  const startedAt = new Date().toISOString();
  const opts = { ...(t.options || {}), mode: t.mode || 'local', targets: t.targets || '', taskId: t.id };
  const r = await run(t.tool, opts, 'scheduler');
  await db.netdiagTaskSave({
    id: t.id, lastStartedAt: startedAt, lastEndedAt: new Date().toISOString(),
    runs: Number(t.runs || 0) + 1, status: 'idle'
  }).catch(() => { });
  return r;
}

/** 保留策略 + Syslog 日志滚动清理 */
async function sweep() {
  try {
    const tasks = await db.netdiagTaskList();
    const now = Date.now();
    for (const t of tasks) {
      const hrs = Number(t.retainHours || 168);
      if (!hrs) continue;
      if (now - new Date(t.lastEndedAt || 0).getTime() < hrs * 3600 * 1000) continue;
      const cut = new Date(now - hrs * 3600 * 1000).toISOString();
      const r = await db.netdiagRemoveOld(cut, t.id);
      if (r.runs) console.log(`[netdiag] 保留策略清理：${r.runs} 条记录 / ${r.hosts} 条主机 / ${r.findings} 条问题`);
    }
    const cfg = syslogConfig();
    const days = Number(cfg.retainDays || 30);
    if (days > 0) {
      const cut = new Date(Date.now() - days * 86400e3).toISOString();
      const n = await db.netdiagLogRemoveOld(cut).catch(() => 0);
      if (n) console.log(`[netdiag] 日志清理：删除 ${n} 条超过 ${days} 天的日志`);
    }
  } catch { /* 清理失败不影响主流程 */ }
}

function info() {
  const s = syslogStatus();
  return [
    `网络诊断  已就绪 · 摄像头/IP冲突/环路/日志审计/外网测速/DHCP 六个检测器`,
    `日志审计  Syslog 接收 ${s.running ? `运行中（UDP ${s.port}，已收 ${s.received} 条）` : (s.error ? `未运行（${s.error.slice(0, 60)}）` : '未启用')}`
  ];
}

async function start() {
  if (timer) return;
  timer = setInterval(tick, SCHED_LEAD);
  setInterval(sweep, 30 * 60 * 1000);
  const cfg = syslogConfig();
  if (cfg.enabled) startSyslog();
  const tasks = await db.netdiagTaskList().catch(() => []);
  console.log(`  网络诊断  已启动 · 任务 ${tasks.length} 个（启用 ${tasks.filter(t => t.enabled).length} 个）`);
  tick();
}

module.exports = {
  start, info, run, tick, sweep, runTask,
  TOOLS, toolMeta,
  // 单独导出原语，供各诊断链路自检脚本在不碰数据库的前提下做引擎级验证
  resolveScope, localNets, enumerateCidr, defaultGateway, arpTable, readPcapFrames, decodeEth, decodeArp,
  decodeIpv4, decodeUdp, parseDhcp, buildDiscover, parseSyslog, classifyLog, auditAggregate,
  readLocalEventLog, localLease, downloadTest, uploadTest,
  scoreOf, worstLevel, LEVEL_ORDER, LEVEL_TEXT, LOG_RULES, CAM_SIGS, TOOLS_KEYS: TOOLS.map(t => t.key),
  startSyslog, stopSyslog, syslogStatus, MAX_HOSTS, running
};
