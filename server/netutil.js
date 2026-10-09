'use strict';
/**
 * 网络底层能力
 *  - ping            真实 ICMP 探测（Windows/Linux 双平台，编码无关解析，中英文系统都能跑）
 *  - tcpConnect      TCP 端口连通与时延
 *  - ThroughputServer 内置 TCP 吞吐测速服务（不依赖 iperf3，可选优先用 iperf3）
 *  - sshExec / sshShell  SSH 执行与交互式 shell（供终端与命令下发复用）
 *  - 地址表解析      Cisco / 华为 / H3C / Fortinet / Palo Alto 的 MAC、ARP、会话表
 *  - 抓包适配器       优先本机 tshark/dumpcap，缺失时降级为设备侧抓包命令下发
 */
const { spawn, execFile } = require('child_process');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const store = require('./store');
const db = require('./db');

/* ============================== ICMP ============================== */
const IS_WIN = process.platform === 'win32';

function pingOnce(host, timeoutMs = 1500) {
  return new Promise(resolve => {
    const args = IS_WIN
      ? ['-n', '1', '-w', String(timeoutMs), host]
      : ['-c', '1', '-W', String(Math.max(1, Math.ceil(timeoutMs / 1000))), host];
    const t0 = Date.now();
    const p = spawn('ping', args, { windowsHide: true });
    const chunks = [];
    let done = false;
    const finish = (rtt) => { if (done) return; done = true; try { p.kill(); } catch { } resolve(rtt); };
    p.stdout.on('data', d => chunks.push(d));
    p.stderr.on('data', d => chunks.push(d));
    p.on('close', () => {
      // 只取 ASCII 数字：`=1ms` / `<1ms` 对中英文系统都成立
      const buf = Buffer.concat(chunks).toString('latin1');
      const m = buf.match(/[=<]\s*(\d+(?:\.\d+)?)\s*ms/i);
      finish(m ? parseFloat(m[1]) : (buf.match(/[=<]\s*(\d+)\s*ms/i) ? parseFloat(m[1]) : null));
    });
    p.on('error', () => finish(null));
    setTimeout(() => finish(null), timeoutMs + 800);
  });
}

/** 连续探测：count 次，intervalMs 间隔 */
async function ping(host, { count = 4, intervalMs = 400, timeoutMs = 1500, onSample } = {}) {
  const rtts = [], lost = [];
  const t0 = Date.now();
  for (let i = 0; i < count; i++) {
    const rtt = await pingOnce(host, timeoutMs);
    if (rtt === null) lost.push(i); else rtts.push(rtt);
    if (onSample) onSample({ seq: i + 1, rtt, lost: rtt === null, ts: Date.now() });
    if (i < count - 1) await new Promise(r => setTimeout(r, intervalMs));
  }
  const ok = rtts.length;
  const avg = ok ? rtts.reduce((a, b) => a + b, 0) / ok : 0;
  const jitter = ok > 1 ? Math.sqrt(rtts.reduce((a, b) => a + (b - avg) ** 2, 0) / ok) : 0;
  return {
    host, sent: count, recv: ok, loss: +(100 * (count - ok) / count).toFixed(1),
    min: ok ? Math.min(...rtts) : null, max: ok ? Math.max(...rtts) : null,
    avg: ok ? +avg.toFixed(2) : null, jitter: +jitter.toFixed(2),
    last: ok ? rtts[rtts.length - 1] : null,
    mdev: jitter, elapsedMs: Date.now() - t0, rtts, lostSeqs: lost
  };
}

/* ============================== TCP ============================== */
function tcpConnect(host, port, timeoutMs = 1500) {
  return new Promise(resolve => {
    const t0 = Date.now();
    const s = new net.Socket();
    let done = false;
    const fin = (ok, err) => {
      if (done) return; done = true;
      try { s.destroy(); } catch { }
      resolve({ host, port, ok, ms: ok ? Date.now() - t0 : null, error: err || '' });
    };
    s.setTimeout(timeoutMs);
    s.once('connect', () => fin(true));
    s.once('timeout', () => fin(false, 'timeout'));
    s.once('error', e => fin(false, e.code || e.message));
    s.connect(port, host);
  });
}

/* ============ 内置 TCP 吞吐测速（无需 iperf3 也能测链路带宽） ============ */
const CHUNK = Buffer.alloc(128 * 1024, 0x5a);

function createThroughputServer(port, onLog = () => { }) {
  const server = net.createServer(sock => {
    sock.setNoDelay(true);
    let mode = null;
    let received = 0;
    let startedAt = 0;
    sock.once('data', d => {
      const head = d.toString('utf8', 0, Math.min(d.length, 64)).trim();
      if (head.startsWith('UP')) {          // 客户端上传：服务端收
        mode = 'upload';
        received += d.length;
        startedAt = Date.now();
      } else {                               // 客户端下载：服务端发
        mode = 'download';
        startedAt = Date.now();
        const total = parseInt((head.match(/DOWN\s+(\d+)/) || [])[1] || '104857600', 10);
        let sent = 0;
        const pump = () => {
          while (sent < total) {
            const n = Math.min(CHUNK.length, total - sent);
            if (!sock.write(n === CHUNK.length ? CHUNK : CHUNK.subarray(0, n))) {
              sent += n;
              sock.once('drain', pump);
              return;
            }
            sent += n;
          }
          sock.end();
        };
        pump();
      }
    });
    sock.on('data', d => { if (mode === 'upload') received += d.length; });
    const report = () => {
      if (!startedAt) return;
      const sec = (Date.now() - startedAt) / 1000;
      const bytes = mode === 'upload' ? received : null;
      if (bytes !== null) onLog({ mode, bytes, sec, bps: bytes * 8 / sec });
    };
    sock.on('close', report);
    sock.on('error', () => { });
  });
  server.listen(port, '0.0.0.0');
  return server;
}

/** 客户端：从对端测速服务下载数据，返回带宽 */
function throughputClient(host, port, { seconds = 8, parallel = 1, mode = 'download', sizeBytes = 200 * 1024 * 1024 } = {}) {
  return new Promise(resolve => {
    let total = 0, running = 0, errors = 0;
    const t0 = Date.now();
    const done = () => {
      const sec = (Date.now() - t0) / 1000;
      resolve({
        host, port, mode, seconds: +sec.toFixed(2), bytes: total,
        bps: total * 8 / sec, parallel, errors
      });
    };
    for (let i = 0; i < parallel; i++) {
      running++;
      const s = new net.Socket();
      s.setNoDelay(true);
      s.connect(port, host, () => {
        if (mode === 'download') s.write(`DOWN ${sizeBytes}\n`);
        else {
          s.write('UP\n');
          let sent = 0;
          const pump = () => {
            while (Date.now() - t0 < seconds * 1000 && s.writable) {
              const n = Math.min(CHUNK.length, 1e9);
              if (!s.write(n === CHUNK.length ? CHUNK : CHUNK.subarray(0, n))) { sent += n; s.once('drain', pump); return; }
              sent += n;
            }
            s.end();
          };
          pump();
        }
      });
      s.on('data', d => {
        total += d.length;
        if (mode === 'download' && Date.now() - t0 >= seconds * 1000) s.end();
      });
      const close = () => { running--; if (running === 0) done(); };
      s.once('close', close);
      s.once('error', () => { errors++; });
      s.setTimeout(seconds * 1000 + 5000, () => s.destroy());
    }
    setTimeout(() => { if (running > 0) { /* 到点收口 */ } }, seconds * 1000 + 3000);
  });
}

/** 是否存在 iperf3 */
function findIperf() {
  const cfgPath = (db.settingsSync() || {}).speed?.iperfPath;
  if (cfgPath && fs.existsSync(cfgPath)) return cfgPath;
  const cands = IS_WIN
    ? ['iperf3.exe', 'C:\\Program Files\\iperf3\\iperf3.exe', 'C:\\iperf3\\iperf3.exe']
    : ['/usr/bin/iperf3', '/usr/local/bin/iperf3', 'iperf3'];
  for (const c of cands) { try { if (c.includes(path.sep) ? fs.existsSync(c) : true) return c; } catch { } }
  return null;
}
function runIperf3(exe, args, timeoutMs = 60000) {
  return new Promise(resolve => {
    const p = spawn(exe, args, { windowsHide: true });
    let out = '', err = '';
    p.stdout.on('data', d => out += d.toString());
    p.stderr.on('data', d => err += d.toString());
    const t = setTimeout(() => { try { p.kill(); } catch { } }, timeoutMs);
    p.on('close', code => {
      clearTimeout(t);
      const sum = (out.match(/\[SUM\][^\n]*?([\d.]+)\s+(?:M|G|K)bits\/sec/g) || []).pop() || '';
      const m = sum.match(/([\d.]+)\s+([MGK])bits\/sec/);
      const mult = m ? ({ M: 1e6, G: 1e9, K: 1e3 }[m[2]] || 1) : 0;
      resolve({ code, out, err, bps: m ? parseFloat(m[1]) * mult : null });
    });
    p.on('error', e => { clearTimeout(t); resolve({ code: -1, out, err: e.message, bps: null }); });
  });
}

/* ============================== SSH ============================== */
function sshConnect(cred) {
  const { Client } = require('ssh2');
  return new Promise((resolve, reject) => {
    const c = new Client();
    const opts = {
      host: cred.host, port: cred.port || 22, username: cred.username,
      readyTimeout: cred.timeoutMs || 15000, keepaliveInterval: 10000,
      algorithms: {
        // 兼容老交换机（Cisco IOS 15 / 老 H3C 只支持这些）
        kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1'],
        cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com'],
        serverHostKey: ['ssh-rsa', 'ssh-dss', 'rsa-sha2-256', 'rsa-sha2-512', 'ecdsa-sha2-nistp256', 'ssh-ed25519'],
        hmac: ['hmac-sha2-256', 'hmac-sha1', 'hmac-md5', 'hmac-sha1-96']
      }
    };
    if (cred.kind === 'ssh-key' && cred.secret) opts.privateKey = cred.secret;
    else opts.password = cred.secret;
    if (cred.enable) { opts.tryKeyboard = true; }
    c.on('keyboard-interactive', (n, i, l, prompts, finish) => finish([cred.enable || cred.secret]));
    c.on('ready', () => resolve(c));
    c.on('error', e => reject(e));
    c.connect(opts);
  });
}

/** 顺序执行一批命令，返回拼接回显 */
function sshExec(cred, commands, { timeoutMs = 60000, perCmdDelay = 500 } = {}) {
  return new Promise(async (resolve, reject) => {
    let conn;
    try { conn = await sshConnect(cred); } catch (e) { return reject(e); }
    let out = '';
    const t = setTimeout(() => { try { conn.end(); } catch { } resolve({ out, timeout: true }); }, timeoutMs);
    conn.shell({ term: 'vt100', cols: 200, rows: 60 }, (err, stream) => {
      if (err) { clearTimeout(t); conn.end(); return reject(err); }
      stream.on('data', d => out += d.toString('utf8'));
      stream.stderr.on('data', d => out += d.toString('utf8'));
      stream.on('close', () => { clearTimeout(t); conn.end(); resolve({ out, timeout: false }); });
      (async () => {
        for (const cmd of commands) {
          stream.write(String(cmd).replace(/\r?\n$/, '') + '\n');
          await new Promise(r => setTimeout(r, perCmdDelay));
        }
        setTimeout(() => { try { stream.end(); } catch { } }, perCmdDelay * 3);
      })();
    });
    conn.on('error', e => { clearTimeout(t); reject(e); });
  });
}

/* ========================= 设备地址表解析 ========================= */
function detectVendor(text, hint) {
  if (hint) return hint;
  const t = (text || '').slice(0, 4000);
  if (/Cisco|IOS|NX-OS/i.test(t)) return 'cisco';
  if (/Huawei|VRP/i.test(t)) return 'huawei';
  if (/H3C|Comware/i.test(t)) return 'h3c';
  if (/FortiGate|FortiOS/i.test(t)) return 'fortinet';
  if (/Palo Alto|PAN-OS/i.test(t)) return 'paloalto';
  return 'unknown';
}

/** show mac address-table / display mac-address */
function parseMacTable(text) {
  const rows = [];
  const lines = String(text).split(/\r?\n/);
  for (const line of lines) {
    // Cisco: 10    0011.2233.4455   DYNAMIC  Gi1/0/12
    let m = line.match(/^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)/i);
    if (m) { rows.push({ vlan: m[1], mac: m[2], type: m[3], port: m[4] }); continue; }
    // Huawei/H3C: 0011-2233-4455  10/-  GE0/0/12  Learned
    m = line.match(/^\s*([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+(\S+)\s+(\S+)\s+(\S+)/i);
    if (m) { rows.push({ mac: m[1], vlan: m[2], port: m[3], type: m[4] }); continue; }
    // 无分隔冒号
    m = line.match(/^\s*([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+(\S+)\s+(\S+)/i);
    if (m) rows.push({ mac: m[1], vlan: m[2], port: m[3], type: 'dynamic' });
  }
  return rows;
}

/** show arp / display arp / show ip arp */
function parseArp(text) {
  const rows = [];
  for (const line of String(text).split(/\r?\n/)) {
    let m = line.match(/(\d+\.\d+\.\d+\.\d+)\s+(?:(\d+|-)\s+)?([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)/i); // Cisco（Age 在 MAC 之前，可为空）
    if (m) { rows.push({ ip: m[1], mac: m[3], age: m[2] || '-', iface: m[5] }); continue; }
    m = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+(?:-|\d+)\s+(\S+)/i); // Huawei/H3C
    if (m) { rows.push({ ip: m[1], mac: m[2], age: '-', iface: m[3] }); continue; }
    m = line.match(/^(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i);  // Palo Alto: name ip mac
    if (m) { rows.push({ ip: m[2], mac: m[3], age: '-', iface: m[1] }); continue; }
    m = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+(\S+)/i); // Fortinet diagnose ip arp list
    if (m) { rows.push({ ip: m[1], mac: m[2], age: '-', iface: m[3] }); }
  }
  return rows;
}

/** 会话表：FortiGate diagnose sys session list / PA show session all / Cisco show conn */
function parseSessions(text) {
  const rows = [];
  const blocks = String(text).split(/\r?\n\r?\n/);
  for (const b of blocks) {
    const proto = (b.match(/proto=(\d+|\w+)/) || [])[1];
    const src = (b.match(/src=(\d+\.\d+\.\d+\.\d+)/) || [])[1];
    const dst = (b.match(/dst=(\d+\.\d+\.\d+\.\d+)/) || [])[1];
    const sport = (b.match(/sport=(\d+)/) || [])[1];
    const dport = (b.match(/dport=(\d+)/) || [])[1];
    const bytes = (b.match(/bytes=(\d+)/) || [])[1];
    if (src && dst) rows.push({ src, dst, sport, dport, proto: proto || 'tcp', bytes: Number(bytes || 0), raw: b.slice(0, 200) });
    else {
      const m = b.match(/(\d+\.\d+\.\d+\.\d+)\((\d+)\)\s*->\s*(\d+\.\d+\.\d+\.\d+)\((\d+)\)/);
      if (m) rows.push({ src: m[1], sport: m[2], dst: m[3], dport: m[4], proto: 'tcp', bytes: 0, raw: b.slice(0, 200) });
    }
  }
  return rows;
}

/** 各厂商取表的命令集 */
const TABLE_CMDS = {
  cisco: { mac: ['terminal length 0', 'show mac address-table'], arp: ['terminal length 0', 'show ip arp'], session: ['terminal length 0', 'show conn'] },
  nxos: { mac: ['terminal length 0', 'show mac address-table'], arp: ['terminal length 0', 'show ip arp'], session: ['terminal length 0', 'show ip arp'] },
  huawei: { mac: ['screen-length 0 temporary', 'display mac-address'], arp: ['screen-length 0 temporary', 'display arp'], session: ['screen-length 0 temporary', 'display firewall session table'] },
  h3c: { mac: ['screen-length disable', 'display mac-address'], arp: ['screen-length disable', 'display arp'], session: ['screen-length disable', 'display session table'] },
  fortinet: { mac: ['diagnose ip arp list'], arp: ['diagnose ip arp list'], session: ['diagnose sys session list'] },
  paloalto: { mac: ['show mac all'], arp: ['show arp all'], session: ['show session all'] }
};

/* ============================== 抓包 ============================== */
function findTshark() {
  const cfg = (db.settingsSync() || {}).capture || {};
  if (cfg.tsharkPath && fs.existsSync(cfg.tsharkPath)) return cfg.tsharkPath;
  const cands = IS_WIN
    ? ['C:\\Program Files\\Wireshark\\tshark.exe', 'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
      'C:\\Program Files\\Wireshark\\dumpcap.exe']
    : ['/usr/bin/tshark', '/usr/local/bin/tshark', '/usr/bin/dumpcap'];
  for (const c of cands) { try { if (fs.existsSync(c)) return c; } catch { } }
  return null;
}

/** 本机抓包（需 Npcap / Wireshark），返回 pcap 文件与摘要 */
function localCapture({ iface, filter, seconds = 15, onProgress }) {
  const exe = findTshark();
  if (!exe) { const e = new Error('未检测到 tshark / dumpcap，请安装 Wireshark（含 Npcap）或在系统设置里指定路径'); e.code = 'NO_CAPTURE_ENGINE'; throw e; }
  const id = store.uid('cap_');
  const out = path.join(store.CAP_DIR, `${id}.pcap`);
  const isDumpcap = /dumpcap/i.test(exe);
  const args = isDumpcap
    ? ['-i', iface, '-w', out, '-a', `duration:${seconds}`]
    : ['-i', iface, '-w', out, '-a', `duration:${seconds}`];
  if (filter) args.push('-f', filter);
  const p = spawn(exe, args, { windowsHide: true });
  let log = '';
  p.stdout.on('data', d => { log += d.toString(); if (onProgress) onProgress(d.toString()); });
  p.stderr.on('data', d => { log += d.toString(); if (onProgress) onProgress(d.toString()); });
  return new Promise((resolve, reject) => {
    p.on('close', code => {
      const size = fs.existsSync(out) ? fs.statSync(out).size : 0;
      resolve({ id, engine: isDumpcap ? 'dumpcap' : 'tshark', iface, filter, seconds, file: `${id}.pcap`, size, code, log: log.slice(-4000) });
    });
    p.on('error', e => reject(e));
  });
}

/** 列出本机网卡（供抓包选择） */
function listInterfaces() {
  const exe = findTshark();
  if (!exe) return [];
  return new Promise(resolve => {
    execFile(exe, ['-D'], { windowsHide: true }, (err, stdout) => {
      if (err) return resolve([]);
      const rows = String(stdout).split(/\r?\n/).filter(Boolean).map(l => {
        const m = l.match(/^\s*(\d+)\.\s+(.+)$/);
        return m ? { id: m[1], name: m[2].trim() } : null;
      }).filter(Boolean);
      resolve(rows);
    });
  });
}

function localInterfaces() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4') {
        // netmask/cidr 供诊断类功能推导本机所在网段（如摄像头扫描、IP 冲突检测的默认范围）
        out.push({ name, address: a.address, mac: a.mac, internal: a.internal, netmask: a.netmask, cidr: a.cidr });
      }
    }
  }
  return out;
}

module.exports = {
  IS_WIN, ping, pingOnce, tcpConnect,
  createThroughputServer, throughputClient, findIperf, runIperf3,
  sshConnect, sshExec,
  detectVendor, parseMacTable, parseArp, parseSessions, TABLE_CMDS,
  findTshark, localCapture, listInterfaces, localInterfaces
};
