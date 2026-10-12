'use strict';
/**
 * 网络扫描引擎（在控制台本机执行，不依赖任何云端服务）
 *
 * 三段式：目标展开 → 存活发现 → 端口/服务扫描，最后做风险判定并入库。
 *
 * 发现方式：
 *   tcp     扫描常用端口的 TCP 握手，快、无需外部依赖，工控/哑终端网段首选
 *   icmp    真实 ICMP 探活，准但慢（每个地址都要 spawn 一次 ping）
 *   mixed   先用 tcp 快速摸一遍存活，再对存活的补一次 ping 拿响应时延
 *   auto    有 nmap 走 nmap -sn，否则退回 tcp
 *
 * 与 capture.js 同构：随服务启动的后台调度器，对 enabled 且到点的任务自动跑一轮，
 * 结果写入 scan_runs / scan_hosts / scan_ports 三张表，并联动资产台账与告警。
 */
const net = require('net');
const dns = require('dns');
const { spawn } = require('child_process');
const store = require('./store');
const db = require('./db');
const dpi = require('./dpi');
const netutil = require('./netutil');

const SCHED_LEAD = 5000;            // 调度巡检间隔
const DEFAULT_CONCURRENCY = 60;     // 并发连接数
const DEFAULT_TIMEOUT = 1200;       // 单连接超时(ms)
const MAX_HOSTS = 4096;             // 单次目标展开上限，防止误填 /8 把服务拖死
const DISCOVER_PORTS = [22, 80, 443, 445, 3389, 502, 5985, 8080];  // tcp 发现用的探测端口

const running = new Map();          // taskId -> Date.now()
let timer = null;

/* ============================ 目标与端口解析 ============================ */
function ipv4ToInt(ip) {
  const p = String(ip).trim().split('.').map(Number);
  if (p.length !== 4 || p.some(x => !Number.isInteger(x) || x < 0 || x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function intToIpv4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** CIDR → 起止整数。注意不能用位运算算数量，1 << 32 在 JS 里会溢出成 1 */
function parseCidr(s) {
  const m = String(s).trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
  if (!m) return null;
  const base = ipv4ToInt(m[1]), bits = Number(m[2]);
  if (base === null || bits > 32) return null;
  const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0);
  const start = (base & mask) >>> 0;
  const size = Math.pow(2, 32 - bits);
  return { start, end: start + size - 1 };
}

/** 解析主机名（扫描界面允许直接填机器名） */
function resolveHost(h) {
  return new Promise(res => {
    dns.lookup(h, (e, addr) => res(e ? null : addr));
  });
}

/**
 * 目标串展开成地址列表：支持 CIDR / 区间 / 单个 IP / 主机名 / 用逗号空格分号混合分隔
 * @example  '10.252.28.0/24, 10.0.0.1-50, 172.16.1.10'
 */
async function expandTargets(input, maxHosts = MAX_HOSTS) {
  const out = [];
  const seen = new Set();
  const push = (ip) => { if (ip && !seen.has(ip)) { seen.add(ip); out.push(ip); } };

  for (const raw of String(input || '').split(/[\s,;]+/)) {
    if (!raw) continue;

    const cidr = parseCidr(raw);
    if (cidr) {
      const count = cidr.end - cidr.start + 1;
      // 提前拦下超大赛道（比如误填 /8 = 1600 万），避免先空跑一轮再报错
      if (count > maxHosts) {
        throw new Error(`目标 ${raw} 展开为 ${count} 个地址，超过单次上限 ${maxHosts}。请缩小掩码或分批扫描`);
      }
      for (let i = cidr.start; i <= cidr.end; i++) push(intToIpv4(i));
      continue;
    }

    // 区间：10.0.0.1-20 或 10.0.0.1-10.0.0.50
    const m = raw.match(/^(\d+\.\d+\.\d+\.\d+)-(\d+(?:\.\d+){0,3})$/);
    if (m) {
      const a = ipv4ToInt(m[1]);
      const b = m[2].includes('.')
        ? ipv4ToInt(m[2])
        : ipv4ToInt(`${m[1].split('.').slice(0, 3).join('.')}.${m[2]}`);
      if (a !== null && b !== null && b >= a) {
        const end = Math.min(b, a + maxHosts - 1);
        for (let i = a; i <= end; i++) push(intToIpv4(i));
        continue;
      }
    }

    // 用 ipv4ToInt 而不是正则判IP：正则管不住 999.1.1.1 这种越界地址，得按四段都 ≤255 才算数
    if (ipv4ToInt(raw) !== null) { push(raw); continue; }
    const addr = await resolveHost(raw);      // 主机名
    if (addr) push(addr);
    else throw new Error(`无法解析目标 "${raw}"，不是合法 IP / CIDR / 区间 / 主机名`);
  }

  if (!out.length) throw new Error('未解析到任何目标地址，请检查目标网段格式');
  if (out.length > maxHosts) {
    throw new Error(`目标展开为 ${out.length} 个地址，超过单次上限 ${maxHosts}。请缩小网段或分批扫描`);
  }
  return out;
}

/** 端口串 → 端口数组：支持 80、80-443、22,80,443 混写 */
function parsePorts(input) {
  const set = new Set();
  for (const tok of String(input || '').split(/[\s,;]+/)) {
    if (!tok) continue;
    const m = tok.match(/^(\d+)-(\d+)$/);
    if (m) {
      const a = Number(m[1]), b = Number(m[2]);
      if (a > b) continue;
      for (let p = a; p <= Math.min(b, 65535); p++) set.add(p);
      continue;
    }
    const p = Number(tok);
    if (Number.isInteger(p) && p >= 1 && p <= 65535) set.add(p);
  }
  return [...set].sort((a, b) => a - b);
}

/* ============================== 服务识别 ============================== */
/** banner 特征表：比纯端口判定更可靠（同端口不同服务的情况很常见） */
const BANNER_RULES = [
  { re: /^SSH-(\d[\d.]*)-(\S+)/i, svc: 'ssh', pick: m => ({ product: m[2] }) },
  { re: /^(220|421).*(FTP|vsFTPd|ProFTPD|FileZilla)/i, svc: 'ftp', pick: m => ({ product: 'FTP' }) },
  { re: /^(\d{3}) .*(SMTP|ESMTP|Postfix|Sendmail)/i, svc: 'smtp', pick: m => ({ product: 'SMTP' }) },
  { re: /^\+OK.*POP3/i, svc: 'pop3', pick: () => ({ product: 'POP3' }) },
  { re: /\* OK .*(IMAP)/i, svc: 'imap', pick: () => ({ product: 'IMAP' }) },
  { re: /MySQL (frontend|Protocol)/i, svc: 'mysql', pick: () => ({ product: 'MySQL' }) },
  { re: /PostgreSQL/i, svc: 'postgresql', pick: () => ({ product: 'PostgreSQL' }) },
  { re: /Redis[\s_]*\d/i, svc: 'redis', pick: m => ({ product: m[0].slice(0, 40) }) },
  { re: /Mongod|MongoDB/i, svc: 'mongodb', pick: () => ({ product: 'MongoDB' }) },
  { re: /Elasticsearch/i, svc: 'elasticsearch', pick: () => ({ product: 'Elasticsearch' }) },
  { re: /HTTP\/1\.[01]/, svc: 'http', pick: m => ({ product: 'HTTP' }) },
  { re: /220 .*Microsoft Exchange/i, svc: 'exchange', pick: () => ({ product: 'Exchange' }) },
  { re: /Samba|NT\/1\.0|Windows 9x|Microsoft Windows/i, svc: 'microsoft-ds', pick: () => ({ product: 'Samba' }) },
  { re: /Modbus|SIEMENS|S7/i, svc: 's7comm', pick: () => ({ product: 'Siemens' }) },
  { re: /(Cisco|IOS|NX-OS) Software/i, svc: 'ssh', pick: () => ({ product: 'Cisco IOS' }) },
  { re: /Amazon Linux|nginx|apache/i, svc: 'http', pick: () => ({ product: 'Web Server' }) }
];

/** 从 banner 猜服务名与产品（拿不到 banner 就退回端口表） */
function identifyService(port, banner) {
  const head = String(banner || '').slice(0, 512);
  for (const r of BANNER_RULES) {
    const m = head.match(r.re);
    if (m) {
      const extra = r.pick ? r.pick(m) : {};
      return { service: r.svc, product: extra.product || '' };
    }
  }
  const hit = dpi.PORT_MAP[String(port)];
  if (hit) return { service: hit[0], product: hit[1] || '' };
  return { service: 'unknown', product: '' };
}

/** 抓一段 banner（拿不到就返回空串，不影响扫描继续） */
function grabBanner(host, port, timeoutMs = 1200) {
  return new Promise(resolve => {
    const s = new net.Socket();
    const chunks = [];
    let size = 0;
    let done = false;
    const fin = () => {
      if (done) return;
      done = true;
      try { s.destroy(); } catch { }
      resolve(Buffer.concat(chunks).toString('utf8').slice(0, 512));
    };
    s.setTimeout(timeoutMs);
    s.once('connect', () => { try { s.write('\r\n'); } catch { } });
    s.on('data', d => {
      size += d.length;
      chunks.push(d);
      // 攒够一屏就收，避免交互服务一直挂着拖慢整轮扫描
      if (size >= 256) setTimeout(fin, 80);
    });
    s.once('end', fin);
    s.once('close', fin);
    s.once('timeout', fin);
    s.once('error', fin);
    try { s.connect(port, host); } catch { fin(); }
  });
}

/* ============================== 风险规则库 ============================== */
/**
 * 端口级风险。level：critical / high / medium / low / info
 * 判定优先级：banner 命中 > 端口规则 > 未识别提示
 */
const RISK_RULES = [
  { ports: [23], service: 'telnet', level: 'high', tag: '明文远程管理', desc: 'Telnet 全程明文，账号口令可被抓包嗅探，应改用 SSH' },
  { ports: [21], service: 'ftp', level: 'high', tag: '明文 FTP', desc: 'FTP 明文传输凭据，且常被匿名访问' },
  { ports: [445], service: 'microsoft-ds', level: 'high', tag: 'SMB 暴露', desc: 'SMB 直面终端风险高（含 EternalBlue 类利用面），建议仅对内网管理段开放' },
  { ports: [3389], service: 'ms-rdp', level: 'high', tag: '远程桌面暴露', desc: 'RDP 暴露面大、爆破风险高，建议跳板机中转或限定源 IP' },
  { ports: [5900, 5901], service: 'vnc', level: 'high', tag: 'VNC 未加密', desc: 'VNC 默认不加密，口令与屏幕内容可被嗅探' },
  { ports: [502], service: 'modbus', level: 'critical', tag: '工控协议暴露', desc: 'Modbus TCP 直接暴露，可被写线圈造成断产事故，必须与 IT 网隔离' },
  { ports: [102], service: 's7comm', level: 'critical', tag: '西门子 S7 暴露', desc: 'S7comm 可被读取并写入 PLC 逻辑，属高危暴露面' },
  { ports: [44818], service: 'enip', level: 'critical', tag: 'EtherNet/IP 暴露', desc: 'EtherNet/IP 可被直接下发至 PLC，存在断控风险' },
  { ports: [1883, 1884], service: 'mqtt', level: 'medium', tag: 'MQTT 未鉴权', desc: 'MQTT 默认可匿名订阅，可能导致数据外泄或指令注入' },
  { ports: [6379], service: 'redis', level: 'critical', tag: 'Redis 未授权', desc: 'Redis 常见未授权访问，可写 crontab 拿到主机控制权' },
  { ports: [27017], service: 'mongodb', level: 'high', tag: 'MongoDB 未授权', desc: 'MongoDB 常见未授权访问，数据可直接被拖走' },
  { ports: [9200, 9300], service: 'elasticsearch', level: 'high', tag: 'ES 未授权', desc: 'Elasticsearch 未授权可读写全部索引' },
  { ports: [1433], service: 'mssql', level: 'high', tag: '数据库端口暴露', desc: 'MSSQL 直连暴露，爆破与注入面同时打开' },
  { ports: [3306], service: 'mysql', level: 'high', tag: '数据库端口暴露', desc: 'MySQL 直连暴露，应改为仅允许应用服务器访问' },
  { ports: [5432], service: 'postgresql', level: 'high', tag: '数据库端口暴露', desc: 'PostgreSQL 直连暴露，应改为仅允许应用服务器访问' },
  { ports: [1521], service: 'oracle', level: 'high', tag: '数据库端口暴露', desc: 'Oracle 直连暴露' },
  { ports: [135, 139], service: 'ms-rpc', level: 'medium', tag: 'Windows  RPC/NetBIOS', desc: '传统 Windows  RPC 端口，信息泄露面较大' },
  { ports: [5985, 5986], service: 'wsman', level: 'medium', tag: 'WinRM 开放', desc: 'WinRM 可被用于远程执行 PowerShell，建议限定管理网段' },
  { ports: [161], service: 'snmp', level: 'medium', tag: 'SNMP 可访问', desc: '若使用 v2c 且团体名弱（public），设备配置可被整份读走' },
  { ports: [80, 8080, 8000, 8888], service: 'http', level: 'low', tag: 'HTTP 明文', desc: '明文 HTTP 服务，登录页与会话 Cookie 存在被嗅探风险' },
  { ports: [443], service: 'https', level: 'info', tag: 'HTTPS', desc: '加密服务' },
  { ports: [22], service: 'ssh', level: 'info', tag: 'SSH', desc: '加密远程管理，建议禁用口令登录改用密钥' }
];

const LEVEL_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * 端口 → 风险规则
 * 服务名已识别且与规则不符时才跳过（同端口不同服务的情况）；
 * 服务名为 unknown（没抓到 banner、端口表也没有）时必须按端口规则兜底，
 * 否则 445/3389 这类高危端口会因为"没识别出服务"被判成无风险。
 */
function riskOf(port, service) {
  for (const r of RISK_RULES) {
    if (!r.ports.includes(port)) continue;
    const known = service && service !== 'unknown';
    if (r.service && known && r.service !== service) continue;
    return r;
  }
  return null;
}

/** 主机级风险：汇总其开放端口的最高等级 + 命中的风险标签 */
function hostRisk(openPorts) {
  let level = 'info';
  const tags = [];
  const descs = [];
  for (const p of openPorts) {
    const r = riskOf(p.port, p.service);
    if (!r) continue;
    if ((LEVEL_ORDER[r.level] || 0) > (LEVEL_ORDER[level] || 0)) level = r.level;
    if (!tags.includes(r.tag)) tags.push(r.tag);
    if (!descs.includes(r.desc)) descs.push(r.desc);
  }
  return { level, tags, descs };
}

/* ============================== 端口预设 ============================== */
const PORT_PRESETS = {
  common: { label: '常用端口', ports: [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200] },
  web: { label: 'Web 服务', ports: [80, 443, 8080, 8443, 8000, 8888, 7000, 9000] },
  database: { label: '数据库', ports: [1433, 1521, 3306, 5432, 6379, 27017, 9200, 9042, 2181] },
  windows: { label: 'Windows', ports: [135, 139, 445, 3389, 5985, 5986] },
  iot: { label: '工控 / IoT', ports: [502, 102, 1883, 1884, 8883, 44818, 47808, 2401, 4711] },
  management: { label: '网络管理', ports: [22, 23, 161, 179, 526, 623, 830, 1610, 10000] }
};

/** 常用端口预设（给前端下拉用） */
function presets() {
  return Object.entries(PORT_PRESETS).map(([k, v]) => ({ key: k, label: v.label, ports: v.ports }));
}

/* ============================== 扫描原语 ============================== */
function tcpProbe(ip, port, timeoutMs) {
  return new Promise(resolve => {
    const s = new net.Socket();
    let done = false;
    const fin = (ok, extra) => {
      if (done) return;
      done = true;
      try { s.destroy(); } catch { }
      resolve({ ok, ...extra });
    };
    s.setTimeout(timeoutMs);
    s.once('connect', () => fin(true));
    s.once('timeout', () => fin(false, { state: 'filtered' }));
    s.once('error', () => fin(false, { state: 'closed' }));
    try { s.connect(port, ip); } catch { fin(false, { state: 'closed' }); }
  });
}

/** 轻量并发池：保持并发度，不一次性开满，避免把自己这端压垮 */
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
        try { out[i] = await worker(items[i]); }
        catch (e) { out[i] = { error: e.message }; }
      }
    })());
  }
  await Promise.all(runners);
  return out;
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/** 存活发现 */
async function discover(targets, { mode = 'tcp', ports = DISCOVER_PORTS, concurrency = DEFAULT_CONCURRENCY, timeoutMs = DEFAULT_TIMEOUT, retries = 0, onProgress } = {}) {
  const alive = [];
  let done = 0;

  const attempts = Math.max(1, Math.min(4, Number(retries || 0) + 1));
  const retry = async (fn, hit) => {
    let value = null;
    for (let i = 0; i < attempts; i++) {
      value = await fn();
      if (hit(value)) break;
    }
    return value;
  };

  const probeTcp = (ip) => pool(ports, Math.min(16, ports.length), async (p) => {
    const r = await retry(() => tcpProbe(ip, p, timeoutMs), x => x && x.ok);
    return r.ok ? p : null;
  });

  const pingOne = async (ip) => {
    const rtt = await retry(() => netutil.pingOnce(ip, timeoutMs), x => x !== null);
    return rtt === null ? null : rtt;
  };

  await pool(targets, concurrency, async (ip) => {
    let hit = null;
    let rtt = null;
    const how = mode;

    if (mode === 'icmp') {
      rtt = await pingOne(ip);
      if (rtt !== null) hit = ip;
    } else if (mode === 'tcp') {
      const open = (await probeTcp(ip)).filter(Boolean);
      if (open.length) hit = ip;
    } else if (mode === 'mixed') {
      const open = (await probeTcp(ip)).filter(Boolean);
      if (open.length) { hit = ip; rtt = await pingOne(ip); }
    } else {
      // auto：优先 nmap -sn，环境没有就退回 tcp
      const r = await nmapDiscover(ip);
      if (r === true) hit = ip;
      else if (r === null) {
        const open = (await probeTcp(ip)).filter(Boolean);
        if (open.length) hit = ip;
      }
    }

    done++;
    if (onProgress) onProgress({ done, total: targets.length, ip });
    if (hit) alive.push({ ip, rttMs: rtt });
  });

  return alive;
}

/** nmap -sn 探测单个目标（批量时不逐条调用，这里只在 auto 模式下用） */
function nmapDiscover(ip) {
  return new Promise(resolve => {
    try {
      const exe = netutil.findNmap();
      if (!exe) return resolve(null);
      const p = spawn(exe, ['-sn', '-T4', '--host-timeout', '2s', ip], { windowsHide: true, timeout: 6000 });
      let out = '';
      p.stdout.on('data', d => { out += d.toString(); });
      p.stderr.on('data', d => { out += d.toString(); });
      p.on('error', () => resolve(null));
      p.on('close', code => resolve(code === 0 ? /Host is up/.test(out) : null));
    } catch { resolve(null); }
  });
}

/** 端口扫描：对已存活主机逐个探端口，开放的可选抓 banner */
async function scanPorts(aliveHosts, ports, { concurrency = DEFAULT_CONCURRENCY, timeoutMs = DEFAULT_TIMEOUT, banner = true, retries = 0, onProgress } = {}) {
  const open = [];
  let done = 0;
  const attempts = Math.max(1, Math.min(4, Number(retries || 0) + 1));
  const targets = [];
  for (const h of aliveHosts) for (const p of ports) targets.push({ ip: h.ip, port: p, rttMs: h.rttMs });

  await pool(targets, concurrency, async (t) => {
    let r = null;
    for (let i = 0; i < attempts; i++) {
      r = await tcpProbe(t.ip, t.port, timeoutMs);
      if (r.ok) break;
    }
    if (!r.ok) return null;
    let bannerStr = '';
    if (banner) bannerStr = await grabBanner(t.ip, t.port, timeoutMs);
    const { service, product } = identifyService(t.port, bannerStr);
    done++;
    if (onProgress) onProgress({ done, total: targets.length });
    open.push({
      ip: t.ip, port: t.port, state: 'open', proto: 'tcp',
      service, product, banner: bannerStr.slice(0, 200), rttMs: t.rttMs
    });
    return true;
  });

  return open;
}

/** 按 IP 聚合开放端口，并算出每台主机的风险等级 */
function groupByHost(openPorts) {
  const map = new Map();
  for (const p of openPorts) {
    if (!map.has(p.ip)) map.set(p.ip, []);
    map.get(p.ip).push(p);
  }
  const hosts = [];
  for (const [ip, ps] of map) {
    ps.sort((a, b) => a.port - b.port);
    const r = hostRisk(ps);
    hosts.push({ ip, openPorts: ps, riskLevel: r.level, riskTags: r.tags, riskDescs: r.descs });
  }
  hosts.sort((a, b) => b.openPorts.length - a.openPorts.length);
  return hosts;
}

/** 尝试反查主机名，失败不影响结果 */
function reverseHostname(ip) {
  return new Promise(resolve => {
    dns.reverse(ip, (e, hostnames) => resolve(e || !hostnames || !hostnames.length ? '' : hostnames[0]));
  });
}

/* ============================== 执行一轮扫描 ============================== */
/**
 * 跑一轮扫描并入库
 * @param {object} task  扫描任务（含 id / name / targets / ports / 等）
 * @param {string} user  触发人
 */
async function runScan(task, user = 'system') {
  const t0 = Date.now();
  const runId = store.uid('scan_');
  const startedAt = new Date(t0).toISOString();

  const advanced = task.data && typeof task.data === 'object' ? task.data : {};
  const mode = task.discoverMode || 'tcp';
  const concurrency = Math.max(1, Math.min(400, Number(task.concurrency || DEFAULT_CONCURRENCY)));
  const timeoutMs = Math.max(200, Math.min(10000, Number(task.timeoutMs || DEFAULT_TIMEOUT)));
  const retries = Math.max(0, Math.min(3, Number(task.retries ?? advanced.retries ?? 0)));
  const discoveryPorts = parsePorts(task.discoveryPorts || advanced.discoveryPorts || DISCOVER_PORTS.join(',')).slice(0, 64);
  const withBanner = task.banner !== false;
  const reverseDns = (task.reverseDns ?? advanced.reverseDns) !== false;
  const excludeTargets = String(task.excludeTargets || advanced.excludeTargets || '').trim();
  const note = String(task.note || advanced.note || '').trim().slice(0, 200);

  let targets = [];
  try {
    targets = await expandTargets(task.targets);
    if (excludeTargets) {
      const excluded = new Set(await expandTargets(excludeTargets));
      targets = targets.filter(ip => !excluded.has(ip));
      if (!targets.length) throw new Error('排除目标后没有剩余扫描地址，请检查自定义排除范围');
    }
  } catch (e) {
    await db.scanRunSave({
      id: runId, taskId: task.id || '', name: task.name || '扫描', targets: task.targets || '',
      mode, status: 'error', hostsTotal: 0, startedAt, endedAt: new Date().toISOString(),
      durationMs: Date.now() - t0, data: { error: e.message }
    });
    throw e;
  }

  await db.scanRunSave({
    id: runId, taskId: task.id || '', name: task.name || '扫描', targets: task.targets || '',
    mode, hostsTotal: targets.length, status: 'running', startedAt,
    data: { ports: parsePorts(task.ports), discoveryPorts, concurrency, timeoutMs, retries, banner: withBanner, reverseDns, excludeTargets, note, user }
  });

  const alive = await discover(targets, { mode, ports: discoveryPorts.length ? discoveryPorts : DISCOVER_PORTS, concurrency, timeoutMs, retries });
  const portList = parsePorts(task.ports);
  const openPorts = portList.length
    ? await scanPorts(alive, portList, { concurrency, timeoutMs, banner: withBanner, retries })
    : [];
  const hosts = groupByHost(openPorts);

  /* 存活但没有开放目标端口的主机也必须进入结果，否则会造成“存活数”和主机明细不一致。 */
  const grouped = new Set(hosts.map(h => h.ip));
  for (const a of alive) {
    if (!grouped.has(a.ip)) hosts.push({ ip: a.ip, rttMs: a.rttMs, openPorts: [], riskLevel: 'info', riskTags: [], riskDescs: [] });
  }
  for (const h of hosts) {
    const a = alive.find(x => x.ip === h.ip);
    if (a) h.rttMs = a.rttMs;
  }
  hosts.sort((a, b) => (LEVEL_ORDER[b.riskLevel] - LEVEL_ORDER[a.riskLevel]) || b.openPorts.length - a.openPorts.length || a.ip.localeCompare(b.ip));

  /* 主机名反查只在主机数不多时做，避免 DNS 拖慢整轮 */
  if (reverseDns && hosts.length && hosts.length <= 64) {
    await pool(hosts, 12, async (h) => {
      h.hostname = await reverseHostname(h.ip);
    });
  }

  const riskCount = hosts.filter(h => ['high', 'critical'].includes(h.riskLevel)).length;

  /* ---- 主机入库 ---- */
  const hostRows = hosts.map(h => ({
    id: store.uid('sh_'),
    runId, taskId: task.id || '',
    ip: h.ip, hostname: h.hostname || '',
    alive: true, openPorts: h.openPorts.length,
    riskLevel: h.riskLevel, riskTags: h.riskTags,
    createdAt: startedAt
  }));
  if (hostRows.length) await db.scanHostInsert(hostRows);

  /* ---- 端口入库 ---- */
  const portRows = openPorts.map(p => {
    const r = riskOf(p.port, p.service);
    return {
      id: store.uid('sp_'),
      runId, taskId: task.id || '', hostIp: p.ip,
      ip: p.ip, port: p.port, proto: p.proto || 'tcp', state: p.state,
      service: p.service, product: p.product || '',
      banner: p.banner || '',
      riskLevel: r ? r.level : 'info', riskDesc: r ? r.desc : '',
      createdAt: startedAt
    };
  });
  if (portRows.length) await db.scanPortInsert(portRows);

  /* ---- 集成：资产台账 + 告警 ---- */
  const inventory = await syncInventory(hosts, runId, task.name);
  const alarms = await raiseAlarms(hosts, portRows, runId, task.name, user);

  const endedAt = new Date().toISOString();
  await db.scanRunSave({
    id: runId, taskId: task.id || '', name: task.name || '扫描', targets: task.targets || '',
    mode, hostsTotal: targets.length, hostsAlive: alive.length,
    portsOpen: portRows.length, risks: riskCount,
    status: 'done', startedAt, endedAt, durationMs: Date.now() - t0,
    data: { ports: portList, discoveryPorts, concurrency, timeoutMs, retries, banner: withBanner, reverseDns, excludeTargets, note, user, inventory, alarms }
  });

  await db.scanTaskSave({
    id: task.id,
    lastStartedAt: startedAt,
    lastEndedAt: endedAt,
    runs: Number(task.runs || 0) + 1,
    status: 'idle'
  }).catch(() => { });

  store.audit({
    user, action: 'scan.run', target: task.name || runId,
    detail: `${targets.length} 目标 · 存活 ${alive.length} · 开放端口 ${portRows.length} · 高危主机 ${riskCount} · ${Date.now() - t0}ms`
  });

  const serviceMap = new Map();
  for (const p of portRows) serviceMap.set(p.service || 'unknown', (serviceMap.get(p.service || 'unknown') || 0) + 1);
  const services = [...serviceMap.entries()].map(([service, count]) => ({ service, count })).sort((a, b) => b.count - a.count).slice(0, 10);
  const findings = portRows.filter(p => ['critical', 'high', 'medium'].includes(p.riskLevel))
    .sort((a, b) => (LEVEL_ORDER[b.riskLevel] || 0) - (LEVEL_ORDER[a.riskLevel] || 0))
    .slice(0, 12).map(p => ({ ip: p.ip, port: p.port, service: p.service, level: p.riskLevel, desc: p.riskDesc }));
  const recommendations = [...new Set(findings.map(x => x.desc).filter(Boolean))].slice(0, 6);
  if (!recommendations.length) recommendations.push('未发现规则库中的明显高危暴露；仍建议结合业务基线确认每个开放端口的必要性。');
  const rtts = alive.map(x => Number(x.rttMs)).filter(Number.isFinite);
  const avgRttMs = rtts.length ? Math.round(rtts.reduce((a, b) => a + b, 0) / rtts.length * 10) / 10 : null;

  return {
    ok: true, runId, ms: Date.now() - t0,
    total: targets.length, alive: alive.length,
    offline: Math.max(0, targets.length - alive.length),
    availabilityRate: targets.length ? Math.round(alive.length / targets.length * 1000) / 10 : 0,
    avgRttMs,
    openPorts: portRows.length, riskHosts: riskCount,
    inventory, alarms, services, findings, recommendations,
    parameters: { mode, ports: portList, discoveryPorts, concurrency, timeoutMs, retries, banner: withBanner, reverseDns, excludeTargets, note },
    hostPreview: hosts.slice(0, 20).map(h => ({ ip: h.ip, hostname: h.hostname || '', rttMs: h.rttMs, openPorts: h.openPorts.map(p => p.port), riskLevel: h.riskLevel, riskTags: h.riskTags }))
  };
}

/* ============================== 集成一：资产台账 ============================== */
/** 把扫描发现的主机并入设备补充信息，让它们出现在资产与拓扑里 */
async function syncInventory(hosts, runId, taskName) {
  let added = 0, updated = 0;
  for (const h of hosts) {
    const cur = await db.inventoryGet(h.ip);
    const isNew = !cur || !Object.keys(cur).length;
    const guess = guessVendor(h.openPorts, h.ip);
    // 系统自己写的发现说明随每次扫描刷新；用户手填的备注原样保留
    const auto = /^由扫描发现（/.test(cur.note || '');
    await db.inventorySet(h.ip, {
      zone: cur.zone || inferZone(h.ip),
      role: cur.role || '未知',
      brand: cur.brand || guess.brand || '',
      model: cur.model || '',
      scannedAt: new Date().toISOString(),
      scannedBy: taskName || '',
      runId,
      note: auto
        ? `由扫描发现（${h.openPorts.length} 个开放端口${h.riskLevel !== 'info' ? `，风险 ${h.riskLevel}` : ''}）`
        : (cur.note || `由扫描发现（${h.openPorts.length} 个开放端口）`)
    });
    if (isNew) added++; else updated++;
  }
  return { added, updated };
}

/** 按开放端口特征猜厂商/品牌，给资产台账一个初始线索 */
function guessVendor(openPorts, ip) {
  const ports = openPorts.map(p => p.port);
  const svcs = openPorts.map(p => p.service);
  const s = svcs.join(' ');
  if (/s7comm|Modbus|Siemens/.test(s)) return { brand: 'Siemens' };
  if (ports.includes(502)) return { brand: 'Modbus 设备' };
  if (ports.includes(179)) return { brand: 'Cisco' };
  if (ports.includes(830) || ports.includes(623)) return { brand: '网络管理设备' };
  if (/ssh/.test(s) && ports.includes(22)) return { brand: 'Linux/Unix' };
  if (/microsoft-ds|ms-rdp|wsman/.test(s)) return { brand: 'Windows' };
  return { brand: '' };
}

/** 按网段惯例给个初始区域，便于后续归到正确的归属组 */
function inferZone(ip) {
  if (/^127\./.test(ip)) return '本机回环';
  if (/^10\.252\./.test(ip)) return '管理网段';
  const a = ip.split('.')[0];
  if (a === '10') return '10 网段';
  if (a === '172') return '172 网段';
  if (a === '192') return '192 网段';
  return '未分组';
}

/* ============================== 集成二：告警与风险 ============================== */
async function raiseAlarms(hosts, portRows, runId, taskName, user) {
  let created = 0;
  // 主机级：只报高危主机，避免一台主机 N 个端口刷 N 条告警
  for (const h of hosts) {
    if (!['high', 'critical'].includes(h.riskLevel)) continue;
    const sev = h.riskLevel === 'critical' ? 'disaster' : 'high';
    const title = `${h.ip} 开放 ${h.openPorts.length} 个端口，风险 ${h.riskLevel === 'critical' ? '极高' : '高'}`;
    const msg = `扫描任务「${taskName}」发现：${h.riskTags.join('、') || '存在高危暴露面'}。\n${(h.riskDescs[0] || '')}`;
    try {
      await db.alarmsCreate({
        source: 'scan', severity: sev, host: h.ip, title, message: msg,
        status: 'open', clock: store.nowSec(), runId,
        createdAt: new Date().toISOString()
      });
      created++;
    } catch { /* 告警写入失败不影响扫描主流程 */ }
  }
  return { created };
}

/* ============================== 调度 ============================== */
async function tick() {
  try {
    const tasks = await db.scanTaskList();
    for (const t of tasks) {
      if (!t.enabled || running.has(t.id)) continue;
      const gap = Number(t.intervalSec || 3600);
      const last = t.lastStartedAt ? new Date(t.lastStartedAt).getTime() : 0;
      if (Date.now() - last < gap * 1000) continue;
      running.set(t.id, Date.now());
      runScan(t, 'scheduler').catch(e => {
        console.error(`[scan] 任务 ${t.name} 执行失败：${e.message}`);
        db.scanTaskSave({ id: t.id, status: 'error' }).catch(() => { });
      }).finally(() => running.delete(t.id));
    }
  } catch (e) { console.error('[scan] 调度异常：', e.message); }
}

/** 保留策略：删除超过 retainHours 的主机/端口记录，扫描任务本身保留供追溯 */
async function sweep() {
  try {
    const tasks = await db.scanTaskList();
    let removedHosts = 0, removedPorts = 0;
    const now = Date.now();
    for (const t of tasks) {
      const hrs = Number(t.retainHours || 72);
      if (!hrs) continue;
      if (now - new Date(t.lastEndedAt || 0).getTime() < hrs * 3600 * 1000) continue;
      const cut = new Date(now - hrs * 3600 * 1000).toISOString();
      const r = await db.scanRemoveOld(cut, t.id);
      removedHosts += r.hosts; removedPorts += r.ports;
    }
    if (removedHosts || removedPorts) {
      console.log(`[scan] 保留策略清理：删除 ${removedHosts} 条主机记录 / ${removedPorts} 条端口记录`);
    }
  } catch (e) { /* 清理失败不影响主流程 */ }
}

function info() {
  return ['网络扫描  已就绪 · 本机执行，发现方式 tcp/icmp/mixed/auto'];
}

async function start() {
  if (timer) return;
  timer = setInterval(tick, SCHED_LEAD);
  setInterval(sweep, 30 * 60 * 1000);
  const tasks = await db.scanTaskList().catch(() => []);
  const enabled = tasks.filter(t => t.enabled).length;
  console.log(`  网络扫描  已启动 · 任务 ${tasks.length} 个（启用 ${enabled} 个）`);
  tick();
}

/* ============================== 快捷扫描 ============================== */
/** 不建任务、直接扫一次（页面上的「快速扫描」） */
async function quick(targets, { ports = '22,80,443,3389,445', discoverMode = 'tcp', banner = true, concurrency = DEFAULT_CONCURRENCY, timeoutMs = DEFAULT_TIMEOUT, retries = 0, discoveryPorts = '', excludeTargets = '', reverseDns = true, note = '' } = {}, user = 'system') {
  return runScan({ name: '快速扫描', targets, ports, discoverMode, banner, concurrency, timeoutMs, retries, discoveryPorts, excludeTargets, reverseDns, note }, user);
}

module.exports = {
  start, info, quick, runScan, tick, sweep,
  // 下面几个扫描原语单独导出，供 tools/scan-smoke.js 在不碰数据库的前提下做引擎级验证
  expandTargets, parsePorts, presets, riskOf, hostRisk, identifyService,
  discover, scanPorts, groupByHost,
  RISK_RULES, PORT_PRESETS, PORT_PRESETS_KEYS: Object.keys(PORT_PRESETS),
  LEVEL_ORDER, DISCOVER_PORTS, MAX_HOSTS, running
};
