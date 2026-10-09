'use strict';
/**
 * 存储层
 * - 结构化数据（用户/凭据/设置/模板/抓包记录/测速记录索引）存 data/db.json
 * - 审计日志与终端录像按 append-only 落盘，便于长期留存与合规审计
 * - 凭据字段使用 AES-256-GCM 加密，主密钥首次运行自动生成并落盘
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* 打包成 exe 后 __dirname 指向进程内只读快照，data/ 写不进去。
   所以拆成两个根：
   - SNAPSHOT_ROOT：包内快照根，只在打包后 ≠ 磁盘目录，用于读静态资源
   - ROOT：运行时可写根，打包后 = exe 所在目录，数据/日志都落这里
   （开发模式下两者是同一个目录，行为与改动前完全一致） */
const SNAPSHOT_ROOT = path.resolve(__dirname, '..');
const ROOT = process.pkg ? path.dirname(process.execPath) : SNAPSHOT_ROOT;
/* 静态资源只读，始终以包内快照为准 */
const WEB_DIR = path.join(SNAPSHOT_ROOT, 'public');
const VENDOR_DIR = path.join(SNAPSHOT_ROOT, 'node_modules');
const DATA_DIR = path.join(ROOT, 'data');
const REC_DIR = path.join(DATA_DIR, 'recordings');
const SPEED_DIR = path.join(DATA_DIR, 'speed');
const CAP_DIR = path.join(DATA_DIR, 'captures');
const LOG_DIR = path.join(DATA_DIR, 'logs');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const KEY_FILE = path.join(DATA_DIR, '.masterkey');

try {
  for (const d of [DATA_DIR, REC_DIR, SPEED_DIR, CAP_DIR, LOG_DIR]) {
    fs.mkdirSync(d, { recursive: true });
  }
} catch (e) {
  throw new Error(`数据目录不可用：${DATA_DIR}（${e.code || e.message}）。请把 exe 放到普通可写文件夹运行，例如桌面、项目目录，不要放在 C:\\Program Files 下。`);
}

/* ---------------------------------- 主密钥 --------------------------------- */
function masterKey() {
  if (!fs.existsSync(KEY_FILE)) {
    fs.writeFileSync(KEY_FILE, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  }
  return Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex');
}
const MK = masterKey();

/* -------------------------------- 加解密工具 ------------------------------- */
function encrypt(plain) {
  if (plain === null || plain === undefined || plain === '') return '';
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', MK, iv);
  const enc = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), enc.toString('base64')].join(':');
}
function decrypt(blob) {
  if (!blob) return '';
  const p = String(blob).split(':');
  if (p.length !== 4 || p[0] !== 'v1') return '';
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', MK, Buffer.from(p[1], 'base64'));
    d.setAuthTag(Buffer.from(p[2], 'base64'));
    return Buffer.concat([d.update(Buffer.from(p[3], 'base64')), d.final()]).toString('utf8');
  } catch { return ''; }
}
const hash = (s, salt = crypto.randomBytes(16).toString('hex')) =>
  `scrypt$${salt}$${crypto.scryptSync(String(s), salt, 64).toString('hex')}`;
function verify(pwd, stored) {
  if (!stored || !stored.startsWith('scrypt$')) return false;
  const [, salt, digest] = stored.split('$');
  const calc = crypto.scryptSync(String(pwd), salt, 64);
  const want = Buffer.from(digest, 'hex');
  return calc.length === want.length && crypto.timingSafeEqual(calc, want);
}
const uid = (p = '') => p + crypto.randomBytes(6).toString('hex');
const nowSec = () => Math.floor(Date.now() / 1000);

/* ---------------------------------- 数据结构 -------------------------------- */
const DEFAULT_DB = () => ({
  version: 1,
  createdAt: new Date().toISOString(),
  settings: {
    site: { name: '网络运维控制台', subtitle: 'Network Operations Console', logoText: 'NETOPS' },
    datasource: {
      mode: 'demo',                       // demo | zabbix
      zabbix: { url: 'http://10.252.28.99', username: 'Admin', password: '', pollSec: 60, tlsVerify: false, timeoutMs: 15000 },
      lastOkAt: null, lastError: ''
    },
    notify: {
      webhook: { enabled: false, url: '', secret: '' },
      wecom: { enabled: false, url: '' },
      dingtalk: { enabled: false, url: '', secret: '' },
      smtp: { enabled: false, host: '', port: 465, secure: true, user: '', pass: '', from: '', to: '' },
      minSeverity: 'high',
      cooldownSec: 300
    },
    ai: {
      enabled: true,
      provider: 'none',                    // none | openai | ollama
      baseUrl: '',                          // 如 https://api.deepseek.com/v1
      apiKey: '',
      model: '',
      temperature: 0.2,
      maxTokens: 1024,
      systemPrompt: '你是一名资深企业网络运维工程师，精通 Cisco IOS/NX-OS、华为 VRP、H3C Comware、Palo Alto PAN-OS、Fortinet FortiOS 的排障与配置。回答要给出可执行的判断步骤和命令，简洁、专业、不废话。'
    },
    terminal: {
      idleTimeoutSec: 600,
      recordSessions: true,
      dangerPatterns: ['reload', 'erase ', 'write erase', 'delete /force', 'format ', 'factory-reset',
        'reset saved-configuration', 'undo ', 'shutdown', 'no vlan', 'clear config', 'restore factory']
    },
    capture: {
      engine: 'auto',                       // auto | tshark | device
      tsharkPath: '',
      deviceCommand: {
        cisco: 'monitor capture {name} interface {intf} both match ip {filterTarget} limit duration {sec}',
        huawei: 'capture-packet interface {intf} ...',
        h3c: 'capture-packet interface {intf} ...',
        fortinet: 'diagnose sniffer packet any \'{filter}\' 4 0 a',
        paloalto: 'debug dataplane packet-diag set filter match source {filterTarget}'
      }
    },
    speed: {
      iperfPath: '',
      serverPort: 5201,
      httpPort: 5202,
      maxParallel: 4,
      durationSec: 10
    },
    netdiag: {
      // Syslog 接收（网络设备把日志发到控制台，供日志审计）
      syslog: { enabled: false, port: 514, proto: 'udp', retainDays: 30, maxRows: 50000 },
      // 外网测速：下行/上行端点与目标主机（可改成内网出口对端）
      speed: {
        endpoints: [
          { key: 'cloudflare', name: 'Cloudflare', down: 'https://speed.cloudflare.com/__down?bytes={bytes}', up: 'https://speed.cloudflare.com/__up', ping: '1.1.1.1' }
        ],
        pingHost: '1.1.1.1',
        durationSec: 8,
        parallel: 4
      },
      // 摄像头扫描端口与网段上限
      camera: { ports: [554, 80, 81, 8000, 8080, 8001, 8081, 37777, 34567, 10554, 5000, 88, 8899, 9000, 6036] },
      maxHosts: 1024,
      // IP 冲突检测采样轮次；环路检测抓包时长（秒）
      conflict: { rounds: 3 },
      loop: { seconds: 8 },
      dhcp: { seconds: 6 }
    }
  },
  users: [],
  credentials: [],   // { id, name, vendor, kind: ssh|telnet|snmp|zabbix, host, port, username, secretEnc, enableEnc, note, createdAt }
  templates: [],     // 命令模板 { id, name, vendor, commands[], category, danger }
  alarms: [],        // 本地告警/事件 { id, source, severity, host, title, message, status, createdAt, ackBy, ackAt }
  inventory: {},     // 设备补充信息 host -> { zone, role, brand, model, rack, owner, note, x, y }
  topology: { nodes: [], links: [] },
  aiHistory: [],     // { id, user, question, answer, at }
  scanRuns: [],      // 每次扫描一条 { id, taskId, name, targets, hostsTotal, hostsAlive, portsOpen, risks, status, ... }
  scanHosts: [],     // 发现的主机 { id, runId, ip, hostname, openPorts, riskLevel, riskTags }
  scanPorts: [],     // 发现的开放端口 { id, runId, ip, port, service, banner, riskLevel }
  scanTasks: [],     // 扫描任务 { id, name, targets, ports, discoverMode, intervalSec, retainHours, ... }
  netdiagRuns: [],   // 诊断执行记录 { id, tool, mode, targets, score, level, findingsCount, ... }
  netdiagHosts: [],  // 诊断命中的主机（摄像头等）{ id, runId, tool, ip, mac, vendor, riskLevel, data }
  netdiagFindings: [], // 诊断问题清单 { id, runId, tool, level, category, target, title, detail, advice }
  netdiagLogs: [],   // 日志审计原始日志 { id, source, host, facility, severity, tag, message, rule, level }
  netdiagTasks: []   // 诊断定时任务 { id, name, tool, mode, targets, options, intervalSec, retainHours }
});

let DB = null;
function load() {
  if (DB) return DB;
  if (fs.existsSync(DB_FILE)) {
    try { DB = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { DB = null; }
  }
  if (!DB || typeof DB !== 'object') DB = DEFAULT_DB();
  // 结构补齐（版本升级不丢数据）
  const d = DEFAULT_DB();
  DB.settings = deepMerge(d.settings, DB.settings || {});
  for (const k of ['users', 'credentials', 'templates', 'alarms', 'aiHistory',
    'scanRuns', 'scanHosts', 'scanPorts', 'scanTasks',
    'netdiagRuns', 'netdiagHosts', 'netdiagFindings', 'netdiagLogs', 'netdiagTasks']) {
    if (!Array.isArray(DB[k])) DB[k] = [];
  }
  if (!DB.inventory) DB.inventory = {};
  if (!DB.topology) DB.topology = { nodes: [], links: [] };
  return DB;
}
function deepMerge(base, over) {
  if (Array.isArray(base) || Array.isArray(over)) return over === undefined ? base : over;
  if (typeof base !== 'object' || base === null) return over === undefined ? base : over;
  const out = { ...base };
  for (const [k, v] of Object.entries(over || {})) {
    out[k] = (v && typeof v === 'object' && !Array.isArray(v)) ? deepMerge(base[k] || {}, v) : v;
  }
  return out;
}

let saveTimer = null;
function save(immediate = false) {
  const write = () => {
    saveTimer = null;
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(DB, null, 2), 'utf8');
    fs.renameSync(tmp, DB_FILE);
  };
  if (immediate) { if (saveTimer) clearTimeout(saveTimer); write(); return; }
  if (!saveTimer) saveTimer = setTimeout(write, 300);
}

/* ---------------------------------- 审计日志 -------------------------------- */
function audit(entry) {
  const row = {
    ts: new Date().toISOString(),
    user: entry.user || 'system',
    role: entry.role || '-',
    ip: entry.ip || '-',
    action: entry.action || 'unknown',
    target: entry.target || '',
    result: entry.result || 'ok',
    detail: entry.detail || ''
  };
  try {
    fs.appendFileSync(path.join(LOG_DIR, `audit-${new Date().toISOString().slice(0, 10)}.ndjson`),
      JSON.stringify(row) + '\n', 'utf8');
  } catch { /* 审计失败不阻断业务 */ }
  return row;
}
function readAudit({ limit = 200, user = '', action = '', from = '', to = '' } = {}) {
  const files = fs.readdirSync(LOG_DIR).filter(f => f.startsWith('audit-')).sort().reverse();
  const out = [];
  for (const f of files) {
    const lines = fs.readFileSync(path.join(LOG_DIR, f), 'utf8').split('\n').filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      let r; try { r = JSON.parse(lines[i]); } catch { continue; }
      if (user && r.user !== user) continue;
      if (action && !String(r.action).includes(action)) continue;
      if (from && r.ts < from) continue;
      if (to && r.ts > to) continue;
      out.push(r);
      if (out.length >= limit) return out;
    }
  }
  return out;
}

/* ---------------------------------- 终端录像 -------------------------------- */
function newRecording(meta) {
  const id = uid('rec_');
  const file = path.join(REC_DIR, `${id}.ndjson`);
  fs.writeFileSync(file, JSON.stringify({ t: 'meta', ...meta, id, startedAt: new Date().toISOString() }) + '\n', 'utf8');
  return { id, file };
}
function appendRecording(file, event) {
  try { fs.appendFileSync(file, JSON.stringify(event) + '\n', 'utf8'); } catch { }
}
function listRecordings({ limit = 100, host = '', user = '' } = {}) {
  const out = [];
  for (const f of fs.readdirSync(REC_DIR).filter(x => x.endsWith('.ndjson'))) {
    const full = path.join(REC_DIR, f);
    let meta = null, count = 0, bytes = 0;
    try {
      const lines = fs.readFileSync(full, 'utf8').split('\n').filter(Boolean);
      meta = JSON.parse(lines[0]);
      for (const l of lines.slice(1)) { try { const e = JSON.parse(l); count++; bytes += (e.d || '').length; } catch { } }
    } catch { continue; }
    if (!meta || meta.t !== 'meta') continue;
    if (host && meta.host !== host) continue;
    if (user && meta.user !== user) continue;
    out.push({ ...meta, events: count, bytes, file: f });
  }
  out.sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
  return out.slice(0, limit);
}
function readRecording(id) {
  const full = path.join(REC_DIR, `${id}.ndjson`);
  if (!fs.existsSync(full)) return null;
  const lines = fs.readFileSync(full, 'utf8').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const meta = lines.find(x => x.t === 'meta') || {};
  const events = lines.filter(x => x.t !== 'meta');
  return { meta, events };
}
function deleteRecording(id) {
  const full = path.join(REC_DIR, `${id}.ndjson`);
  if (fs.existsSync(full)) { fs.unlinkSync(full); return true; }
  return false;
}

/* ---------------------------------- 测速结果 -------------------------------- */
function saveSpeedResult(r) {
  const f = path.join(SPEED_DIR, `${r.id}.json`);
  fs.writeFileSync(f, JSON.stringify(r, null, 2), 'utf8');
  return r;
}
function listSpeedResults(limit = 50) {
  const files = fs.readdirSync(SPEED_DIR).filter(f => f.endsWith('.json'));
  const out = files.map(f => { try { return JSON.parse(fs.readFileSync(path.join(SPEED_DIR, f), 'utf8')); } catch { return null; } })
    .filter(Boolean).sort((a, b) => String(b.at).localeCompare(String(a.at)));
  return out.slice(0, limit);
}

module.exports = {
  ROOT, SNAPSHOT_ROOT, WEB_DIR, VENDOR_DIR,
  DATA_DIR, REC_DIR, SPEED_DIR, CAP_DIR, LOG_DIR,
  get db() { return load(); },
  load, save, deepMerge,
  encrypt, decrypt, hash, verify, uid, nowSec,
  audit, readAudit,
  newRecording, appendRecording, listRecordings, readRecording, deleteRecording,
  saveSpeedResult, listSpeedResults,
  path, fs, crypto
};
