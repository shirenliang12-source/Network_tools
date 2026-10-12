'use strict';
/**
 * 网络运维与故障排除工具平台 —— 服务入口
 * 启动后浏览器访问 http(s)://<本机IP>:8787
 *   - 在 data/ 下放置 cert.pem + key.pem（或设 TLS_CERT/TLS_KEY 环境变量）即自动启用 HTTPS；
 *   - 未提供证书时回退为 HTTP（便于开发/自检）；HTTPS=1 可强制启用（缺证书则启动失败）。
 */
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');
const express = require('express');
const { WebSocketServer } = require('ws');

/* ---------- 启动日志与崩溃可见性 ----------
   打包成 exe 后双击运行，若发生致命错误，控制台窗口会一闪而过、用户看不到原因。
   这里在最早时机挂上：
     ① 把输出同时追加写入 exe 旁的 netops-console.log（便于事后排查）；
     ② 致命错误时用 pause 阻塞窗口，等用户读完提示再退出。 */
const RUNTIME_DIR = process.pkg ? path.dirname(process.execPath) : path.resolve(__dirname, '..');
const START_LOG = path.join(RUNTIME_DIR, 'netops-console.log');
const _teeLog = console.log.bind(console), _teeErr = console.error.bind(console);
function _teeWrite(level, args) {
  try { fs.appendFileSync(START_LOG, `[${new Date().toISOString()}] ${level} ${args.map(String).join(' ')}\n`); } catch { }
}
console.log = (...a) => { _teeLog(...a); _teeWrite('INFO', a); };
console.error = (...a) => { _teeErr(...a); _teeWrite('ERR', a); };
/* 双击运行（pkg）时若致命错误，原地 pause，避免窗口一闪而过 */
function holdWindow() {
  if (!process.pkg) return;
  try {
    if (process.platform === 'win32') require('child_process').spawnSync('cmd', ['/c', 'pause'], { stdio: 'inherit' });
    else require('child_process').spawnSync('sh', ['-c', 'read -r _'], { stdio: 'inherit' });
  } catch { }
}
function fatalExit(err) {
  console.error('\n========== 启动失败 ==========');
  console.error((err && err.stack) || err);
  console.error('常见原因与解决：');
  console.error('  1) exe 放在只读目录（如 C:\\Program Files）→ 移到桌面或普通文件夹再运行');
  console.error('  2) 端口被占用 → 设置端口后重试：set PORT=8899  （再执行本程序）');
  console.error('  3) 完整启动日志见：' + START_LOG);
  console.error('==============================');
  holdWindow();
  process.exit(1);
}
process.on('uncaughtException', e => console.error('[uncaught]', (e && e.stack) || e));
process.on('unhandledRejection', e => console.error('[unhandled]', (e && e.stack) || e));

let store, db, auth, netutil, runtimeTools, term, router;
try {
  store = require('./store');
  db = require('./db');
  auth = require('./auth');
  netutil = require('./netutil');
  runtimeTools = require('./runtime-tools');
  term = require('./term');
  router = require('./api').router;
} catch (e) { fatalExit(e); }

/*
 * 打包版首次启动自动申请管理员令牌：PktMon 本机抓包与 Nmap 的 Windows
 * 静默安装都受 UAC 保护。用户只需在启动平台时通过一次 Windows 系统提示，
 * 后续第三方工具全部由后台完成，不再弹各自安装向导。
 */
if (process.pkg && process.platform === 'win32' && process.env.NO_ELEVATE !== '1' && !runtimeTools.isElevated()) {
  try {
    const ps = require('child_process').spawnSync('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-Command',
      'Start-Process -FilePath $env:NETOPS_EXE -Verb RunAs'
    ], { windowsHide: true, env: { ...process.env, NETOPS_EXE: process.execPath }, timeout: 30000 });
    if (ps.status === 0) process.exit(0);
    console.warn('[runtime] 未获得管理员权限，将保留设备侧抓包与内置扫描回退。');
  } catch (e) { console.warn('[runtime] 自动提权失败：', e.message); }
}

const PORT = Number(process.env.PORT || 8787);
/* 默认双栈监听 '::'：Windows 上 localhost 有可能解析到 ::1，只听 IPv4 会导致
   浏览器「 localhost 打不开、但 127.0.0.1 能开 」。dual-stack 下 IPv4-mapped
   地址同样可连，两种写法都能通。HOST 环境变量仍可显式指定，见下方 listenFallback。 */
const HOST = process.env.HOST || '::';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '4mb', strict: false }));   // strict:false 兼容空 body / null 这类 DELETE 请求
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

/* 访问日志（仅记录关键动作，避免刷屏） */
app.use((req, res, next) => {
  const t0 = Date.now();
  res.on('finish', () => {
    if (req.path.startsWith('/api') && !req.path.startsWith('/api/speed/http')) {
      const ms = Date.now() - t0;
      if (ms > 800) console.log(`[slow] ${req.method} ${req.path} ${res.statusCode} ${ms}ms`);
    }
  });
  next();
});

/* 前端静态资源；vendor 直接映射 node_modules，保证内网无外网也能跑 */
app.use('/vendor', express.static(path.join(store.VENDOR_DIR, 'vue', 'dist'), { maxAge: '7d' }));
app.use('/vendor/echarts', express.static(path.join(store.VENDOR_DIR, 'echarts', 'dist'), { maxAge: '7d' }));
app.use(express.static(store.WEB_DIR, { maxAge: '0', etag: false }));

/* HTTPS 时下发 HSTS，强制浏览器只用安全连接 */
app.use((req, res, next) => {
  if (useHttps) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

app.use('/api', router);
app.get('/healthz', (req, res) => res.json({ ok: true, ts: Date.now() }));

/* 抓包文件下载（PCAP 需带正确文件名） */
app.get('/api/capture/file/:id', (req, res) => {
  const id = String(req.params.id).replace(/[^\w-]/g, '');
  const p = [path.join(store.CAP_DIR, `${id}.pcap`), path.join(store.CAP_DIR, `${id}.pcapng`)].find(fs.existsSync);
  if (!p) return res.status(404).send('not found');
  res.download(p, path.basename(p));
});

/* SPA 兜底（Express 5 / path-to-regexp v8 需使用命名通配 *splat） */
app.get('/*splat', (req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/ws')) return next();
  res.sendFile(path.join(store.WEB_DIR, 'index.html'));
});
app.use((req, res) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/ws')) return res.status(404).json({ ok: false, error: '接口不存在' });
  res.sendFile(path.join(store.WEB_DIR, 'index.html'));
});

/* 统一错误处理 */
app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  res.status(500).json({ ok: false, error: err.message || '服务器内部错误' });
});

/* ============================== TLS 配置 ============================== */
/* 优先使用用户提供的 CA 证书（data/cert.pem + data/key.pem，或用环境变量
   TLS_CERT / TLS_KEY 指定路径）。HTTPS=1 强制启用（缺证书则启动失败并提示）；
   未强制且缺证书时回退 HTTP 并打印警告（便于开发/自检，部署时放好证书即自动升级）。
   WebSocket 升级逻辑对 http/https 通用，无需改动。 */
let useHttps = false;
function loadTls() {
  const env = String(process.env.HTTPS || '').toLowerCase();
  const force = env === '1' || env === 'true';
  const certPath = process.env.TLS_CERT || path.join(store.DATA_DIR, 'cert.pem');
  const keyPath = process.env.TLS_KEY || path.join(store.DATA_DIR, 'key.pem');
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    if (force) {
      return fatalExit(new Error(
        `已设置 HTTPS=1 但未找到 TLS 证书文件：\n  cert: ${certPath}\n  key : ${keyPath}\n` +
        `请将 CA 签发的证书 cert.pem 与私钥 key.pem 放到程序目录的 data/ 下，或用 TLS_CERT / TLS_KEY 环境变量指定绝对路径。`
      ));
    }
    console.warn('[tls] 未找到证书文件（data/cert.pem + data/key.pem），将以 HTTP 方式启动。\n' +
      '      HTTPS=1 可强制启用；将证书放到 data/ 后即自动升级为 HTTPS。');
    return null;
  }
  try {
    const opts = { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) };
    const chainPath = process.env.TLS_CHAIN || path.join(store.DATA_DIR, 'chain.pem');
    if (fs.existsSync(chainPath)) opts.ca = fs.readFileSync(chainPath);
    return opts;
  } catch (e) {
    return fatalExit(new Error('读取 TLS 证书失败：' + e.message));
  }
}

/* ============================== WebSocket ============================== */
const _tls = loadTls();
useHttps = !!_tls;
const server = _tls ? https.createServer(_tls, app) : http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

term.terminalSocket(wss);   // 终端

/* 实时探测流：/ws/probe?token=... 前端发 {targets,count,intervalMs} 后端逐包回推 */
const wssProbe = new WebSocketServer({ noServer: true });
wssProbe.on('connection', (ws, req) => {
  const u = new URL(req.url, 'http://x');
  const p = auth.verifyToken(u.searchParams.get('token') || '');
  if (!p) return ws.close();
  let stopped = false;
  ws.on('message', async raw => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (msg.t !== 'start') return;
    const targets = (Array.isArray(msg.targets) ? msg.targets : String(msg.targets || '').split(/[\s,;]+/)).filter(Boolean).slice(0, 12);
    const count = Math.min(200, Math.max(1, Number(msg.count || 20)));
    const intervalMs = Math.min(5000, Math.max(100, Number(msg.intervalMs || 1000)));
    stopped = false;
    for (const t of targets) {
      if (stopped) break;
      ws.readyState === 1 && ws.send(JSON.stringify({ t: 'begin', target: t }));
      await netutil.ping(t.split(':')[0], {
        count, intervalMs, timeoutMs: 1500,
        onSample: s => { if (ws.readyState === 1) ws.send(JSON.stringify({ t: 'sample', target: t, ...s })); }
      }).then(r => { if (ws.readyState === 1) ws.send(JSON.stringify({ t: 'done', target: t, summary: r })); });
    }
    ws.readyState === 1 && ws.send(JSON.stringify({ t: 'all-done' }));
  });
  ws.on('message', raw => { try { if (JSON.parse(raw.toString()).t === 'stop') stopped = true; } catch { } });
  ws.on('close', () => { stopped = true; });
});

server.on('upgrade', (req, socket, head) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/ws/probe') return wssProbe.handleUpgrade(req, socket, head, ws => wssProbe.emit('connection', ws, req));
});

/* ============================== 启动 ============================== */
async function seedTemplates() {
  if ((await db.templatesList()).length) return;
  const t = [
    { name: '查看版本与序列号（全厂商通用）', vendor: '通用', category: '查询', commands: ['show version'], description: '获取设备型号、系统版本、序列号、运行时长' },
    { name: '端口状态总览 - Cisco', vendor: 'Cisco', category: '查询', commands: ['terminal length 0', 'show interfaces status'], description: '所有端口的 up/down、速率、VLAN' },
    { name: '端口状态总览 - 华为/H3C', vendor: '华为', category: '查询', commands: ['screen-length 0 temporary', 'display interface brief'], description: '华为 VRP / H3C Comware 通用' },
    { name: '接口错包统计', vendor: 'Cisco', category: '排障', commands: ['terminal length 0', 'show interfaces counters errors'], description: '定位网线、光模块、端口硬件问题' },
    { name: 'MAC 地址表', vendor: 'Cisco', category: '排障', commands: ['terminal length 0', 'show mac address-table'], description: '查终端接在哪个端口' },
    { name: 'ARP 表', vendor: 'Cisco', category: '排障', commands: ['terminal length 0', 'show ip arp'], description: '查 IP 与 MAC 对应关系' },
    { name: '生成树状态', vendor: 'Cisco', category: '排障', commands: ['terminal length 0', 'show spanning-tree summary'], description: '判断环路、根桥、阻塞端口' },
    { name: 'CPU 与内存 - Cisco', vendor: 'Cisco', category: '巡检', commands: ['show processes cpu sorted | exclude 0.00', 'show memory statistics'], description: '定期巡检 CPU 高占用进程' },
    { name: 'CPU 与内存 - 华为/H3C', vendor: '华为', category: '巡检', commands: ['display cpu-usage', 'display memory-usage'], description: '华为 VRP 巡检' },
    { name: '保存配置', vendor: '通用', category: '配置', danger: true, commands: ['write memory'], description: '华为/H3C 用 save，Cisco 用 write memory。高风险，会写启动配置' },
    { name: '端口描述批量规划（示例）', vendor: 'Cisco', category: '配置', commands: ['configure terminal', 'interface GigabitEthernet1/0/5', 'description PC-205 办公位', 'end'], description: '示例模板，使用前请核对端口号' },
    { name: 'FortiGate 会话与接口', vendor: 'Fortinet', category: '查询', commands: ['get system status', 'diagnose sys session stat', 'get system interface physical'], description: 'FortiGate 400F 常用巡检' },
    { name: 'Palo Alto 接口与会话', vendor: 'Palo Alto', category: '查询', commands: ['show system info', 'show interface all', 'show session info'], description: 'PA-820 常用巡检' }
  ];
  for (const x of t) await db.templatesCreate({ id: store.uid('tpl_'), createdAt: new Date().toISOString(), creator: 'system', ...x });
}

function lanIPs() {
  return netutil.localInterfaces().filter(i => !i.internal).map(i => i.address);
}

/* 自动打开浏览器。只在 listen 回调里调用 —— 此时端口一定已经绑定完成，
   不会出现「浏览器先打开、服务还没起来」导致的「无法访问此网站」假故障。
   策略：双击打包 exe 默认自动打开；node 直接跑（自检/开发）默认不打扰。
   可用环境变量强制：OPEN_BROWSER=1 开 / OPEN_BROWSER=0 关。 */
function openBrowser(url) {
  try {
    const cp = require('child_process');
    const [cmd, args] = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]]
      : process.platform === 'darwin' ? ['open', [url]]
        : ['xdg-open', [url]];
    const child = cp.spawn(cmd, args, { detached: true, stdio: 'ignore' });
    child.on('error', () => { });
    child.unref();
  } catch (e) {
    console.warn('[open] 未能自动打开浏览器：', e.message);
  }
}

(async function bootstrap() {
  /* 1) 选驱动并建好连接；2) 灌种子数据；3) 起旁路采集；4) 监听 */
  try { await db.init(); } catch (e) { console.error('[db] 初始化失败：', e.message); }
  try { await auth.ensureSeed(); } catch (e) { console.error('[db] 种子账号初始化失败：', e.message); }
  try { await seedTemplates(); } catch (e) { console.error('[db] 命令模板初始化失败：', e.message); }
  try { const cap = require('./capture'); await cap.start(); } catch (e) { console.error('[capture] 采集引擎启动失败：', e.message); }
  try { const sc = require('./scanner'); await sc.start(); } catch (e) { console.error('[scan] 扫描引擎启动失败：', e.message); }

/* 是否自动打开浏览器 */
function shouldOpenBrowser() {
  const v = process.env.OPEN_BROWSER;
  if (v === '0' || v === 'false') return false;
  if (v === '1' || v === 'true') return true;
  return !!process.pkg;   /* 双击 exe 默认开；node 直接跑（自检/开发）不打扰 */
}

/* 单次监听尝试（Promise 化，便于自动重试/换端口） */
function listenAttempt(port, host) {
  return new Promise((resolve, reject) => {
    const onOk = () => { server.removeListener('error', onErr); resolve(); };
    const onErr = e => { server.removeListener('listening', onOk); reject(e); };
    server.once('listening', onOk);
    server.once('error', onErr);
    server.listen(port, host);
  });
}

function printReady(port) {
  const ips = lanIPs();
  const scheme = useHttps ? 'https' : 'http';
  const line = '='.repeat(66);
  console.log('\n' + line);
  console.log('  网络运维与故障排除工具平台  netops-console  v1.1.1');
  console.log(line);
  console.log(`  传输协议        ${useHttps ? 'HTTPS 🔒' : 'HTTP（未启用 TLS）'}`);
  console.log(`  本机访问        ${scheme}://127.0.0.1:${port}`);
  console.log(`  localhost       ${scheme}://localhost:${port}  （IPv6 环境请用这个）`);
  ips.forEach(ip => console.log(`  局域网访问      ${scheme}://${ip}:${port}`));
  console.log('');
  console.log('  默认账号  admin / admin@123    （管理员，全部权限）');
  console.log('            ops   / ops@123      （运维，可终端与下发）');
  console.log('            audit / audit@123    （审计，只读与回放）');
  console.log('');
  console.log(`  数据目录  ${store.DATA_DIR}`);
  console.log(`  数据源    ${db.settingsSync()?.datasource?.mode === 'zabbix' ? 'Zabbix ' + db.settingsSync().datasource.zabbix.url : '演示模式（内置模拟数据）'}`);
  console.log(`  抓包引擎  ${runtimeTools.status().captureEngine}`);
  console.log(`  iperf3    ${netutil.findIperf() || '未检测到（已内置 TCP 吞吐引擎）'}`);
  console.log(`  启动日志  ${START_LOG}`);
  console.log(line + '\n');
  // 启动内置测速服务
  try { require('./api'); } catch { }
  // 服务确已就绪，此刻再打开浏览器，避免「浏览器先开、服务没起」的假故障
  if (shouldOpenBrowser()) openBrowser(`${scheme}://127.0.0.1:${port}`);
  /* 外部工具不阻塞平台启动；首次运行在后台静默检测/部署。 */
  setTimeout(() => runtimeTools.bootstrap().catch(e => console.error('[runtime] 自动部署失败：', e.message)), 1200);
}

/* 监听启动：IPv6 不可用自动退回 IPv4；端口被占用自动顺延，
   避免双击 exe 后因端口冲突「静默退出」，用户误以为 UI 打不开。 */
async function startListening() {
  let port = PORT;
  for (let i = 0; i < 25; i++) {
    for (const host of [HOST, '0.0.0.0']) {
      try {
        await listenAttempt(port, host);
        if (port !== PORT) console.warn(`[listen] 端口 ${PORT} 被占用，已自动改用 ${port}`);
        printReady(port);
        return;
      } catch (e) {
        /* 端口冲突 → 跳出内层，换下一个端口 */
        if (e && e.code === 'EADDRINUSE') break;
        /* IPv6 不可用等 → 换 IPv4(0.0.0.0) 再试 */
        if (e && (e.code === 'EAFNOSUPPORT' || e.code === 'EADDRNOTAVAIL' || e.code === 'EINVAL')) continue;
        return fatalExit(e);
      }
    }
    port++;
  }
  fatalExit(new Error(`连续尝试 25 个端口（${PORT}~${PORT + 24}）均被占用，请设置空闲端口后重试：set PORT=8899`));
}
startListening();

try {
  const cap = require('./capture'); cap.info().forEach(l => console.log(l));
  require('./scanner').info().forEach(l => console.log(l));
} catch { }
})();

process.on('SIGINT', async () => {
  console.log('\n正在保存数据并退出...');
  try { store.save(true); } catch { }
  try { await db.end(); } catch { }
  process.exit(0);
});
process.on('uncaughtException', e => console.error('[uncaught]', e));
process.on('unhandledRejection', e => console.error('[unhandled]', e));
