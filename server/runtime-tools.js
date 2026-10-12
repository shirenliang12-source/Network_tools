'use strict';
/**
 * 平台运行时依赖管理器
 *
 * 原则：
 *  - 不把第三方二进制提交进仓库；从项目官网/Windows Package Manager 获取，避免二次分发。
 *  - Windows 首次启动后台静默部署，服务与 UI 不等待下载完成。
 *  - 每个外部安装包都校验 SHA-256（或交由 winget 校验清单），失败时保留内置实现。
 *  - Npcap 免费版不允许静默再分发，因此仅检测已有驱动；无驱动时抓包自动使用 Windows PktMon。
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const store = require('./store');

const DIR = path.join(store.DATA_DIR, 'runtime');
const CACHE_DIR = path.join(DIR, 'installers');
const STATE_FILE = path.join(DIR, 'state.json');
fs.mkdirSync(CACHE_DIR, { recursive: true });

const MANAGED = {
  wireshark: path.join(DIR, 'WiresharkPortable64', 'App', 'Wireshark', 'tshark.exe'),
  dumpcap: path.join(DIR, 'WiresharkPortable64', 'App', 'Wireshark', 'dumpcap.exe'),
  nmap: path.join(DIR, 'Nmap', 'nmap.exe')
};

const PACKAGES = {
  wireshark: {
    name: 'TShark / Wireshark', version: '4.6.9',
    url: 'https://www.wireshark.org/download/win64/WiresharkPortable64_4.6.9.paf.exe',
    sha256: '71bcfda9eefec8088faaf0b8e6d026369ea83ae6149cd0b76ccf0b3194240db0',
    file: 'WiresharkPortable64_4.6.9.paf.exe'
  },
  nmap: {
    name: 'Nmap', version: '7.991',
    url: 'https://nmap.org/dist/nmap-7.991-setup.exe',
    sha256: '93bfd37bdb31a7adfd932beb5dbce06025da691d01a0939e806ea704f7367657',
    file: 'nmap-7.991-setup.exe'
  }
};

let state = { busy: false, current: '', message: '', updatedAt: '', attempts: {}, log: [] };
try { state = { ...state, ...JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) }; } catch { }
state.busy = false;
let active = null;

function saveState() {
  state.updatedAt = new Date().toISOString();
  state.log = (state.log || []).slice(-30);
  try { fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf8'); } catch { }
}

function note(message, level = 'info') {
  state.message = message;
  state.log.push({ at: new Date().toISOString(), level, message });
  saveState();
  const fn = level === 'error' ? console.error : console.log;
  fn(`[runtime] ${message}`);
}

function resolveCommand(name, extra = []) {
  for (const p of extra) {
    try { if (p && fs.existsSync(p)) return p; } catch { }
  }
  try {
    const cmd = process.platform === 'win32' ? 'where.exe' : 'sh';
    const args = process.platform === 'win32' ? [name] : ['-lc', `command -v ${name}`];
    const r = spawnSync(cmd, args, { encoding: 'utf8', windowsHide: true, timeout: 2500 });
    const p = String(r.stdout || '').split(/\r?\n/).map(x => x.trim()).find(Boolean);
    if (r.status === 0 && p) return p;
  } catch { }
  return null;
}

function hasNpcap() {
  if (process.platform !== 'win32') return true;
  try {
    const r = spawnSync('sc.exe', ['query', 'npcap'], { encoding: 'utf8', windowsHide: true, timeout: 2500 });
    return r.status === 0 && /SERVICE_NAME:\s*npcap/i.test(String(r.stdout || ''));
  } catch { return false; }
}

function isElevated() {
  if (process.platform !== 'win32') return typeof process.getuid !== 'function' || process.getuid() === 0;
  try {
    const r = spawnSync('whoami.exe', ['/groups'], { encoding: 'utf8', windowsHide: true, timeout: 2500 });
    return r.status === 0 && /S-1-16-(12288|16384)/.test(String(r.stdout || ''));
  } catch { return false; }
}

function paths() { return { ...MANAGED, dir: DIR }; }

function status() {
  const tshark = resolveCommand(process.platform === 'win32' ? 'tshark.exe' : 'tshark', [MANAGED.wireshark,
    'C:\\Program Files\\Wireshark\\tshark.exe', 'C:\\Program Files (x86)\\Wireshark\\tshark.exe']);
  const nmap = resolveCommand(process.platform === 'win32' ? 'nmap.exe' : 'nmap', [MANAGED.nmap,
    'C:\\Program Files (x86)\\Nmap\\nmap.exe', 'C:\\Program Files\\Nmap\\nmap.exe']);
  const iperf = resolveCommand(process.platform === 'win32' ? 'iperf3.exe' : 'iperf3', [
    path.join(DIR, 'iperf3', 'iperf3.exe'),
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'Microsoft', 'WinGet', 'Packages', 'ar51an.iPerf3_Microsoft.Winget.Source_8wekyb3d8bbwe', 'iperf3.exe') : '',
    'C:\\Program Files\\iperf3\\iperf3.exe', 'C:\\iperf3\\iperf3.exe']);
  const pktmon = process.platform === 'win32' ? resolveCommand('pktmon.exe', ['C:\\Windows\\System32\\PktMon.exe']) : null;
  const npcap = hasNpcap();
  const elevated = isElevated();
  const tools = [
    { id: 'nmap', name: 'Nmap', kind: 'managed', ready: !!nmap, path: nmap || '', version: nmap ? PACKAGES.nmap.version : (npcap ? PACKAGES.nmap.version : `${PACKAGES.nmap.version} / 等待 Npcap`), fallback: '内置 TCP/ICMP/端口扫描器' },
    { id: 'tshark', name: 'TShark', kind: 'managed', ready: !!tshark, path: tshark || '', version: PACKAGES.wireshark.version, fallback: pktmon ? 'Windows PktMon 抓包' : '设备侧抓包' },
    { id: 'pktmon', name: 'Windows PktMon', kind: 'system', ready: !!pktmon && elevated, path: pktmon || '', version: pktmon ? (elevated ? '系统组件' : '已安装 / 需管理员权限') : '未安装', fallback: pktmon && !elevated ? '以管理员身份运行平台后自动启用' : '' },
    { id: 'npcap', name: 'Npcap 驱动', kind: 'external-license', ready: npcap, path: '', version: npcap ? '已检测' : '未安装', fallback: pktmon ? '无需安装：自动使用 PktMon' : '设备侧抓包' },
    { id: 'mtr', name: 'MTR', kind: 'builtin', ready: true, path: '平台内置逐跳探测引擎', version: '内置', fallback: '' },
    { id: 'iperf3', name: 'iperf3', kind: 'managed', ready: !!iperf, path: iperf || '', version: '3.22', fallback: '平台内置 TCP 吞吐引擎' },
    { id: 'net-snmp', name: 'Net-SNMP', kind: 'builtin', ready: true, path: 'Node net-snmp 3.29.2', version: '3.29.2', fallback: '' }
  ];
  const readyNames = tools.filter(x => x.ready).map(x => x.name).join('、');
  const displayMessage = state.busy ? state.message : `运行时检查完成：${readyNames || '内置回退引擎'}已就绪`;
  return { ...state, message: displayMessage, dir: DIR, autoInstall: process.env.AUTO_INSTALL_TOOLS !== '0', elevated, tools,
    captureReady: !!(tshark && npcap) || !!(pktmon && elevated),
    captureEngine: tshark && npcap ? 'TShark + Npcap' : (pktmon && elevated ? 'Windows PktMon + TShark 解析' : (pktmon ? 'PktMon 已安装（需管理员权限）' : (tshark ? 'TShark（仅离线解析）' : '设备侧抓包'))) };
}

function run(bin, args, timeoutMs = 10 * 60 * 1000) {
  return new Promise((resolve, reject) => {
    const p = spawn(bin, args, { windowsHide: true });
    let out = '';
    const add = d => { out = (out + d.toString()).slice(-12000); };
    p.stdout.on('data', add); p.stderr.on('data', add);
    const timer = setTimeout(() => { try { p.kill(); } catch { } reject(new Error('安装超时')); }, timeoutMs);
    p.once('error', e => { clearTimeout(timer); reject(e); });
    p.once('close', code => { clearTimeout(timer); code === 0 ? resolve(out) : reject(new Error(`安装程序退出码 ${code}：${out.slice(-500)}`)); });
  });
}

function download(url, dest, expectedSha, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 8) return reject(new Error('下载重定向次数过多'));
    const req = https.get(url, { headers: { 'User-Agent': 'netops-console/1.0' } }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return download(new URL(res.headers.location, url).toString(), dest, expectedSha, redirects + 1).then(resolve, reject);
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`下载失败 HTTP ${res.statusCode}`)); }
      const tmp = dest + '.part';
      const h = crypto.createHash('sha256');
      const f = fs.createWriteStream(tmp);
      let bytes = 0;
      res.on('data', d => { bytes += d.length; h.update(d); });
      res.pipe(f);
      const fail = e => { try { f.close(); fs.unlinkSync(tmp); } catch { } reject(e); };
      res.once('error', fail); f.once('error', fail);
      f.once('finish', () => {
        f.close(() => {
          const got = h.digest('hex').toLowerCase();
          if (expectedSha && got !== expectedSha.toLowerCase()) return fail(new Error(`SHA-256 校验失败（${got}）`));
          try { fs.renameSync(tmp, dest); resolve({ bytes, sha256: got }); } catch (e) { fail(e); }
        });
      });
    });
    req.setTimeout(120000, () => req.destroy(new Error('下载超时')));
    req.once('error', reject);
  });
}

async function installExe(id) {
  const pkg = PACKAGES[id];
  const oemNmap = id === 'nmap' && process.env.NMAP_OEM_INSTALLER && fs.existsSync(process.env.NMAP_OEM_INSTALLER)
    ? path.resolve(process.env.NMAP_OEM_INSTALLER) : '';
  const dest = oemNmap || path.join(CACHE_DIR, pkg.file);
  state.current = id;
  if (!oemNmap) note(`正在下载 ${pkg.name} ${pkg.version}（官网源）…`);
  if (!oemNmap && !fs.existsSync(dest)) await download(pkg.url, dest, pkg.sha256);
  else if (!oemNmap) {
    const got = crypto.createHash('sha256').update(fs.readFileSync(dest)).digest('hex');
    if (got.toLowerCase() !== pkg.sha256) { fs.unlinkSync(dest); await download(pkg.url, dest, pkg.sha256); }
  }
  if (id === 'nmap' && !oemNmap && !hasNpcap()) {
    throw new Error('官方免费版静默安装要求系统已存在 Npcap；安装包已校验并缓存，当前使用平台内置扫描器。可配置 NMAP_OEM_INSTALLER 启用 OEM 无人值守包');
  }
  note(`正在静默部署 ${pkg.name} ${pkg.version}…`);
  if (id === 'wireshark') {
    /* PortableApps 安装器：/S + DESTINATION 指父目录，安装器自行追加 WiresharkPortable64。 */
    const destination = DIR.endsWith(path.sep) ? DIR : DIR + path.sep;
    await run(dest, ['/S', `/DESTINATION=${destination}`]);
    if (!fs.existsSync(MANAGED.wireshark)) throw new Error('TShark 安装完成但未找到 tshark.exe');
  } else if (id === 'nmap') {
    const installDir = path.join(DIR, 'Nmap');
    const args = oemNmap
      ? ['/S', '/ZENMAP=NO', '/NDIFF=NO', '/REGISTERPATH=NO', `/D=${installDir}`]
      : ['/S', '/NPCAP=NO', '/ZENMAP=NO', '/NDIFF=NO', '/REGISTERPATH=NO', `/D=${installDir}`];
    await run(dest, args);
    if (!fs.existsSync(MANAGED.nmap)) throw new Error('Nmap 安装完成但未找到 nmap.exe');
  }
  if (!oemNmap) { try { fs.unlinkSync(dest); } catch { } }
  note(`${pkg.name} 已就绪`);
}

async function installIperf() {
  state.current = 'iperf3';
  note('正在通过 Windows Package Manager 静默部署 iperf3 3.22…');
  const winget = resolveCommand('winget.exe');
  if (!winget) throw new Error('未检测到 Windows Package Manager（winget）');
  await run(winget, ['install', '--id', 'ar51an.iPerf3', '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity'], 10 * 60 * 1000);
  note('iperf3 已就绪（若当前进程尚未发现，重启平台后自动生效）');
}

async function bootstrap({ force = false } = {}) {
  if (active) return active;
  if (process.platform !== 'win32' || process.env.AUTO_INSTALL_TOOLS === '0') return status();
  const last = Date.parse(state.lastAttemptAt || 0);
  if (!force && last && Date.now() - last < 6 * 3600 * 1000) return status();
  active = (async () => {
    state.busy = true; state.lastAttemptAt = new Date().toISOString(); saveState();
    const before = status();
    const jobs = [];
    if (!(before.tools.find(x => x.id === 'wireshark') || {}).ready) jobs.push(['wireshark', () => installExe('wireshark')]);
    if (!(before.tools.find(x => x.id === 'nmap') || {}).ready) jobs.push(['nmap', () => installExe('nmap')]);
    if (!(before.tools.find(x => x.id === 'iperf3') || {}).ready) jobs.push(['iperf3', installIperf]);
    if (!jobs.length) note('网络工具运行时均已就绪，无需安装');
    for (const [id, job] of jobs) {
      try { await job(); state.attempts[id] = { ok: true, at: new Date().toISOString(), error: '' }; }
      catch (e) { state.attempts[id] = { ok: false, at: new Date().toISOString(), error: e.message }; note(`${id} 自动部署失败，已启用内置回退：${e.message}`, 'error'); }
      saveState();
    }
    state.busy = false; state.current = ''; note('网络工具运行时检查完成');
    return status();
  })().finally(() => { active = null; });
  return active;
}

module.exports = { status, bootstrap, resolveCommand, hasNpcap, isElevated, paths, DIR };
