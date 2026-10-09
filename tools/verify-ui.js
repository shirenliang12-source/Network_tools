'use strict';
/* 端到端 UI 验证：起服务 -> 无头浏览器加载 -> 抓控制台报错 -> 登录 -> 再验渲染
   用法: node tools/verify-ui.js [url]       默认 http://127.0.0.1:8787/
   说明: 本进程内拉起服务并自行收尾，避免遗留常驻进程。 */
const { spawn } = require('child_process');
const os = require('os');
const path = require('path');
const fs = require('fs');

/* 本机回环访问不该走代理，否则 chrome 拉页面会卡死；此处就地摘掉代理变量 */
for (const k of ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY']) {
  try { delete process.env[k]; } catch { }
}
const URL_ = process.argv[2] || 'http://127.0.0.1:8787/';
const CHROME = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
].find(p => fs.existsSync(p));

const PORT = 9341;
const PROF = path.join(os.tmpdir(), 'nc-verify-ui-prof');
/* USE_EXE=1 时验证打包产物 dist\netops-console.exe 本身，否则验证源码服务 */
/* SKIP_SRV=1 时复用已经跑在 URL 上的外部服务，不自己拉起 */
const srv = process.env.SKIP_SRV === '1'
  ? { kill() { } }
  : process.env.USE_EXE === '1'
    ? spawn(path.join(__dirname, '..', 'dist', 'netops-console.exe'), [], {
      env: Object.assign({}, process.env, { PORT: new URL(URL_).port || '8787' }),
      stdio: ['ignore', 'ignore', 'ignore'], windowsHide: true,
    })
    : spawn(process.execPath, ['server/index.js'], {
      cwd: path.join(__dirname, '..'),
      env: Object.assign({}, process.env, { PORT: process.env.PORT || '8787' }),
      stdio: ['ignore', 'ignore', 'ignore'],
    });
const fail = (msg, code = 1) => { console.log('!! ' + msg); try { srv.kill(); } catch { } process.exit(code); };

(async () => {
  /* ---------- 1. 等服务就绪 ---------- */
  let up = false;
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch('http://127.0.0.1:' + (new URL(URL_).port || 80) + '/healthz');
      if (r.ok) { up = true; break; }
    } catch { }
    await new Promise(r => setTimeout(r, 300));
  }
  if (!up) fail('服务未能在 12s 内就绪');

  if (!CHROME) fail('找不到 Chrome/Edge，无法做浏览器验证');
  fs.rmSync(PROF, { recursive: true, force: true });

  /* ---------- 2. 拉起无头浏览器 ---------- */
  const chrome = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run', '--disable-extensions',
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${PROF}`,
    '--window-size=1600,1000', 'about:blank',
  ], { stdio: 'ignore' });

  let targets = null;
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/json/list`);
      targets = await r.json();
      if (targets && targets.length) break;
    } catch { }
    await new Promise(r => setTimeout(r, 300));
  }
  if (!targets || !targets.length) { chrome.kill(); fail('CDP 未就绪'); }

  const page = targets.find(t => t.type === 'page') || targets[0];
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0;
  const send = (method, params = {}) => ws.send(JSON.stringify({ id: ++id, method, params }));

  /* 每条日志标注当时所处路由，便于精确定位是哪个页面的模板报错 */
  const logs = [], pending = new Map();
  let at = '(初始)';
  const put = (line) => logs.push(`[${at}] ` + line);
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method === 'Runtime.exceptionThrown') {
      const d = m.params.exceptionDetails;
      put('[异常] ' + ((d.exception && d.exception.description) || d.text) +
        '\n        at ' + (d.url || '?') + ':' + ((d.lineNumber | 0) + 1));
    }
    if (m.method === 'Log.entryAdded') {
      const e = m.params.entry;
      if (e.level === 'error' || e.level === 'warning') put(`[${e.level}] ${e.text} ${e.url || ''}:${(e.lineNumber | 0) + 1}`);
    }
    if (m.method === 'Runtime.consoleAPICalled' && (m.params.type === 'error' || m.params.type === 'warning')) {
      put('[console.' + m.params.type + '] ' +
        (m.params.args || []).map(a => a.value !== undefined ? a.value : (a.description || a.type)).join(' '));
    }
    if (m.method === 'Network.loadingFailed') put('[资源失败] ' + m.params.errorText);
  };
  await new Promise(res => { ws.onopen = res; });
  send('Runtime.enable'); send('Log.enable'); send('Page.enable'); send('Network.enable');

  /* 统一的请求-响应分发：不能再各自覆盖 ws.onmessage，否则会丢掉后续的控制台报错 */
  const rpc = (method, params) => new Promise(res => {
    const myId = ++id;
    pending.set(myId, res);
    ws.send(JSON.stringify({ id: myId, method, params }));
  });
  const ev = async (expression, awaitPromise = false) => {
    const m = await rpc('Runtime.evaluate', { expression, returnByValue: true, awaitPromise });
    if (m.error) return { value: 'RPC_ERROR ' + JSON.stringify(m.error).slice(0, 160) };
    if (m.result && m.result.exceptionDetails) {
      const d = m.result.exceptionDetails;
      return { value: 'EVAL_ERROR ' + ((d.exception && d.exception.description) || d.text || '').slice(0, 200) };
    }
    return (m.result && m.result.result) || { value: undefined };
  };

  /* ---------- 3. 首屏 ---------- */
  send('Page.navigate', { url: URL_ });
  await new Promise(r => setTimeout(r, 6000));

  const snap = (label) => ev(`JSON.stringify({
    vue: Vue && Vue.version,
    nc: typeof window.NC,
    pages: window.PAGES ? Object.keys(window.PAGES).length : 0,
    user: !!(window.NC && window.NC.state && window.NC.state.user),
    token: !!(window.NC && window.NC.state && window.NC.state.token),
    stillLogin: !!document.querySelector('.login-wrap'),
    appLen: (document.getElementById('app')||{}).innerHTML ? document.getElementById('app').innerHTML.length : 0,
    appHTML: ((document.getElementById('app')||{}).innerHTML||'').slice(0, 180),
    nav: document.querySelectorAll('.sidebar-nav .nav-item').length,
    title: (document.querySelector('.login-card h1')||{}).textContent || null,
    bodyLen: document.body.innerHTML.length
  })`);

  const show = (v) => { try { return JSON.stringify(JSON.parse(v), null, 2); } catch { return String(v); } };

  const s1 = await snap();
  console.log('===== 首屏（未登录）=====');
  console.log(show(s1.value));

  /* ---------- 4. 真实 UI 登录（填表 + 提交，不走内部 API） ---------- */
  const lg = await ev(`(async()=>{
    const f = document.querySelector('.login-form form');
    if (!f) return 'no-form';
    const inp = f.querySelectorAll('input.inp');
    const set = (el, v) => { el.value = v; el.dispatchEvent(new Event('input', {bubbles:true})); };
    set(inp[0], 'admin'); set(inp[1], 'admin@123');
    await new Promise(r => setTimeout(r, 200));
    f.dispatchEvent(new Event('submit', {bubbles:true, cancelable:true}));
    await new Promise(r => setTimeout(r, 2500));
    return 'submitted';
  })()`, true);
  console.log('\nUI 登录动作:', lg.value);

  await new Promise(r => setTimeout(r, 4000));
  const s2 = await snap();
  console.log('\n===== 登录后 =====');
  console.log(show(s2.value));

  /* ---------- 5. 逐页点一遍 ---------- */
  const routes = ['/screen', '/devices', '/terminal', '/traffic', '/flow', '/flow-metrics', '/flow-graph', '/capture', '/custom-protocols', '/scan', '/diag', '/toolbox', '/wifi', '/speed', '/alarms', '/troubleshoot', '/deep-tools', '/topology', '/system'];
  const bad = [];
  for (const r of routes) {
    at = r;
    await ev(`NC.go('${r}')`);
    let o = null, t0 = Date.now();
    /* 页面内容是异步取数后渲染的，轮询等它涨起来，最多 8 秒 */
    for (let i = 0; i < 16; i++) {
      await new Promise(t => setTimeout(t, 500));
      const d = await ev(`JSON.stringify({
        len: document.getElementById('app').innerHTML.length,
        mainLen: (document.querySelector('.main')||{innerHTML:''}).innerHTML.length,
        main: (document.querySelector('.main')||{}).innerText ? document.querySelector('.main').innerText.slice(0,60) : ''
      })`);
      o = JSON.parse(d.value);
      if (o.mainLen > 1500) break;
    }
    const waited = Date.now() - t0;
    const tag = o.mainLen > 1500 ? 'OK ' : '空!';
    if (o.mainLen <= 1500) bad.push(r);
    console.log(`  ${tag} ${r.padEnd(10)} ${String(waited).padStart(5)}ms len=${String(o.len).padStart(6)}  ${o.main.replace(/\n/g, ' / ')}`);
  }

  /* ---------- 6. 出图取证 ---------- */
  if (process.env.SHOTS === '1') {
    const dir = path.join(__dirname, '..', 'dist', 'ui-shot');
    fs.mkdirSync(dir, { recursive: true });
    const shot = async (name) => {
      const m0 = await rpc('Page.captureScreenshot', { format: 'png' });
      if (!m0.result || !m0.result.data) { console.log('  截图失败 ' + name + ': ' + JSON.stringify(m0).slice(0, 200)); return; }
      fs.writeFileSync(path.join(dir, name + '.png'), Buffer.from(m0.result.data, 'base64'));
      console.log('  截图 ' + name + '.png');
    };
    for (const r of ['/screen', '/devices', '/flow', '/topology', '/system', '/toolbox', '/diag', 'login']) {
      if (r !== 'login') { await ev(`NC.go('${r}')`); await new Promise(t => setTimeout(t, 2000)); }
      else await ev('NC.go(\'/screen\'); NC.state.user=null');
      await shot(r.replace(/\//g, '_'));
    }
    console.log('截图目录: ' + dir);
  }

  console.log('\n===== 控制台报错 =====');
  if (!logs.length) console.log('(无)'); else logs.slice(0, 30).forEach(l => console.log(' - ' + l));

  console.log('\n结论: ' + (JSON.parse(s1.value).appLen > 200 && !bad.length && !logs.length
    ? 'UI 正常渲染 ✔' : 'UI 异常 ✘' + (bad.length ? ' 空白页: ' + bad.join(',') : '')));

  ws.close(); chrome.kill(); setTimeout(() => { srv.kill(); process.exit(0); }, 300);
})().catch(e => { console.log('!! 探测异常: ' + e.message); try { srv.kill(); } catch { } process.exit(1); });
