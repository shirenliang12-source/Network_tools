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
      env: Object.assign({}, process.env, { PORT: new URL(URL_).port || '8787', AUTO_INSTALL_TOOLS: '0', NO_ELEVATE: '1' }),
      stdio: ['ignore', 'ignore', 'ignore'], windowsHide: true,
    })
    : spawn(process.execPath, ['server/index.js'], {
      cwd: path.join(__dirname, '..'),
      env: Object.assign({}, process.env, { PORT: process.env.PORT || '8787', AUTO_INSTALL_TOOLS: '0' }),
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
  const routes = ['/alarms', '/devices', '/terminal', '/traffic', '/flow', '/flow-metrics', '/flow-graph', '/capture', '/custom-protocols', '/scan', '/diag', '/toolbox', '/wifi', '/speed', '/troubleshoot', '/deep-tools', '/topology', '/system', '/system?tab=health'];
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

  /* 命名插槽回归：快速扫描过去曾出现“只有标题和按钮、正文空白”。 */
  await ev(`NC.go('/scan')`); await new Promise(t => setTimeout(t, 1200));
  await ev(`(()=>{const b=[...document.querySelectorAll('button')].find(x=>x.innerText.includes('快速扫描'));if(b)b.click();return !!b})()`);
  await new Promise(t => setTimeout(t, 500));
  const quickModal = await ev(`JSON.stringify({
    shown: !!document.querySelector('.modal'),
    text: (document.querySelector('.modal-body')||{}).innerText || '',
    fields: document.querySelectorAll('.modal-body input,.modal-body select').length
  })`);
  const quickInfo = JSON.parse(quickModal.value);
  const quickOk = quickInfo.shown && quickInfo.fields >= 5 && quickInfo.text.includes('自定义参数');
  if (!quickOk) bad.push('/scan#quick');
  console.log(`  ${quickOk ? 'OK ' : '空!'} /scan#quick  fields=${quickInfo.fields}  ${quickInfo.text.replace(/\n/g, ' / ').slice(0,100)}`);

  /* 设备资产回归：来源必须明确、编辑抽屉必须可用、隐藏页签图表显示后必须铺满。 */
  await ev(`NC.go('/devices')`); await new Promise(t => setTimeout(t, 1400));
  await ev(`(()=>{const b=[...document.querySelectorAll('button')].find(x=>x.innerText.includes('编辑'));if(b)b.click();return !!b})()`);
  await new Promise(t => setTimeout(t, 400));
  const assetDrawer = JSON.parse((await ev(`JSON.stringify({
    source: (document.querySelector('.main')||{}).innerText?.includes('当前数据来源：演示数据') || false,
    shown: !!document.querySelector('.drawer'), fields: document.querySelectorAll('.drawer input,.drawer select,.drawer textarea').length,
    text: (document.querySelector('.drawer')||{}).innerText || ''
  })`)).value);
  const assetOk = assetDrawer.source && assetDrawer.shown && assetDrawer.fields >= 10 && assetDrawer.text.includes('恢复跟随数据源');
  if (!assetOk) bad.push('/devices#edit');
  console.log(`  ${assetOk ? 'OK ' : '空!'} /devices#edit fields=${assetDrawer.fields} source=${assetDrawer.source}`);

  await ev(`NC.go('/device/SW-ACC-03')`); await new Promise(t => setTimeout(t, 1500));
  await ev(`(()=>{const t=[...document.querySelectorAll('.tab')].find(x=>x.innerText.includes('流量趋势'));if(t)t.click();return !!t})()`);
  await new Promise(t => setTimeout(t, 1800));
  const chartInfo = JSON.parse((await ev(`JSON.stringify({widths:[...document.querySelectorAll('.card-body canvas')].map(x=>Math.round(x.getBoundingClientRect().width)), body:Math.round((document.querySelector('.main')||{}).getBoundingClientRect?.().width||0)})`)).value);
  const chartOk = chartInfo.widths.length >= 2 && chartInfo.widths.every(w => w > 600);
  if (!chartOk) bad.push('/device#traffic');
  console.log(`  ${chartOk ? 'OK ' : '窄!'} /device#traffic canvas=${chartInfo.widths.join(',')} main=${chartInfo.body}`);

  /* Zabbix 组同步回归：切换模式但不保存，确认组筛选与手动同步控件完整渲染。 */
  await ev(`NC.go('/system?tab=ds')`); await new Promise(t => setTimeout(t, 1200));
  await ev(`(()=>{const x=document.querySelector('input[type=radio][value=zabbix]');if(!x)return false;x.click();return true})()`);
  await new Promise(t => setTimeout(t, 300));
  const groupSync = JSON.parse((await ev(`JSON.stringify({
    text:(document.querySelector('.main')||{}).innerText||'',
    checks:document.querySelectorAll('input[type=checkbox]').length,
    mode:document.querySelector('input[type=radio][value=zabbix]')?.checked||false
  })`)).value);
  const groupSyncOk = groupSync.mode && groupSync.text.includes('Zabbix 主机组同步范围') && groupSync.text.includes('读取主机组') && groupSync.text.includes('立即同步');
  if (!groupSyncOk) bad.push('/system#zabbix-groups');
  console.log(`  ${groupSyncOk ? 'OK ' : '空!'} /system#zabbix-groups mode=${groupSync.mode}`);

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
    for (const r of ['/alarms', '/devices', '/devices#edit', '/device/SW-ACC-03#traffic', '/flow', '/topology', '/system', '/system#zabbix-groups', '/system?tab=health', '/toolbox', '/diag', '/scan#quick', 'login']) {
      if (r === '/devices#edit') {
        await ev(`NC.go('/devices')`); await new Promise(t => setTimeout(t, 1200));
        await ev(`(()=>{const b=[...document.querySelectorAll('button')].find(x=>x.innerText.includes('编辑'));if(b)b.click()})()`);
        await new Promise(t => setTimeout(t, 400));
      } else if (r === '/device/SW-ACC-03#traffic') {
        await ev(`NC.go('/device/SW-ACC-03')`); await new Promise(t => setTimeout(t, 1500));
        await ev(`(()=>{const t=[...document.querySelectorAll('.tab')].find(x=>x.innerText.includes('流量趋势'));if(t)t.click()})()`);
        await new Promise(t => setTimeout(t, 1800));
      } else if (r === '/scan#quick') {
        await ev(`NC.go('/scan')`); await new Promise(t => setTimeout(t, 1200));
        await ev(`(()=>{const b=[...document.querySelectorAll('button')].find(x=>x.innerText.includes('快速扫描'));if(b)b.click()})()`);
        await new Promise(t => setTimeout(t, 500));
        await ev(`(()=>{const x=[...document.querySelectorAll('.modal-body .result-box')].find(x=>x.innerText.includes('自定义参数'));if(x)x.click()})()`);
        await new Promise(t => setTimeout(t, 300));
      } else if (r === '/system#zabbix-groups') {
        await ev(`NC.go('/system?tab=ds')`); await new Promise(t => setTimeout(t, 1200));
        await ev(`(()=>{const x=document.querySelector('input[type=radio][value=zabbix]');if(x)x.click()})()`);
        await new Promise(t => setTimeout(t, 300));
      } else if (r !== 'login') { await ev(`NC.go('${r}')`); await new Promise(t => setTimeout(t, 2000)); }
      else await ev('NC.go(\'/alarms\'); NC.state.user=null');
      const shotName = r === '/system?tab=health' ? '_system-runtime'
        : r === '/scan#quick' ? '_scan-quick'
          : r === '/system#zabbix-groups' ? '_system-zabbix-groups'
          : r === '/devices#edit' ? '_devices-edit'
            : r === '/device/SW-ACC-03#traffic' ? '_device-traffic'
              : r.replace(/\//g, '_');
      await shot(shotName);
      if (r === '/scan#quick') {
        await ev(`(()=>{const is=[...document.querySelectorAll('.modal-body input')],ss=[...document.querySelectorAll('.modal-body select')];if(!is[0])return false;const set=(x,v)=>{x.value=v;x.dispatchEvent(new Event('input',{bubbles:true}));};set(is[0],'127.0.0.1');if(is[1])set(is[1],'8787');if(ss[1]){ss[1].value='icmp';ss[1].dispatchEvent(new Event('change',{bubbles:true}));}const b=[...document.querySelectorAll('.modal-foot button')].find(x=>x.innerText.includes('开始扫描'));if(b)b.click();return !!b})()`);
        for (let i = 0; i < 20; i++) {
          await new Promise(t => setTimeout(t, 500));
          const done = await ev(`(document.querySelector('.modal-body')||{}).innerText?.includes('扫描完成')||false`);
          if (done.value === true) break;
        }
        await shot('_scan-result');
      }
    }
    console.log('截图目录: ' + dir);
  }

  console.log('\n===== 控制台报错 =====');
  if (!logs.length) console.log('(无)'); else logs.slice(0, 30).forEach(l => console.log(' - ' + l));

  console.log('\n结论: ' + (JSON.parse(s1.value).appLen > 200 && !bad.length && !logs.length
    ? 'UI 正常渲染 ✔' : 'UI 异常 ✘' + (bad.length ? ' 空白页: ' + bad.join(',') : '')));

  ws.close(); chrome.kill(); setTimeout(() => { srv.kill(); process.exit(0); }, 300);
})().catch(e => { console.log('!! 探测异常: ' + e.message); try { srv.kill(); } catch { } process.exit(1); });
