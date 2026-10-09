'use strict';
/* 单页截图取证：复用 verify-ui 的 CDP 方式，只拍指定路由，便于视觉校对
   用法: node tools/shot-page.js /toolbox [outName]
   前提: 已在 http://127.0.0.1:8787 跑着服务（SKIP_SRV 模式） */
const { spawn } = require('child_process');
const os = require('os');
const path = require('path');
const fs = require('fs');

for (const k of ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY']) {
  try { delete process.env[k]; } catch { }
}
const ROUTE = process.argv[2] || '/toolbox';
const NAME = process.argv[3] || ROUTE.replace(/[^\w]/g, '_');
const BASE = 'http://127.0.0.1:8787/';
const CHROME = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
].find(p => fs.existsSync(p));
const PORT = 9355;
const PROF = path.join(os.tmpdir(), 'nc-shot-prof');
const OUT = path.join(__dirname, '..', 'dist', 'ui-shot');

(async () => {
  if (!CHROME) { console.log('找不到 Chrome/Edge'); process.exit(1); }
  fs.rmSync(PROF, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });

  const chrome = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run', '--disable-extensions',
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${PROF}`,
    '--window-size=1440,900', 'about:blank',
  ], { stdio: 'ignore' });

  let targets = null;
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(`http://127.0.0.1:${PORT}/json/list`); targets = await r.json(); if (targets && targets.length) break; } catch { }
    await new Promise(r => setTimeout(r, 300));
  }
  if (!targets || !targets.length) { chrome.kill(); console.log('CDP 未就绪'); process.exit(1); }
  const page = targets.find(t => t.type === 'page') || targets[0];
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0; const pending = new Map();
  const rpc = (method, params) => new Promise(res => { const my = ++id; pending.set(my, res); ws.send(JSON.stringify({ id: my, method, params })); });
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
  await new Promise(res => { ws.onopen = res; });
  rpc('Runtime.enable'); rpc('Page.enable');
  const ev = async (expression, awaitPromise = false) => {
    const m = await rpc('Runtime.evaluate', { expression, returnByValue: true, awaitPromise });
    return (m.result && m.result.result) || { value: undefined };
  };
  const shot = async (name) => {
    const m = await rpc('Page.captureScreenshot', { format: 'png' });
    if (!m.result || !m.result.data) { console.log('截图失败 ' + name); return; }
    fs.writeFileSync(path.join(OUT, name + '.png'), Buffer.from(m.result.data, 'base64'));
    console.log('  截图 ' + name + '.png');
  };

  rpc('Page.navigate', { url: BASE });
  await new Promise(r => setTimeout(r, 5000));
  await ev(`(async()=>{
    const f=document.querySelector('.login-form form'); if(!f) return 'no-form';
    const inp=f.querySelectorAll('input.inp'); const set=(el,v)=>{el.value=v;el.dispatchEvent(new Event('input',{bubbles:true}));};
    set(inp[0],'admin'); set(inp[1],'admin@123');
    await new Promise(r=>setTimeout(r,200));
    f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
    await new Promise(r=>setTimeout(r,2500)); return 'ok';
  })()`, true);
  await new Promise(r => setTimeout(r, 2500));

  const nav = await ev(`(()=>{ location.hash = '#${ROUTE}'; return location.hash; })()`);
  console.log('导航 hash -> ' + nav.value);
  await new Promise(r => setTimeout(r, 3500));
  const st = await ev(`JSON.stringify({hash:location.hash, route:(window.NC&&NC.state&&NC.state.route), hasTb:!!document.querySelector('.tb'), comps:Object.keys(window.PAGES||{}).length})`);
  console.log('路由状态: ' + st.value);

  /* 布局取证：主区宽度、左栏宽度、是否溢出 */
  const diag = await ev(`JSON.stringify((()=>{
    const tb=document.querySelector('.tb'), side=document.querySelector('.tb-side'), main=document.querySelector('.tb-main');
    const items=document.querySelectorAll('.tb-item').length;
    const groups=document.querySelectorAll('.tb-group').length;
    return { tbW: tb?Math.round(tb.getBoundingClientRect().width):0,
      sideW: side?Math.round(side.getBoundingClientRect().width):0,
      mainW: main?Math.round(main.getBoundingClientRect().width):0,
      items, groups,
      bodyH: document.body.scrollHeight,
      mainText: (main&&main.innerText||'').slice(0,60).replace(/\\n/g,' / ') };
  })())`);
  console.log('布局诊断: ' + diag.value);

  /* 可选：点击含指定文案的按钮后截图（如 CLICK_TEXT=开始扫描 触发真实扫描） */
  if (process.env.CLICK_TEXT) {
    const c = await ev(`(()=>{ const b=[...document.querySelectorAll('button,.btn')].find(e=>e.innerText.trim().includes(${JSON.stringify(process.env.CLICK_TEXT)})); if(!b) return 'not-found'; b.click(); return 'clicked'; })()`);
    console.log('点击「' + process.env.CLICK_TEXT + '」-> ' + c.value);
    await new Promise(r => setTimeout(r, 6000));
  }

  await shot(NAME);
  await shot(NAME + '_full');

  /* 可选：选中某个工具并执行，用于校对结果区（.kv / .tb-notes / 表格）渲染 */
  if (process.env.PICK) {
    const picked = await ev(`(()=>{
      const el=[...document.querySelectorAll('.tb-item')].find(e=>e.innerText.includes(${JSON.stringify(process.env.PICK)}));
      if(!el) return 'not-found'; el.click(); return 'clicked';
    })()`);
    console.log('选中工具 ' + process.env.PICK + ' -> ' + picked.value);
    await new Promise(r => setTimeout(r, 800));
    const ran = await ev(`(()=>{ const b=[...document.querySelectorAll('.tb-main .btn.primary')].find(e=>e.innerText.includes('执行')); if(!b) return 'no-btn'; b.click(); return 'run'; })()`);
    console.log('执行 -> ' + ran.value);
    await new Promise(r => setTimeout(r, 4000));
    await shot(NAME + '_result');
    const resLen = await ev(`(document.querySelector('.tb-main').innerText||'').length`);
    console.log('结果区文本长度: ' + resLen.value);
  }

  ws.close(); chrome.kill(); process.exit(0);
})().catch(e => { console.log('!! ' + e.message); process.exit(1); });
