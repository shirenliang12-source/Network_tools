'use strict';
/* 前端静态自检：两类「浏览器才暴露、模板自检抓不到」的问题
   1) 页面用到的 CSS 类在 app.css 里没有定义  -> 布局塌陷 / 样式缺失
   2) 把 NC.api 当函数调用（应为 api.get/post/raw） -> 运行时 "api is not a function"
   用法: node tools/front-check.js */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CSS = path.join(ROOT, 'public', 'css', 'app.css');
const PAGES = path.join(ROOT, 'public', 'js', 'pages');

/* 工具类之外的结构类由组件/框架自带，允许列表 */
const ALLOW = new Set(['on', 'active', 'sel', 'hidden', 'primary', 'danger', 'ghost', 'sm', 'lg', 'xs',
  'ok', 'off', 'up', 'down', 'warn', 'info', 'high', 'medium', 'low', 'critical', 'disaster',
  'average', 'warning', 'information', 'sortable', 'compact', 'full', 'blue', 'green', 'amber', 'red', 'violet']);

const css = fs.readFileSync(CSS, 'utf8');
const defined = new Set();
for (const m of css.matchAll(/\.(-?[_a-zA-Z][\w-]*)/g)) defined.add(m[1]);

const files = fs.readdirSync(PAGES).filter(f => f.endsWith('.js')).map(f => path.join(PAGES, f));
files.push(path.join(ROOT, 'public', 'js', 'app.js'));

let missTotal = 0, apiTotal = 0;

for (const f of files) {
  const name = path.basename(f);
  const src = fs.readFileSync(f, 'utf8');

  /* ---- 1. 缺失的 CSS 类 ---- */
  const used = new Set();
  /* 注意：负向回顾 (?<![\\w:]) 排除 :class / v-bind:class 等动态绑定，
     这类值里出现的是 JS 表达式（如对象键名 dlRes），不是静态类名，不能误报 */
  for (const m of src.matchAll(/(?<![\\w:])class="([^"]*)"/g)) {
    for (const raw of m[1].split(/\s+/)) {
      const c = raw.replace(/^:/, '');
      /* 只接受「纯类名」token；:class="{...}" / :class="expr" 里的表达式一律跳过 */
      if (/^[a-zA-Z][\w-]*$/.test(c)) used.add(c);
    }
  }
  const miss = [...used].filter(c => !defined.has(c) && !ALLOW.has(c)).sort();
  if (miss.length) { console.log(`  ✗ ${name} — 缺 CSS 类：${miss.join(' ')}`); missTotal += miss.length; }

  /* ---- 2. api(...) 误用（NC.api 是对象，不是函数）---- */
  const lines = src.split('\n');
  lines.forEach((ln, i) => {
    for (const m of ln.matchAll(/(?<![.\w$])api\s*\(/g)) {
      console.log(`  ✗ ${name}:${i + 1} — 把 api 当函数调用，应改为 api.get/api.post/api.raw：${ln.trim().slice(0, 90)}`);
      apiTotal++;
    }
  });
}

console.log('');
if (!missTotal && !apiTotal) {
  console.log('=== 前端静态自检：通过（无缺类 / 无 api 误用）===');
  process.exit(0);
}
console.log(`=== 前端静态自检：失败（缺类 ${missTotal} 处 / api 误用 ${apiTotal} 处）===`);
process.exit(1);
