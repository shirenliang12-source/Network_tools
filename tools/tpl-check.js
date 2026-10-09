'use strict';
/**
 * 前端模板编译自检：把 public/js 里每个页面组件的 template 用 @vue/compiler-dom 过一遍，
 * 把只有运行时才会暴露的模板语法错误（标签未闭合、v-if/v-for 结构非法、插值写错）拦在提交前。
 * 用法：node tools/tpl-check.js [页面文件 ...]
 */
const fs = require('fs');
const path = require('path');
const { compile } = require('@vue/compiler-dom');

const ROOT = path.join(__dirname, '..');
const pagesDir = path.join(ROOT, 'public/js/pages');
const files = (process.argv.slice(2).length
  ? process.argv.slice(2)
  : fs.readdirSync(pagesDir).map(f => path.join(pagesDir, f)));
for (const f of files) if (!fs.statSync(f).isFile()) { console.log(`  ! 跳过目录 ${f}`); files.splice(files.indexOf(f), 1); }

let pass = 0, fail = 0;
for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  const re = /template:\s*`([\s\S]*?)`\s*(?:,|\n\s*\})/g;
  let m, i = 0, bad = 0;
  while ((m = re.exec(src))) {
    i++;
    const tpl = m[1];
    const name = (src.match(/name:\s*'(\w+)'/) || [, path.basename(file)])[1];
    try {
      compile(tpl, { onError(e) { throw e; } });
    } catch (e) {
      bad++; fail++;
      const line = tpl.slice(0, Math.max(0, (e.loc ? e.loc.start.offset : 0))).split('\n').length;
      console.log(`  ✗ ${path.relative(ROOT, file)} #${i} (${name}) 第 ${line} 行 — ${e.message}`);
      continue;
    }
  }
  if (!bad) { pass++; console.log(`  ✓ ${path.relative(ROOT, file)} — ${i} 个模板编译通过`); }
}
console.log(`\n=== 模板自检：${pass} 个文件通过，${fail} 个失败 ===`);
process.exit(fail ? 1 : 0);
