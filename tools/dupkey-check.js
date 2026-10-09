'use strict';
/**
 * 重复键自检：对象的重复属性键在 JS 里会被静默覆盖（后者胜），
 * 最典型的就是组件里写了两个 components: { ... }，
 * 结果前面的注册被吞掉 —— 例如 Shell 里 Login 被覆盖后，首页渲染成空 <login> 白屏。
 * 这类错误没有任何运行时报错（生产版 Vue 还会吞掉 "Failed to resolve component" 警告），
 * 只能靠静态扫描拦住。用 @babel/parser 做真实 AST 分析，避免注释/字符串造成的误报。
 *
 * 用法: node tools/dupkey-check.js [文件 ...]    默认扫 public/js 下全部 js
 */
const fs = require('fs');
const path = require('path');
const parser = require('@babel/parser');

const ROOT = path.join(__dirname, '..');
const files = (() => {
  const given = process.argv.slice(2);
  if (given.length) return given;
  const out = [];
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
    const p = path.join(dir, d.name);
    if (d.isDirectory()) walk(p); else if (d.name.endsWith('.js')) out.push(p);
  });
  walk(path.join(ROOT, 'public/js'));
  return out;
})();

function collectDups(node, hits, file) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { node.forEach(n => collectDups(n, hits, file)); return; }
  if (typeof node.type !== 'string') return;

  if (node.type === 'ObjectExpression') {
    const seen = new Map();
    for (const p of node.properties) {
      let name = null, line = 0;
      if (p.type === 'ObjectProperty' || p.type === 'ObjectMethod') {
        const k = p.key;
        if (k && k.type === 'Identifier') name = k.name;
        else if (k && k.type === 'StringLiteral') name = k.value;
        else if (k && k.type === 'NumericLiteral') name = String(k.value);
      }
      line = (node.loc && node.loc.start.line) || 0;
      if (name !== null) {
        if (seen.has(name)) hits.push({ key: name, line, first: seen.get(name) });
        else seen.set(name, line);
      }
    }
  }
  for (const v of Object.values(node)) {
    if (v && typeof v === 'object' && (typeof v.type === 'string' || Array.isArray(v))) collectDups(v, hits, file);
  }
}

let pass = 0, fail = 0;
for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  let ast;
  try { ast = parser.parse(src, { sourceType: 'script', errorRecovery: false }); }
  catch (e) { fail++; console.log(`  ✗ ${path.relative(ROOT, file)} — 解析失败: ${e.message}`); continue; }

  const hits = [];
  collectDups(ast, hits, file);
  if (!hits.length) { pass++; continue; }
  fail++;
  console.log(`  ✗ ${path.relative(ROOT, file)}`);
  [...new Map(hits.map(h => [h.key + '@' + h.line, h])).values()]
    .forEach(h => console.log(`      重复键 "${h.key}" 第 ${h.line} 行（后者覆盖前者）`));
}
console.log(`\n=== 重复键自检：${pass} 个文件通过，${fail} 个失败 ===`);
process.exit(fail ? 1 : 0);
