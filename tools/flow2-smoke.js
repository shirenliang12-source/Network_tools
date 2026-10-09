'use strict';
/**
 * 阶段二/三 链路自检：自定义协议 / PCAP 上传 / 通信关系图 / 路径测量 / AI 根因
 * 用法：node tools/flow2-smoke.js [baseUrl]   （需先启动服务）
 * 分两段：A 段引擎级（不依赖服务）；B 段接口级（需服务 + admin 登录）。
 */
const fs = require('fs');
const path = require('path');
const dpi = require('../server/dpi');
const dpiMetrics = require('../server/dpi-metrics');
const customProto = require('../server/custom-proto');
const flowGraph = require('../server/flow-graph');
const store = require('../server/store');
const multipart = require('../server/multipart');

const CAP_DIR = store.CAP_DIR;
let pass = 0, fail = 0, skip = 0;
const ok = (n, c, e) => { if (c) { pass++; console.log(`  ✓ ${n}${e ? ' — ' + e : ''}`); } else { fail++; console.log(`  ✗ ${n}${e ? ' — ' + e : ''}`); } };
const sk = (n, e) => { skip++; console.log(`  ⊘ ${n}${e ? ' — ' + e : ''}`); };

/* ------------------------- 构造测试 pcap ------------------------- */
function ethIpUdpTcp(srcIp, dstIp, sport, dport, payload, opts = {}) {
  const ipv4 = (s, d, proto, payloadLen) => {
    const h = Buffer.alloc(20); h[0] = 0x45; h[2] = 0; h[3] = 0;
    h.writeUInt16BE(20 + payloadLen, 2); h[8] = 64; h[9] = proto; h.writeUInt16BE(0, 10);
    const ip = (x) => x.split('.').map(Number), sa = ip(s), da = ip(d);
    for (let i = 0; i < 4; i++) { h[12 + i] = sa[i]; h[16 + i] = da[i]; }
    return h;
  };
  const tcp = (sp, dp, pl) => { const h = Buffer.alloc(20); h.writeUInt16BE(sp, 0); h.writeUInt16BE(dp, 2); h.writeUInt32BE(1, 4); h.writeUInt32BE(2, 8); h[12] = 0x50; h[13] = 0x02; h.writeUInt16BE(pl.length, 16); return Buffer.concat([h, pl]); };
  const udp = (sp, dp, pl) => { const h = Buffer.alloc(8); h.writeUInt16BE(sp, 0); h.writeUInt16BE(dp, 2); h.writeUInt16BE(8 + pl.length, 4); h.writeUInt16BE(8 + pl.length, 6); return Buffer.concat([h, pl]); };
  const eth = (pl) => { const h = Buffer.alloc(14); for (let i = 0; i < 6; i++) { h[i] = 0x00; h[6 + i] = 0x11; } h.writeUInt16BE(0x0800, 12); return Buffer.concat([h, pl]); };
  const isUdp = opts.udp;
  const seg = isUdp ? udp(sport, dport, payload) : tcp(sport, dport, payload);
  return eth(Buffer.concat([ipv4(srcIp, dstIp, isUdp ? 17 : 6, seg.length), seg]));
}
function buildCustomPcap(file, magicHex) {
  const parts = [Buffer.alloc(24)]; const g = parts[0];
  g.writeUInt32LE(0xa1b2c3d4, 0); g.writeUInt16LE(2, 4); g.writeUInt16LE(4, 6); g.writeUInt32LE(1, 20);
  const payload = Buffer.from(magicHex.replace(/\s+/g, ''), 'hex');
  const flows = [
    { src: '10.252.28.99', dst: '10.252.28.201', sport: 60001, dport: 9000, payload },
    { src: '10.252.28.99', dst: '10.252.28.202', sport: 60002, dport: 9100, payload }
  ];
  let t = 1760000000;
  flows.forEach((f) => {
    for (let k = 0; k < 3; k++) {
      const frame = ethIpUdpTcp(f.src, f.dst, f.sport + k, f.dport, payload);
      const rec = Buffer.alloc(16); rec.writeUInt32LE(t, 0); rec.writeUInt32LE(1000 * k, 4); rec.writeUInt32LE(frame.length, 8); rec.writeUInt32LE(frame.length, 12);
      parts.push(rec, frame);
    }
    t += 3;
  });
  fs.writeFileSync(file, Buffer.concat(parts));
  return file;
}

(async () => {
  console.log('\n=== A 段：引擎级自检（自定义协议 / 关系图 / 上传解析）===\n');

  // 1. customProto 校验/规范化
  const v1 = customProto.validate({ name: 'MyERP', ports: [9000] }); ok('validate 合法定义', v1.ok, v1.error);
  const v2 = customProto.validate({ name: 'Bad', ports: [] }); ok('validate 拒绝空条件', !v2.ok);
  const v3 = customProto.validate({ name: '', ports: [80] }); ok('validate 拒绝空名', !v3.ok);
  const norm = customProto.normalize({ name: 'My ERP', ports: '9000, 9100', ipFilter: '10\\.252', hexOffset: '0', hexBytes: 'deadbeef', color: '' });
  ok('normalize 解析端口串', norm.ports.length === 2 && norm.ports[0] === 9000, JSON.stringify(norm.ports));
  ok('normalize 补默认色', /^#[0-9a-f]{6}$/i.test(norm.color), norm.color);

  // 2. dpi 自定义协议命中（端口 + HEX 魔数）
  const cpFile = path.join(CAP_DIR, `flow2-${Date.now()}.pcap`);
  buildCustomPcap(cpFile, '4d517250'); // 'MQ Rp' 业务魔数
  const defs = [
    { name: 'MyERP-Sync', desc: '业务同步协议', ports: [9000, 9100], ipFilter: '', hexOffset: 0, hexBytes: '4d517250' }
  ];
  const parsed = dpi.parsePcapFile(cpFile, { customDefs: defs });
  ok('自定义协议 pcap 解析', parsed.sessions.length >= 2, `${parsed.sessions.length} 会话`);
  const hit = parsed.sessions.find(s => s.appProto === 'MyERP-Sync');
  ok('端口命中自定义协议', !!hit, hit ? `${hit.srcIp}:${hit.srcPort}→${hit.dstIp}:${hit.dstPort}` : '未命中');
  const magicDefs = [{ name: 'MagicProto', desc: '', ports: [], ipFilter: '', hexOffset: 0, hexBytes: '4d517250' }];
  const parsed2 = dpi.parsePcapFile(cpFile, { customDefs: magicDefs });
  const hit2 = parsed2.sessions.find(s => s.appProto === 'MagicProto');
  ok('HEX 魔数命中自定义协议', !!hit2);

  // 3. flowGraph.buildGraph
  const G = flowGraph.buildGraph(parsed.sessions, { buckets: 12 });
  ok('关系图产出节点', G.nodes.length === 3, `节点 ${G.nodes.length}`); // 2 源 + 2 目的，去重后 3（99 重复）
  ok('关系图产出边', G.links.length === 2, `边 ${G.links.length}`);
  ok('关系图时间帧', G.buckets.length === 12, `帧 ${G.buckets.length}`);
  const b0 = G.buckets[0];
  ok('首帧含活跃节点', b0.nodes.length > 0 && b0.links.length > 0, `节点 ${b0.nodes.length}/边 ${b0.links.length}`);
  const allSpan = G.buckets.reduce((a, b) => a + b.nodes.length, 0);
  ok('时间帧覆盖流量', allSpan >= 2, `累计点活跃 ${allSpan}`);

  // 4. multipart 解析（自实现）
  const boundary = '----flow2test';
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="t.pcap"\r\nContent-Type: application/octet-stream\r\n\r\n`),
    fs.readFileSync(cpFile),
    Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);
  const ct = `multipart/form-data; boundary=${boundary}`;
  const parts = multipart.parse(body, ct);
  ok('multipart 解析出文件', parts.length === 1 && parts[0].filename === 't.pcap', `parts=${parts.length}`);
  ok('multipart 保留文件内容', parts[0].data.equals(fs.readFileSync(cpFile)));

  // 5. dpiMetrics 聚合 + 自定义协议进入报表
  const m = dpiMetrics.computeFlowMetrics(parsed.sessions, parsed.packets);
  ok('metrics 协议构成含自定义协议', m.byProto.some(p => p.proto === 'MyERP-Sync'), m.byProto.map(p => p.proto).join(','));

  console.log('\n=== B 段：接口级自检（需运行中的服务 + admin）===\n');
  const BASE = (process.argv[2] || 'http://127.0.0.1:8799').replace(/\/+$/, '');
  let token = '';
  try {
    const lg = await fetch(BASE + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin@123' }) });
    const lj = await lg.json();
    token = lj.token || '';
    ok('admin 登录', !!token, lj.error || '');
  } catch (e) { sk('服务不可达，跳过 B 段', e.message); console.log(`\n结果：通过 ${pass} / 失败 ${fail} / 跳过 ${skip}`); process.exit(fail ? 1 : 0); }

  const H = () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer ' + token });
  const jpost = async (p, b) => { const r = await fetch(BASE + p, { method: 'POST', headers: H(), body: JSON.stringify(b) }); return r.json().catch(() => ({})); };
  const jget = async (p) => { const r = await fetch(BASE + p, { headers: H() }); return r.json().catch(() => ({})); };
  const jput = async (p, b) => { const r = await fetch(BASE + p, { method: 'PUT', headers: H(), body: JSON.stringify(b) }); return r.json().catch(() => ({})); };
  const jdel = async (p) => { const r = await fetch(BASE + p, { method: 'DELETE', headers: H() }); return r.json().catch(() => ({})); };

  // 6. 自定义协议 CRUD（建名为 MyERP-Sync，供后续 flow/metrics、flow/graph 命中）
  const created = await jpost('/api/custom-protocols', { name: 'MyERP-Sync', desc: 'smoke', ports: [9000], hexOffset: 0, hexBytes: '4d517250' });
  ok('创建自定义协议', created.ok && created.item && created.item.id, created.error || '');
  const cid = created.item ? created.item.id : '';
  const listed = await jget('/api/custom-protocols');
  ok('列表含新建协议', listed.ok && listed.list.some(x => x.id === cid), `${listed.list ? listed.list.length : 0} 条`);
  const upd = await jput('/api/custom-protocols/' + cid, { enabled: false });
  ok('更新协议(停用)', upd.ok && upd.item && upd.item.enabled === false);
  const upd2 = await jput('/api/custom-protocols/' + cid, { enabled: true });
  ok('更新协议(重新启用)', upd2.ok && upd2.item && upd2.item.enabled === true);

  // 7. flow/metrics（文件，应命中 MyERP-Sync）
  const cpName = path.basename(cpFile);
  const fm = await jpost('/api/flow/metrics', { file: cpName });
  ok('flow/metrics 解析文件', fm.ok && fm.totals && fm.totals.sessions >= 2, fm.error || `${fm.totals ? fm.totals.sessions : 0} 会话`);
  ok('flow/metrics 含自定义协议报表', fm.ok && fm.byProto && fm.byProto.some(p => p.proto === 'MyERP-Sync'));

  // 8. flow/graph
  const fg = await jpost('/api/flow/graph', { file: cpName, buckets: 12 });
  ok('flow/graph 产出图', fg.ok && fg.nodes && fg.nodes.length >= 3 && fg.links.length >= 2, fg.error || `${fg.nodes ? fg.nodes.length : 0}节点/${fg.links ? fg.links.length : 0}边`);
  ok('flow/graph 时间帧', fg.ok && fg.buckets && fg.buckets.length === 12);

  // 9. flow/upload（multipart）
  const upBody = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${cpName}"\r\nContent-Type: application/octet-stream\r\n\r\n`),
    fs.readFileSync(cpFile),
    Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);
  const up = await fetch(BASE + '/api/flow/upload', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': `multipart/form-data; boundary=${boundary}` }, body: upBody });
  const upj = await up.json().catch(() => ({}));
  ok('flow/upload 接收并解析', upj.ok && upj.metrics && upj.metrics.totals && upj.metrics.totals.sessions >= 2, upj.error || `会话 ${upj.metrics ? upj.metrics.totals.sessions : 0}`);
  if (upj.file) await jdel('/api/capture/files/' + encodeURIComponent(upj.file)).catch(() => {});

  // 10. flow/path（沙箱无 traceroute，应优雅失败而非 500）
  const fp = await jpost('/api/flow/path', { target: '8.8.8.8', rounds: 2, maxHops: 20 });
  ok('flow/path 调用不崩（优雅失败）', fp && (fp.ok === true || (fp.ok === false && fp.error)), fp.error || 'ok');

  // 11. ai/chat flow（开启 AI 规则引擎）
  await fetch(BASE + '/api/system/settings', { method: 'PUT', headers: H(), body: JSON.stringify({ ai: { enabled: true, provider: 'none' } }) }).catch(() => {});
  const ai = await fetch(BASE + '/api/ai/chat', { method: 'POST', headers: H(), body: JSON.stringify({ flow: { file: cpName }, messages: [{ role: 'user', content: '根因解读' }], useContext: true }) });
  const aij = await ai.json().catch(() => ({}));
  ok('ai/chat flow 返回解读', aij.ok && aij.answer && aij.answer.includes('流量'), aij.error || (aij.answer ? aij.answer.slice(0, 30) + '…' : '无'));

  // 清理测试文件 + 自定义协议
  try { fs.unlinkSync(cpFile); } catch {}
  if (cid) await jdel('/api/custom-protocols/' + cid).catch(() => {});

  console.log(`\n结果：通过 ${pass} / 失败 ${fail} / 跳过 ${skip}`);
  process.exit(fail ? 1 : 0);
})();
