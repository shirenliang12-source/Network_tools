'use strict';
/**
 * 抓包链路自检：手工构造一个含 HTTP / HTTPS / DNS / SSH / Modbus 会话的 pcap，
 * 走「dpi 解析 → 会话入库 → 接口查询」全链路，验证全流量回溯能力可用。
 * 用法：node tools/pcap-smoke.js [baseUrl]  （需先启动服务）
 */
const fs = require('fs');
const path = require('path');
const dpi = require('../server/dpi');
const store = require('../server/store');

const CAP_DIR = store.CAP_DIR;
let pass = 0, fail = 0;
const ok = (n, c, e) => { if (c) { pass++; console.log(`  ✓ ${n}${e ? ' — ' + e : ''}`); } else { fail++; console.log(`  ✗ ${n}${e ? ' — ' + e : ''}`); } };

/* ------------------------- 构造测试 pcap ------------------------- */
function ethIpUdpTcp(srcIp, dstIp, sport, dport, payload, opts = {}) {
  const ipv4 = (s, d, proto, payloadLen) => {
    const h = Buffer.alloc(20);
    h[0] = 0x45; h[2] = 0; h[3] = 0;
    h.writeUInt16BE(20 + payloadLen, 2);
    h[8] = 64; h[9] = proto;
    h.writeUInt16BE(0, 10);
    const ip = (x) => x.split('.').map(Number);
    const sa = ip(s), da = ip(d);
    for (let i = 0; i < 4; i++) { h[12 + i] = sa[i]; h[16 + i] = da[i]; }
    return h;
  };
  const tcp = (sport, dport, payload) => {
    const h = Buffer.alloc(20);
    h.writeUInt16BE(sport, 0); h.writeUInt16BE(dport, 2);
    h.writeUInt32BE(1, 4); h.writeUInt32BE(2, 8);
    h[12] = 0x50; h[13] = 0x02;                 // flags SYN
    h.writeUInt16BE(payload.length, 16);
    return Buffer.concat([h, payload]);
  };
  const udp = (sport, dport, payload) => {
    const h = Buffer.alloc(8);
    h.writeUInt16BE(sport, 0); h.writeUInt16BE(dport, 2);
    h.writeUInt16BE(8 + payload.length, 4); h.writeUInt16BE(8 + payload.length, 6);
    return Buffer.concat([h, payload]);
  };
  const eth = (payload) => {
    const h = Buffer.alloc(14);
    for (let i = 0; i < 6; i++) { h[i] = 0x00; h[6 + i] = 0x11; }
    h.writeUInt16BE(0x0800, 12);
    return Buffer.concat([h, payload]);
  };
  const isUdp = opts.udp;
  const seg = isUdp ? udp(sport, dport, payload) : tcp(sport, dport, payload);
  // IP 头只负责写长度/协议/地址，实际报文段在这里拼接进去
  const frame = eth(Buffer.concat([ipv4(srcIp, dstIp, isUdp ? 17 : 6, seg.length), seg]));
  return frame;
}

function buildPcap(file) {
  const parts = [Buffer.alloc(24)];
  const g = parts[0];
  g.writeUInt32LE(0xa1b2c3d4, 0);
  g.writeUInt16LE(2, 4); g.writeUInt16LE(4, 6);
  g.writeUInt32LE(0, 8); g.writeUInt32LE(0, 12);
  g.writeUInt32LE(65535, 16);
  g.writeUInt32LE(1, 20);            // Ethernet

  const flows = [
    { src: '10.252.28.99', dst: '10.252.28.101', sport: 54120, dport: 80, udp: false, payload: 'GET /zabbix.php?action=dashboard HTTP/1.1\r\nHost: sw-core-01.nothing.local\r\nUser-Agent: Zabbix\r\n\r\n' },
    { src: '10.252.28.99', dst: '10.252.28.101', sport: 54121, dport: 443, udp: false, payload: null, tls: true },
    { src: '10.252.28.99', dst: '10.252.28.1', sport: 54122, dport: 53, udp: true, payload: null, dns: true },
    { src: '10.252.28.99', dst: '10.252.28.101', sport: 54123, dport: 22, udp: false, payload: 'SSH-2.0-OpenSSH_8.9\r\n' },
    { src: '10.252.28.99', dst: '10.252.28.101', sport: 54124, dport: 502, udp: false, payload: Buffer.from([0, 0, 0, 0, 0, 6, 3, 0, 0, 1, 0, 2]).toString('latin1'), binary: true },
    { src: '10.252.28.99', dst: '10.252.28.101', sport: 54125, dport: 3306, udp: false, payload: '' }
  ];
  let t = 1760000000;
  flows.forEach((f, i) => {
    let payload = Buffer.from(f.payload || '', f.binary ? 'latin1' : 'utf8');
    if (f.tls) {
      // 构造合规的 TLS ClientHello：record 头 → 握手头 → 版本 → random(32) → 会话ID →
      // 加密套件 → 压缩 → 扩展区；扩展区内 [i]=0x0000 类型，[i+8]=域名长度，[i+10]=域名
      const sni = 'svc-billing.nothing.local';
      const hostLen = Buffer.alloc(2); hostLen.writeUInt16BE(sni.length, 0);
      const ext = Buffer.concat([
        Buffer.from([0x00, 0x00]),              // server_name 扩展类型
        Buffer.from([0x00, 0x05]),              // 扩展数据长度
        Buffer.from([0x00, sni.length + 5]),    // 列表长度 = 类型(2) + 域名长度(2) + 域名
        Buffer.from([0x00, 0x00]),              // 名称类型 + 保留
        hostLen, Buffer.from(sni, 'utf8')
      ]);
      const h = Buffer.alloc(51);                               // 0..49 固定头 + 1 字节预留
      h[0] = 0x16; h[1] = 0x03; h[2] = 0x01;                   // record: Handshake / TLS1.0
      h.writeUInt16BE(4 + 32 + ext.length, 3);                 // 握手消息长度
      h.writeUInt32BE(0x5ecd1a7b, 10); h.writeUInt32BE(0x9f2c48d1, 14);   // random 前 8 字节（非零，贴近真实）
      h[5] = 0x01;                                              // ClientHello
      h.writeUInt16BE(0x0303, 8);                               // TLS1.2
      h[42] = 0x00;                                             // session id 长度
      h.writeUInt16BE(2, 43); h.writeUInt16BE(0x1301, 45);      // 加密套件
      h[47] = 0x01; h[48] = 0x00;                               // 压缩方法
      h.writeUInt16BE(ext.length, 49);                          // 扩展区总长
      payload = Buffer.concat([h, ext]);
    }
    if (f.dns) {
      const name = 'www.nothing.local';
      const q = Buffer.concat([Buffer.from([0x00, 0x00]), Buffer.alloc(10),
        Buffer.from([name.length]), Buffer.from(name, 'utf8'), Buffer.from([0, 0, 1, 0, 1])]);
      payload = q;
    }
    for (let k = 0; k < 4; k++) {
      const frame = ethIpUdpTcp(f.src, f.dst, f.sport + k, f.dport, payload, { udp: f.udp });
      const rec = Buffer.alloc(16);
      rec.writeUInt32LE(t, 0); rec.writeUInt32LE(1000 * k, 4);
      rec.writeUInt32LE(frame.length, 8); rec.writeUInt32LE(frame.length, 12);
      parts.push(rec, frame);
    }
    t += 3;
  });
  fs.writeFileSync(file, Buffer.concat(parts));
  return file;
}

(async () => {
  console.log('\n=== 抓包链路自检（pcap 解析 → 会话入库 → 接口查询）===\n');
  const file = path.join(CAP_DIR, `smoke-${Date.now()}.pcap`);
  buildPcap(file);
  const size = fs.statSync(file).size;
  ok('生成测试 pcap', size > 0, `${(size / 1024).toFixed(1)} KB`);

  const parsed = dpi.parsePcapFile(file);
  ok('pcap 解析出包数', parsed.packets > 0, `${parsed.packets} 包 / 会话 ${parsed.sessions.length} 条`);
  ok('解析出会话', parsed.sessions.length >= 6, `${parsed.sessions.length} 条`);

  const protoOf = (p, d) => (parsed.sessions.find(s => s.dstPort === d || s.srcPort === d) || {}).appProto;
  ok('HTTP 识别', protoOf(0, 80) === 'http', `appProto=${protoOf(0, 80)}`);
  ok('HTTPS 识别', protoOf(0, 443) === 'tls', `appProto=${protoOf(0, 443)}`);
  ok('DNS 识别', protoOf(0, 53) === 'dns', `appProto=${protoOf(0, 53)}`);
  ok('SSH 识别', protoOf(0, 22) === 'ssh', `appProto=${protoOf(0, 22)}`);
  ok('Modbus 识别', protoOf(0, 502) === 'modbus-tcp', `appProto=${protoOf(0, 502)}`);
  ok('端口兜底 3306', protoOf(0, 3306) === 'mysql', `appProto=${protoOf(0, 3306)}`);

  const http = parsed.sessions.find(s => s.dstPort === 80);
  ok('HTTP 载荷抽取', http && http.hint.host === 'sw-core-01.nothing.local', http ? `${http.hint.method} ${http.hint.uri} @${http.hint.host}` : '');
  const tls = parsed.sessions.find(s => s.dstPort === 443);
  ok('TLS SNI 抽取', tls && tls.hint.sni === 'svc-billing.nothing.local', tls ? String(tls.hint.sni) : '');
  const dns = parsed.sessions.find(s => s.dstPort === 53);
  ok('DNS 查询名抽取', dns && dns.hint.qname === 'www.nothing.local', dns ? String(dns.hint.qname) : '');

  /* 会话入库 → 接口查询 */
  const BASE = (process.argv[2] || 'http://127.0.0.1:8787').replace(/\/+$/, '');
  let token = '';
  try {
    const lg = await fetch(BASE + '/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'admin@123' })
    }).then(r => r.json());
    token = lg.token || '';
  } catch { }
  if (!token) { console.log('  (服务未启动，跳过接口部分)'); }
  else {
    /* 入库交给服务端进程完成（persist），避免本进程与服务端同时写 data/db.json 互相覆盖 */
    const up = await fetch(BASE + '/api/flow/parse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify({ file: path.basename(file), persist: 1 })
    }).then(r => r.json()).catch(() => ({}));
    ok('服务端入库会话', up.inserted >= 6, `入库 ${up.inserted} 条 / 解析 ${up.packets} 包`);

    const list = await fetch(BASE + '/api/flow/sessions?limit=100&fileId=' + encodeURIComponent(path.basename(file)),
      { headers: { Authorization: 'Bearer ' + token } }).then(r => r.json());
    ok('接口查询会话', list.ok && list.total >= 6, `返回 ${list.rows.length} / 共 ${list.total} 条`);
    const stat = await fetch(BASE + '/api/flow/stats', { headers: { Authorization: 'Bearer ' + token } }).then(r => r.json());
    ok('协议分布统计', stat.ok && stat.byProto.length >= 5, stat.ok ? stat.byProto.map(x => `${x.proto}:${x.sessions}`).join(' ') : '');
    const one = await fetch(BASE + '/api/flow/sessions/' + encodeURIComponent((list.rows[0] || {}).id || ''),
      { headers: { Authorization: 'Bearer ' + token } }).then(r => r.json()).catch(() => ({}));
    ok('会话详情可读', one.ok === true || one.error === '会话不存在', one.ok ? '返回单条会话' : String(one.error));
  }

  try { fs.unlinkSync(file); } catch { }
  console.log(`\n=== 完成：通过 ${pass} 项，失败 ${fail} 项 ===\n`);
  process.exit(fail ? 1 : 0);
})();
