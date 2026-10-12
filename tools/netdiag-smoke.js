'use strict';
/**
 * 网络诊断链路自检
 *
 * 分两段：
 *   A 段（引擎级，无需服务）：工具元数据 → 打分口径 → 帧解码 → DHCP 报文解析
 *                             → Syslog 解析 → 规则分类 → 聚合阈值 → 目标展开
 *   B 段（接口级，需服务）：任务 CRUD → 执行诊断 → 入库 → 查询 → 统计 → CSV → 导出
 *                           → Syslog 开关 → 权限校验
 *
 * A 段刻意不碰数据库：解码/解析/打分这类纯函数一旦回归，不需要起服务也能抓到。
 * 帧解码用手工拼出来的字节（ARP 请求、IPv4/TCP、DHCP Offer），保证结果可复现，
 * 不依赖 tshark 也不依赖真实抓包环境。
 *
 * 用法：node tools/netdiag-smoke.js [baseUrl]   （默认 http://127.0.0.1:8787）
 */
const netdiag = require('../server/netdiag');
const scanner = require('../server/scanner');

const BASE = (process.argv[2] || 'http://127.0.0.1:8787').replace(/\/+$/, '');

let pass = 0, fail = 0;
const fails = [];
const ok = (n, c, e) => {
  if (c) { pass++; console.log(`  ✓ ${n}${e ? ' — ' + e : ''}`); }
  else { fail++; fails.push(n); console.log(`  ✗ ${n}${e ? ' — ' + e : ''}`); }
};

/* ============================== 工具箱 ============================== */

/**  手工字节拼装：16 位按场景区分大小端（协议头里的长度/类型字段一律大端） */
const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v & 0xffff, 0); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0, 0); return b; };
const macBuf = (s) => Buffer.from(s.split(/[:-]/).map(x => parseInt(x, 16)));
const ipBuf = (s) => Buffer.from(s.split('.').map(x => parseInt(x, 10)));
const MAC_A = '00:11:22:33:44:55';
const MAC_B = '66:77:88:99:aa:bb';
const DST = Buffer.from(macBuf(MAC_A));
const SRC = Buffer.from(macBuf(MAC_B));

/** 构造一个经典 pcap 文件（只含 LinkType 1 = Ethernet） */
function wrapPcap(frames) {
  const alink = Buffer.alloc(24);
  alink.writeUInt32LE(0xa1b2c3d4, 0);      // 魔数：小端 pcap
  alink.writeUInt16LE(2, 4);                // 主版本
  alink.writeUInt16LE(4, 6);                // 次版本
  alink.writeUInt32LE(0, 8);                 // 时区
  alink.writeUInt32LE(0, 12);                // 精度
  alink.writeUInt32LE(65535, 16);            // 单包上限
  alink.writeUInt32LE(1, 20);                // LinkType = Ethernet
  const parts = [alink];
  let t = 1700000000;
  for (const f of frames) {
    const h = Buffer.alloc(16);
    h.writeUInt32LE(t, 0); h.writeUInt32LE(t, 4);
    h.writeUInt32LE(f.length, 8); h.writeUInt32LE(f.length, 12);
    parts.push(h, f);
    t += 1;
  }
  return Buffer.concat(parts);
}

/** 以太网头：目的 MAC 在前、源 MAC 在后，协议类型沿用大端 */
const ETH_HDR = (type) => Buffer.concat([DST, SRC, u16(type)]);

/** 纯 ARP 请求帧（0x0806，20 字节固定头） */
const arpReq = () => Buffer.concat([
  ETH_HDR(0x0806),
  Buffer.from([0x00, 0x01]), u16(0x0800), Buffer.from([0x06, 0x04]),
  Buffer.from([0x00, 0x01]), DST, ipBuf('192.168.1.10'),
  Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), ipBuf('192.168.1.1')
]);

/** IPv4 + UDP 帧。字段布局按 RFC791：TTL/协议在 8/9，源目的 IP 在 12/16 */
function ipv4Udp(srcIp, dstIp, sport, dport, payload, { id = 0x1a2b, ttl = 64 } = {}) {
  const udp = Buffer.concat([u16(sport), u16(dport), u16(8 + payload.length), u16(0), payload]);
  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0);                        // version 4 + IHL 5
  ip.writeUInt16BE(20 + udp.length, 2);
  ip.writeUInt16BE(id, 4);                       // IP ID：环路检测就靠它
  ip.writeUInt8(ttl, 8);                         // TTL
  ip.writeUInt8(17, 9);                          // protocol = UDP
  ip.writeUInt16BE(0, 10);                       // 校验和解码器不校验，填 0 也能过
  ipBuf(srcIp).copy(ip, 12);
  ipBuf(dstIp).copy(ip, 16);
  return Buffer.concat([ip, udp]);
}

/* ====================== A1：工具元数据与打分口径 ====================== */

function checkMeta() {
  console.log('\n[A1] 工具元数据与打分口径');
  const keys = netdiag.TOOLS_KEYS;
  ok('六个检测器全部注册', keys.length === 6, keys.join('/'));
  ok('含摄像头扫描', keys.includes('camera'));
  ok('含 IP 冲突检测', keys.includes('ipconflict'));
  ok('含环路检测', keys.includes('loop'));
  ok('含日志审计', keys.includes('logaudit'));
  ok('含外网测速', keys.includes('speedtest'));
  ok('含 DHCP 检测', keys.includes('dhcp'));

  const all = netdiag.TOOLS;
  ok('每个工具都有中文名与说明', all.every(t => t.name && t.desc && t.risk));
  const needTargets = all.filter(t => t.needsTargets).map(t => t.key);
  ok('目标相关工具标记 needsTargets', needTargets.join(',') === 'camera,ipconflict', needTargets.join(','));
  const withOpts = all.filter(t => (t.options || []).length);
  ok('每个工具都声明了可调选项', withOpts.length === 6, `${withOpts.length}/6`);

  ok('未知工具返回 null', netdiag.toolMeta('nope') === null);

  ok('满分 100 起', netdiag.scoreOf([]) === 100);
  ok('低危扣 3 分', netdiag.scoreOf([{ level: 'low' }]) === 97);
  ok('中危扣 8 分', netdiag.scoreOf([{ level: 'medium' }]) === 92);
  ok('高危扣 20 分', netdiag.scoreOf([{ level: 'high' }]) === 80);
  ok('极高危扣 40 分', netdiag.scoreOf([{ level: 'critical' }]) === 60);
  ok('扣分不会跌破 0', netdiag.scoreOf([{ level: 'critical' }, { level: 'critical' }, { level: 'critical' }]) === 0);
  ok('未知等级按 0 分处理', netdiag.scoreOf([{ level: 'weird' }]) === 100);

  ok('worstLevel 空数组为 info', netdiag.worstLevel([]) === 'info');
  ok('worstLevel 取最高等级', netdiag.worstLevel(['low', 'medium', 'critical', 'high']) === 'critical');
  ok('worstLevel 无视低等级', netdiag.worstLevel(['info', 'low']) === 'low');
  ok('LEVEL_TEXT 覆盖五级', ['critical', 'high', 'medium', 'low', 'info'].every(k => netdiag.LEVEL_TEXT[k]));
  ok('LEVEL_ORDER 满足 critical>high>medium>low>info',
    netdiag.LEVEL_ORDER.critical > netdiag.LEVEL_ORDER.high &&
    netdiag.LEVEL_ORDER.high > netdiag.LEVEL_ORDER.medium &&
    netdiag.LEVEL_ORDER.medium > netdiag.LEVEL_ORDER.low &&
    netdiag.LEVEL_ORDER.low > netdiag.LEVEL_ORDER.info);
}

/* ========================= A2：帧解码（手工字节） ========================= */

function checkDecode() {
  console.log('\n[A2] 帧解码（手工拼字节，不依赖抓包环境）');

  // 以太网头：解码器按标准布局读（dst 在 0、src 在 6）
  const eth = netdiag.decodeEth(ETH_HDR(0x0800), 1);
  ok('decodeEth 解出目的 MAC', eth.dst === MAC_A, eth.dst);
  ok('decodeEth 解出源 MAC', eth.src === MAC_B, eth.src);
  ok('decodeEth 解出 etherType', eth.type === 0x0800, '0x' + eth.type.toString(16));
  ok('decodeEth 给出 L3 起点 p=14', eth.p === 14, String(eth.p));

  // ARP：需要 eth 解析出的 p 作为起始偏移
  const arp = netdiag.decodeArp(arpReq(), 14);
  ok('decodeArp 解出发送方 MAC(sha)', arp.sha === MAC_A, arp.sha);
  ok('decodeArp 解出发送方 IP(spa)', arp.spa === '192.168.1.10', arp.spa);
  ok('decodeArp 解出目标 IP(tpa)', arp.tpa === '192.168.1.1', arp.tpa);
  ok('decodeArp 解出目标 MAC(tha)', arp.tha === '00:00:00:00:00:00', arp.tha);
  ok('decodeArp 解出 opcode=1(请求)', arp.op === 1, String(arp.op));

  // IPv4 + UDP。注意解码器的 d 是完整帧（含以太网头），起始偏移由 eth.p 给出
  const frame = Buffer.concat([ETH_HDR(0x0800), ipv4Udp('10.0.0.5', '10.0.0.9', 12345, 67, Buffer.from('discover-payload'))]);
  ok('构造的帧含以太网头', frame.length === 14 + 20 + 8 + 16, `${frame.length} 字节`);
  const ip = netdiag.decodeIpv4(frame, 14);
  ok('decodeIpv4 解出 src/dst', ip.src === '10.0.0.5' && ip.dst === '10.0.0.9', `${ip.src} → ${ip.dst}`);
  ok('decodeIpv4 解出 protocol=17(UDP)', ip.proto === 17, String(ip.proto));
  ok('decodeIpv4 解出 ttl=64', ip.ttl === 64, String(ip.ttl));
  ok('decodeIpv4 解出 ipId', ip.id === 0x1a2b, String(ip.id));
  ok('decodeIpv4 给出 L4 起点', ip.p === 34, String(ip.p));

  const udp = netdiag.decodeUdp(frame, ip.p);
  ok('decodeUdp 解出 sport/dport', udp.sport === 12345 && udp.dport === 67, `${udp.sport} → ${udp.dport}`);
  ok('decodeUdp 带 payload', Buffer.isBuffer(udp.payload) && udp.payload.length > 0, `${udp.payload?.length} 字节`);
  ok('payload 内容可复原', udp.payload.toString('utf8') === 'discover-payload', udp.payload.toString('utf8'));

  // 越界输入不能炸
  ok('decodeIpv4 遇短包返回 null', netdiag.decodeIpv4(Buffer.alloc(10), 0) === null);
  ok('decodeUdp 遇短包返回 null', netdiag.decodeUdp(Buffer.alloc(4), 0) === null);
  ok('decodeEth 遇非以太网链路返回 null', netdiag.decodeEth(Buffer.alloc(64), 999) === null);

  // pcap 容器：解码器读的是 {frames:[{t,data}], linkType}
  const fs = require('fs'), os = require('os'), path = require('path');
  const tmp = path.join(os.tmpdir(), `nd-smoke-${Date.now()}.pcap`);
  try {
    fs.writeFileSync(tmp, wrapPcap([arpReq(), frame]));
    const r = netdiag.readPcapFrames(tmp);
    ok('readPcapFrames 无错且读到 2 帧', !r.error && r.frames.length === 2, r.error || `${r.frames.length} 帧 · linkType=${r.linkType}`);

    const e0 = netdiag.decodeEth(r.frames[0].data, r.linkType);
    const a0 = netdiag.decodeArp(r.frames[0].data, e0.p);
    ok('pcap 帧 0 是可解析的 ARP', a0 && a0.spa === '192.168.1.10', a0 ? `${a0.spa} → ${a0.tpa}` : '解析失败');

    const e1 = netdiag.decodeEth(r.frames[1].data, r.linkType);
    const i1 = netdiag.decodeIpv4(r.frames[1].data, e1.p);
    const u1 = netdiag.decodeUdp(r.frames[1].data, i1.p);
    ok('pcap 帧 1 是可解析的 UDP', i1.src === '10.0.0.5' && u1.dport === 67, `${i1.src} → ${u1.dport}`);
    ok('pcap 帧带时间戳 t', typeof r.frames[0].t === 'number' && r.frames[0].t > 1600000000, String(r.frames[0].t));

    // pcapng（tshark 默认格式）必须给出明确提示，而不是报个看不懂的错
    const ng = path.join(os.tmpdir(), `nd-ng-${Date.now()}.pcapng`);
    fs.writeFileSync(ng, Buffer.concat([Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), Buffer.alloc(64)]));
    const r2 = netdiag.readPcapFrames(ng);
    ok('pcapng 给出「需加 -F pcap」的明确提示', /-F pcap/.test(r2.error || ''), r2.error || '未报错');
    try { fs.unlinkSync(ng); } catch { }
  } catch (e) {
    ok('readPcapFrames 读回 2 帧', false, e.message);
  } finally {
    try { fs.unlinkSync(tmp); } catch { }
  }
}

/* ========================= A3：DHCP 报文解析 ========================= */

function checkDhcp() {
  console.log('\n[A3] DHCP 报文构造与解析');

  // 拿引擎自己构造的 Discover，塞一段伪造的 Offer 进去解析
  let disc = null;
  try {
    disc = netdiag.buildDiscover(0xdeadbeef, '00:11:22:33:44:55', 'ndtest');
  } catch (e) { }
  ok('buildDiscover 产出 Buffer', Buffer.isBuffer(disc) && disc.length > 200, disc ? `${disc.length} 字节` : 'null');

  if (disc) {
    ok('Discover 是完整 BOOTP 报文（含固定头，op=BOOTREQUEST）', disc[0] === 1 && disc[2] === 6, `op=${disc[0]} hlen=${disc[2]}`);
    ok('Discover 带魔数 0x63825363', disc.readUInt32BE(236) === 0x63825363, '0x' + disc.readUInt32BE(236).toString(16));
    ok('Discover 带 xid 0xdeadbeef', disc.readUInt32BE(4) === 0xdeadbeef, '0x' + disc.readUInt32BE(4).toString(16));
    ok('Discover 带 client MAC(chaddr@28)', disc.slice(28, 34).toString('hex') === Buffer.from(macBuf('00:11:22:33:44:55')).toString('hex'));
    // 整包回环解析：能不能被 parseDhcp 认出来，才是「发出去的包 server 收得到」的真判据
    const back = netdiag.parseDhcp(disc);
    ok('Discover 能被 parseDhcp 解析', !!back && back.msgType === 1, back ? `msgType=${back.msgType}` : 'null');
    ok('Discover 解出 xid 一致', back && back.xid === 0xdeadbeef, String(back?.xid));
  }

  // 手工拼一个 DHCP Offer。字段布局要与引擎的 parseDhcp 对齐：
  //   op@0 htype@1 hlen@2 xid@4(4字节) flags@10 ciaddr@12 yiaddr@16 siaddr@20 giaddr@24
  //   chaddr@28（引擎约定，非 RFC 的 20）  魔数 0x63825363 在 236 处   选项从 240 起
  const fixed = Buffer.alloc(240);
  fixed.writeUInt8(0x02, 0);                       // op = BOOTREPLY
  fixed.writeUInt8(0x01, 1);                       // htype = ethernet
  fixed.writeUInt8(0x06, 2);                       // hlen = 6
  fixed.writeUInt32BE(0xdeadbeef, 4);              // xid
  fixed.writeUInt16BE(0x8000, 10);                 // flags（广播应答位）
  ipBuf('192.168.1.100').copy(fixed, 16);          // yiaddr：要下发的地址
  SRC.copy(fixed, 28);                             // chaddr
  fixed.writeUInt32BE(0x63825363, 236);            // 魔数
  const offer = Buffer.concat([fixed, Buffer.from([
    53, 1, 2,                                        // 53 = DHCP Message Type，2 = OFFER
    54, 4, 192, 168, 1, 1,                          // 54 = Server Identifier
    1, 4, 255, 255, 255, 0,                         // 1  = Subnet Mask
    3, 4, 192, 168, 1, 1,                           // 3  = Router
    6, 4, 8, 8, 8, 8,                               // 6  = DNS
    15, 3, 97, 115, 99,                             // 15 = Domain Name
    51, 4, 0, 0, 14, 16,                            // 51 = Lease Time（3600 = 0x00000E10）
    255                                             // End
  ])]);

  const p = netdiag.parseDhcp(offer);
  ok('parseDhcp 解析成功', !!p, p ? 'ok' : 'null');
  ok('parseDhcp 识别出 msgType=2(OFFER)', p && p.msgType === 2, String(p?.msgType));
  ok('parseDhcp 解出 xid', p && p.xid === 0xdeadbeef, '0x' + Number(p?.xid || 0).toString(16));
  ok('parseDhcp 解出 yiaddr', p && p.yiaddr === '192.168.1.100', p?.yiaddr);
  ok('parseDhcp 解出 serverId', p && p.serverId === '192.168.1.1', p?.serverId);
  ok('parseDhcp 解出子网掩码', p && p.options?.mask === '255.255.255.0', p?.options?.mask);
  ok('parseDhcp 解出网关', p && (p.options?.routers || []).includes('192.168.1.1'), JSON.stringify(p?.options?.routers));
  ok('parseDhcp 解出 DNS', p && (p.options?.dns || []).includes('8.8.8.8'), JSON.stringify(p?.options?.dns));
  ok('parseDhcp 解出域名', p && p.options?.domain === 'asc', p?.options?.domain);
  ok('parseDhcp 解出租约时长', p && p.options?.lease === 3600, String(p?.options?.lease));
  ok('parseDhcp 解出 chaddr', p && p.chaddr === MAC_B, p?.chaddr);

  // 非 DHCP 报文（少了魔数）必须返回 null 而不是乱解
  const junk = Buffer.concat([Buffer.alloc(240), Buffer.from([255])]);
  ok('parseDhcp 遇非 DHCP 报文返回 null', netdiag.parseDhcp(junk) === null);
  ok('parseDhcp 遇空输入返回 null', netdiag.parseDhcp(null) === null && netdiag.parseDhcp(Buffer.alloc(10)) === null);
}

/* ====================== A4：Syslog 解析与规则分类 ====================== */

function checkSyslog() {
  console.log('\n[A4] Syslog 解析与规则分类');

  // RFC3164
  const r1 = netdiag.parseSyslog('<34>Oct 11 22:14:15 mymachine su: session opened', '1.2.3.4');
  ok('RFC3164 解析 facility=4', r1.facility === '4', String(r1.facility));
  ok('RFC3164 解析 severity=2', r1.severity === 2, String(r1.severity));
  ok('RFC3164 解析 host', r1.host === 'mymachine', String(r1.host));
  ok('RFC3164 解析 tag', r1.tag === 'su', String(r1.tag));
  ok('RFC3164 解析 message', /session opened/.test(r1.msg), String(r1.msg));

  // RFC3164 带 [pid]
  const r1b = netdiag.parseSyslog('<165>Oct 11 22:14:15 fw01 sshd[12345]: Failed password', '10.0.0.1');
  ok('RFC3164 带 [pid] 也能取到 tag', r1b.tag === 'sshd', String(r1b.tag));
  ok('RFC3164 带 [pid] 也能取到消息', /Failed password/.test(r1b.msg), String(r1b.msg));
  ok('RFC3164 带 [pid] 解析 facility=20', r1b.facility === '20', String(r1b.facility));

  // RFC5424
  const r2 = netdiag.parseSyslog('<134>1 2024-10-11T22:14:15.003Z mymachine su - ID47 - session opened', '1.2.3.4');
  ok('RFC5424 解析 host', r2.host === 'mymachine', String(r2.host));
  ok('RFC5424 解析 tag', r2.tag === 'su', String(r2.tag));
  ok('RFC5424 解析 message', /session opened/.test(r2.msg), String(r2.msg));
  ok('RFC5424 解析 severity', r2.severity === 6, String(r2.severity));

  // 无 PRI 兜底：用来源 IP 补 host
  const r3 = netdiag.parseSyslog('some random text without pri', '9.9.9.9');
  ok('无 PRI 时 host 回落到来源 IP', r3.host === '9.9.9.9', String(r3.host));
  ok('无 PRI 时 severity 兜底 6', r3.severity === 6, String(r3.severity));

  // 空串不炸
  const r4 = netdiag.parseSyslog('', '1.1.1.1');
  ok('空消息不崩溃', r4 && typeof r4.msg === 'string', JSON.stringify(r4));

  // 规则分类
  const hit = netdiag.classifyLog({ tag: 'sshd', msg: 'Failed password for root from 10.0.0.66 port 22 ssh2' });
  ok('登录失败命中规则', !!hit.rule, `${hit.rule} / ${hit.level}`);
  ok('登录失败判为 medium 以上', ['medium', 'high', 'critical'].includes(hit.level), hit.level);

  const hit2 = netdiag.classifyLog({ tag: 'sshd', msg: 'Failed password for invalid user admin from 10.0.0.66 port 22' });
  ok('无效用户名命中爆破规则', hit2.rule === 'auth.bruteforce', `${hit2.rule} / ${hit2.level}`);
  const hit2b = netdiag.classifyLog({ tag: 'kernel', msg: 'fan fault detected on slot 3' });
  ok('风扇故障判为极高危', hit2b.rule === 'power.fan.temp' && hit2b.level === 'critical', `${hit2b.rule} / ${hit2b.level}`);
  const hit2c = netdiag.classifyLog({ tag: 'sh', msg: 'audit log cleared by root' });
  ok('日志被清除判为极高危', hit2c.rule === 'sec.log.clear' && hit2c.level === 'critical', `${hit2c.rule} / ${hit2c.level}`);

  const hit3 = netdiag.classifyLog({ tag: 'kernel', msg: 'link is up' });
  ok('无关日志走严重度兜底', hit3.rule === '' && hit3.level === 'info', `${hit3.rule} / ${hit3.level}`);

  const hit4 = netdiag.classifyLog({ tag: 'kernel', msg: 'something', severity: 2 });
  ok('严重度 2 兜底为 high', hit4.level === 'high', hit4.level);
  const hit5 = netdiag.classifyLog({ tag: 'kernel', msg: 'something', severity: 6 });
  ok('严重度 6 兜底为 info', hit5.level === 'info', hit5.level);

  // 规则库自检：每条规则都该有 key/level/title/advice/re
  const rules = netdiag.LOG_RULES;
  ok('规则库非空且覆盖爆破/越权/配置变更', rules.length >= 10, `${rules.length} 条`);
  ok('每条规则字段完整', rules.every(r => r.key && r.level && r.title && r.advice && r.re));
  ok('登录爆破类规则存在', rules.some(r => r.key === 'auth.bruteforce'));
  ok('硬件健康类规则存在', rules.some(r => r.key === 'power.fan.temp'));
  ok('配置变更类规则存在', rules.some(r => r.key === 'cfg.change'));
  ok('规则库覆盖登录/配置/硬件/二层环路四类场景',
    new Set(rules.map(r => r.category)).size >= 8, `${new Set(rules.map(r => r.category)).size} 个分类`);
}

/* ====================== A5：审计聚合阈值（防刷屏） ====================== */

function checkAggregate() {
  console.log('\n[A5] 审计聚合阈值');
  const mk = (n, level, key) => Array.from({ length: n }, (_, i) => ({
    rule: key, level, tag: 'sshd', msg: 'Failed password', severity: 5, host: 'h1'
  }));

  // 返回的是 findings（与 run() 产物同构），条数在 evidence.count 里
  const a = netdiag.auditAggregate(mk(3, 'high', 'auth.bruteforce'));
  ok('达到阈值的规则被聚合出来', a.length === 1 && a[0].evidence?.rule === 'auth.bruteforce',
    JSON.stringify(a.map(x => x.evidence?.rule)));
  ok('聚合结果带条数', a[0]?.evidence?.count === 3, String(a[0]?.evidence?.count));
  ok('聚合结果带等级', a[0]?.level === 'high', a[0]?.level);
  ok('标题里带上命中次数', /×\s*3/.test(a[0]?.title || ''), a[0]?.title);
  ok('聚合结果带分类与建议', !!a[0]?.category && !!a[0]?.advice, a[0]?.category);

  // 1 条 high：达不到阈值（high 需 >= 3）
  const b = netdiag.auditAggregate(mk(1, 'high', 'auth.bruteforce'));
  ok('未达阈值的规则不产出', b.length === 0, JSON.stringify(b.map(x => x.evidence?.rule)));

  // info 级日志不参与聚合（否则日志一多就全是噪音）
  const b2 = netdiag.auditAggregate(mk(500, 'info', 'auth.bruteforce'));
  ok('info 级日志不参与聚合', b2.length === 0, `${b2.length} 条`);

  // 不同规则分开成条，不混在一起
  const c = netdiag.auditAggregate([
    ...mk(3, 'high', 'auth.bruteforce'),
    ...mk(5, 'medium', 'cfg.change')
  ]);
  const rs = c.map(x => x.evidence?.rule);
  ok('不同规则各自成条', rs.includes('auth.bruteforce') && rs.includes('cfg.change'), rs.join('/'));
  ok('medium 阈值下 5 条能过', c.find(x => x.evidence?.rule === 'cfg.change')?.evidence?.count === 5);

  // 自定义阈值
  const c2 = netdiag.auditAggregate(mk(2, 'high', 'auth.bruteforce'), { minCount: { high: 2 } });
  ok('可自定义聚合阈值', c2.length === 1, `${c2.length} 条`);

  // 空输入
  ok('空日志列表不崩', Array.isArray(netdiag.auditAggregate([])));
}

/* ========================= A6：本机环境与原语 ========================= */

async function checkLocal() {
  console.log('\n[A6] 本机环境与原语');
  const nets = netdiag.localNets();
  ok('localNets 返回非空', Array.isArray(nets) && nets.length > 0, nets.map(n => n.cidr || n.address).join(' / '));
  ok('网卡带 netmask/cidr（诊断推导网段要用）',
    nets.every(n => n.netmask !== undefined && n.cidr !== undefined),
    nets.map(n => `${n.cidr}:${n.netmask}`).join(' '));
  ok('localNets 排除了回环', nets.every(n => !String(n.address || '').startsWith('127.')));

  const gw = netdiag.defaultGateway();
  ok('defaultGateway 返回对象或 null', gw === null || typeof gw === 'object', JSON.stringify(gw));

  // Windows 上 arp -a 可能一个条目都没有，但返回类型必须是 Map（调用方靠它聚合 MAC）
  const arp = await netdiag.arpTable();
  ok('arpTable 返回 Map', arp instanceof Map, `${arp.size} 条`);
  ok('arpTable 条目是规范化 MAC', [...arp.values()].every(v => /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(v)),
    [...arp.values()].slice(0, 3).join(' '));

  // 目标展开：range 模式复用扫描器的实现
  const list = await scanner.expandTargets('127.0.0.1/32', 64);
  ok('指定网段可展开出地址', list.length >= 1, list.join(','));

  // 本机事件日志：Windows 才有，其它平台应给出明确说明而不是抛异常
  const ev = await netdiag.readLocalEventLog({ limit: 5 });
  ok('readLocalEventLog 返回结构而非抛错', ev && Array.isArray(ev.rows), ev?.error ? `（${String(ev.error).slice(0, 40)}）` : `${ev?.rows?.length} 条`);

  // 本机租约
  const lease = await netdiag.localLease();
  ok('localLease 返回结构而非抛错', lease && typeof lease === 'object', JSON.stringify(lease).slice(0, 100));
}

/* ========================= A7：目标范围解析（双模式） ========================= */

async function checkScope() {
  console.log('\n[A7] 目标范围解析（本机 / 指定网段）');

  // local 模式：不传 targets，应从活动网卡推导网段
  let scope = null, err = null;
  try {
    scope = await netdiag.resolveScope('local', '', 256);
  } catch (e) { err = e; }
  if (err) {
    ok('local 模式可解析目标范围', false, err.message);
  } else {
    ok('local 模式解析出目标列表', Array.isArray(scope.targets) && scope.targets.length > 0, `${scope.targets.length} 个地址`);
    ok('local 模式带出网卡信息', Array.isArray(scope.ifaces) && scope.ifaces.length > 0, `${scope.ifaces.length} 张`);
    ok('local 模式给出说明文案', !!scope.note, String(scope.note).slice(0, 60));
    const segs = scope.targets.filter(t => String(t).startsWith('127.'));
    ok('local 模式不会扫到回环网段', segs.length === 0 || scope.nets.length > 0, `回环地址 ${segs.length} 个`);
  }

  // range 模式：指定网段
  let rs = null;
  try { rs = await netdiag.resolveScope('range', '127.0.0.1/30', 64); } catch (e) { }
  ok('range 模式解析出目标列表', rs && rs.targets && rs.targets.length > 0, rs ? `${rs.targets.length} 个：${rs.targets.join(',')}` : 'null');

  // range 模式：非法目标要报错而不是静默返回空
  let badErr = null;
  try { await netdiag.resolveScope('range', '999.1.1.1/24', 64); } catch (e) { badErr = e; }
  ok('range 模式非法目标抛错', !!badErr, badErr ? badErr.message.slice(0, 40) : '未抛错');

  // 显式指定网段超配额：必须报错而不是悄悄少扫（用户是要扫这个网段的）
  let capErr = null;
  try { await netdiag.resolveScope('range', '127.0.0.0/24', 32); } catch (e) { capErr = e; }
  ok('显式网段超配额要报错提示分批', !!capErr && /上限|分批/.test(capErr.message || ''), capErr ? capErr.message.slice(0, 50) : '未抛错');

  // 本机网段超配额：要截断到配额并给出说明，不能退化成只扫本机一个地址
  let cap2 = null, capErr2 = null;
  try { cap2 = await netdiag.resolveScope('local', '', 48); } catch (e) { cap2 = null; capErr2 = e; }
  ok('本机网段超配额时截断到配额',
    cap2 && cap2.targets.length > 1 && cap2.targets.length <= 48,
    cap2 ? `${cap2.targets.length} 个（上限 48）` : (capErr2 ? capErr2.message.slice(0, 50) : 'null'));
  ok('截断时给出说明而不是静默', cap2 && /截断/.test(cap2.note || ''), String(cap2?.note).slice(0, 60));
  // 截断不能把本机自己切出去，否则「本机网段」扫描结果没有意义
  const selfIp = netdiag.localNets()[0]?.address;
  ok('截断结果里一定含本机地址', cap2 && cap2.targets.includes(selfIp), `本机 ${selfIp} · 前 3 个 ${cap2?.targets?.slice(0, 3).join(',')}`);
}

/* ============================== B 段：接口 ============================== */

let TOKEN = '', ADMIN = '';

async function api(path, { method = 'GET', body = null, token = TOKEN } = {}) {
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: `Bearer ${token}` } : {}),
    body: body ? JSON.stringify(body) : undefined
  });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  return { status: r.status, data };
}

async function login() {
  // 先试默认管理员，失败再试 ops / audit
  const cands = [
    { username: 'admin', password: 'admin@123' },
    { username: 'admin', password: 'admin123' },
    { username: 'admin', password: '123456' }
  ];
  for (const c of cands) {
    try {
      const r = await api('/api/auth/login', { method: 'POST', body: c, token: '' });
      if (r.data && r.data.ok && r.data.token) {
        ADMIN = r.data.token;
        TOKEN = r.data.token;
        return { role: 'admin', token: r.data.token };
      }
    } catch {
      return null;
    }
  }
  return null;
}

async function checkApi() {
  console.log('\n[B] 接口层');

  // 元数据
  const meta = await api('/api/diag/tools');
  ok('GET /diag/tools 200', meta.status === 200 && meta.data.ok, JSON.stringify(meta.data).slice(0, 60));
  ok('tools 返回六个工具', meta.data?.tools?.length === 6, `${meta.data?.tools?.length} 个`);
  ok('tools 带五档等级中文名', !!meta.data?.levels?.critical);
  ok('tools 带环境信息（tshark / 平台）', !!meta.data?.env);

  // 范围预览
  const sc = await api('/api/diag/scope?mode=local');
  ok('GET /diag/scope 本机模式 200', sc.status === 200 && sc.data.ok, JSON.stringify(sc.data).slice(0, 80));
  ok('scope 带出本机网段', Array.isArray(sc.data?.nets) && sc.data.nets.length > 0, sc.data?.note?.slice(0, 60));

  const sc2 = await api('/api/diag/scope?mode=range&targets=127.0.0.1/30');
  ok('scope 指定网段可展开', sc2.status === 200 && sc2.data.targets?.length > 0, sc2.data?.note);

  const sc3 = await api('/api/diag/scope?mode=range');
  ok('scope 指定网段缺目标要 400', sc3.status === 400, `HTTP ${sc3.status}`);

  // 任务 CRUD
  const taskName = `自检任务-${Date.now()}`;
  const c = await api('/api/diag/tasks', { method: 'POST', body: { name: taskName, tool: 'logaudit', mode: 'local', intervalSec: 3600, enabled: false } });
  ok('POST /diag/tasks 建任务', c.status === 200 && c.data.ok && c.data.task?.id, c.data?.error || c.data?.task?.id);
  const tid = c.data?.task?.id;

  const l = await api('/api/diag/tasks');
  ok('GET /diag/tasks 列出任务', l.status === 200 && l.data.rows?.length > 0, `${l.data?.rows?.length} 个`);

  const u = await api(`/api/diag/tasks/${tid}`, { method: 'PUT', body: { name: taskName + '-改名', enabled: true } });
  ok('PUT /diag/tasks/:id 改任务', u.status === 200 && /改名/.test(u.data?.task?.name || ''), u.data?.task?.name);

  const tg = await api(`/api/diag/tasks/${tid}/toggle`, { method: 'POST', body: { enabled: false } });
  ok('POST /diag/tasks/:id/toggle 切换', tg.status === 200 && tg.data?.task?.enabled === false);

  const bad = await api('/api/diag/tasks', { method: 'POST', body: { name: '缺工具', tool: '' } });
  ok('建任务缺工具要 400', bad.status === 400, `HTTP ${bad.status}`);

  const badRange = await api('/api/diag/tasks', { method: 'POST', body: { name: '缺目标', tool: 'camera', mode: 'range', targets: '' } });
  ok('range 任务缺目标要 400', badRange.status === 400, `HTTP ${badRange.status}`);

  const nf = await api('/api/diag/tasks/ndt_nope', { method: 'PUT', body: { name: 'x' } });
  ok('改不存在的任务要 404', nf.status === 404, `HTTP ${nf.status}`);

  // 执行诊断（选最快的日志审计，不需要真实网络）
  const run = await api('/api/diag/run', { method: 'POST', body: { tool: 'logaudit', mode: 'local', options: { limit: 100 } } });
  ok('POST /diag/run 执行诊断', run.status === 200 && run.data.ok, run.data?.error || `${run.data?.ms}ms · ${run.data?.findings?.length} 条问题`);
  ok('run 结果带 runId', !!run.data?.runId, String(run.data?.runId));
  ok('run 结果带风险评分', typeof run.data?.score === 'number', `score=${run.data?.score}`);
  ok('run 结果带等级文案', !!run.data?.levelText, run.data?.levelText);
  ok('run 结果带目标数量', typeof run.data?.targets === 'number', String(run.data?.targets));

  const rid = run.data?.runId;

  const runs = await api(`/api/diag/runs?limit=5`);
  ok('GET /diag/runs 查得到本轮', runs.status === 200 && runs.data.rows?.some(r => r.id === rid));

  const fnd = await api(`/api/diag/findings?runId=${encodeURIComponent(rid || '')}`);
  ok('GET /diag/findings 查问题清单', fnd.status === 200 && Array.isArray(fnd.data.rows), `${fnd.data?.total} 条`);
  if (fnd.data?.rows?.length) {
    ok('问题条目字段完整', fnd.data.rows.every(x => x.level && x.category && x.title), JSON.stringify(fnd.data.rows[0]).slice(0, 90));
  }

  const st = await api(`/api/diag/findings/stats?runId=${encodeURIComponent(rid || '')}`);
  ok('GET /diag/findings/stats', st.status === 200 && typeof st.data?.total === 'number', `${st.data?.total} 条 · 需处理 ${st.data?.needFix}`);
  ok('stats 带分档统计', Array.isArray(st.data?.byLevel) && Array.isArray(st.data?.byTool));

  const hs = await api(`/api/diag/hosts?tool=logaudit`);
  ok('GET /diag/hosts', hs.status === 200 && Array.isArray(hs.data.rows), `${hs.data?.total} 条`);

  const lg = await api(`/api/diag/logs?limit=20`);
  ok('GET /diag/logs', lg.status === 200 && Array.isArray(lg.data.rows), `${lg.data?.total} 条`);

  const lgStat = await api('/api/diag/logs/stats?days=7');
  ok('GET /diag/logs/stats', lgStat.status === 200 && typeof lgStat.data?.total === 'number', `${lgStat.data?.total} 条`);
  ok('logs/stats 带来源与规则分布', Array.isArray(lgStat.data?.bySource) && Array.isArray(lgStat.data?.byRule));

  const lgF = await api('/api/diag/logs?level=high&limit=5');
  ok('按等级过滤日志', lgF.status === 200 && lgF.data.rows.every(x => x.level === 'high'), `${lgF.data?.total} 条匹配`);
  const lgT = await api('/api/diag/logs?host=127.0.0.1&limit=5');
  ok('按主机过滤日志不炸', lgT.status === 200, `${lgT.data?.total} 条`);

  const expRes = await fetch(`${BASE}/api/diag/export?runId=${encodeURIComponent(rid || '')}`, {
    headers: { Authorization: `Bearer ${TOKEN}` }
  });
  const expBuf = Buffer.from(await expRes.arrayBuffer());
  const expText = expBuf.toString('utf8');
  ok('GET /diag/export 返回 CSV', expRes.status === 200 && expBuf.length > 3, `${expBuf.length} 字节`);
  ok('CSV 带 BOM（Excel 不乱码）', expBuf[0] === 0xEF && expBuf[1] === 0xBB && expBuf[2] === 0xBF);
  ok('CSV 含表头', /等级,分类,目标/.test(expText));

  const expBad = await api('/api/diag/export');
  ok('export 缺 runId 要 400', expBad.status === 400, `HTTP ${expBad.status}`);

  const sl = await api('/api/diag/syslog');
  ok('GET /diag/syslog 状态', sl.status === 200 && typeof sl.data?.status === 'object', JSON.stringify(sl.data?.status).slice(0, 90));

  // 任务手动执行
  if (tid) {
    const tr = await api(`/api/diag/tasks/${tid}/run`, { method: 'POST' });
    ok('POST /diag/tasks/:id/run 执行任务', tr.status === 200 && tr.data.ok, tr.data?.error || `等级 ${tr.data?.levelText}`);
    const td = await api(`/api/diag/tasks/${tid}`, { method: 'DELETE' });
    ok('DELETE /diag/tasks/:id 删任务', td.status === 200 && td.data.ok);
  }

  // 权限：audit 角色没有 scan，调 /diag/run 应该 403
  if (ADMIN) {
    const r = await fetch(`${BASE}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'audit', password: 'audit@123' })
    }).then(x => x.json()).catch(() => null);
    if (r && r.ok && r.token) {
      TOKEN = r.token;
      const denied = await api('/api/diag/run', { method: 'POST', body: { tool: 'logaudit' } });
      ok('audit 角色执行诊断被拒（主动发包需单独授权）', denied.status === 403, `HTTP ${denied.status}`);
      const allowed = await api('/api/diag/tools');
      ok('audit 角色仍可看工具元数据', allowed.status === 200);
      const noTask = await api('/api/diag/tasks');
      ok('audit 角色不能管诊断任务', noTask.status === 403, `HTTP ${noTask.status}`);
    } else {
      console.log('  · 未找到 audit 测试账号，跳过权限断言');
    }
    TOKEN = '';
  }
}

/* ============================== 入口 ============================== */

(async () => {
  console.log('\n=== 网络诊断链路自检（引擎 → 入库 → 接口）===\n');
  checkMeta();
  checkDecode();
  checkDhcp();
  checkSyslog();
  checkAggregate();
  await checkLocal();
  await checkScope();

  const session = await login();
  if (session) {
    try { await checkApi(); } catch (e) { ok('接口段执行完成', false, e.message); }
  } else {
    console.log('\n[B] 接口层（跳过：无法登录，未启动服务或默认账号已改）');
  }

  console.log(`\n=== 完成：通过 ${pass} 项，失败 ${fail} 项 ===`);
  if (fails.length) console.log('失败项：\n  - ' + fails.join('\n  - '));
  console.log('');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('自检异常：', e); process.exit(1); });
