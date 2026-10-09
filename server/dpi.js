'use strict';
/**
 * 轻量协议识别（DPI）
 * 不依赖 tshark/Any 外部程序，直接解析 pcap 二进制，做「端口特征 + 握手/载荷特征」双重判定。
 * 覆盖：HTTP / HTTPS / DNS / SSH / Telnet / TLS / SNMP / NTP / SMB 及 Modbus TCP / OPC UA / S7comm /
 *       MQTT / 数据库 / RTSP 等运维与工控常见协议。
 *
 * 兼容 libpcap 常见变体（microsecond / nanosecond，大端小端），linktype 主要支持 Ethernet(1)、
 * Linux SLL(113)、Raw IP(101/12)、Loopback(0)。
 */

/** 端口特征表： port -> [协议名, 标签] */
const PORT_MAP = {
  20: ['ftp-data', ''], 21: ['ftp', ''], 22: ['ssh', '远程管理'], 23: ['telnet', '远程管理'],
  25: ['smtp', ''], 53: ['dns', '域名'], 67: ['dhcp-client', ''], 68: ['dhcp-server', ''],
  69: ['tftp', ''], 80: ['http', 'Web 服务'], 110: ['pop3', ''], 123: ['ntp', '时间同步'],
  137: ['netbios-ns', ''], 139: ['netbios-ssn', ''], 143: ['imap', ''], 161: ['snmp', '网管'],
  162: ['snmp-trap', '网管'], 389: ['ldap', ''], 443: ['https', '加密 Web'], 465: ['smtps', ''],
  465: ['smtps', ''], 636: ['ldaps', ''], 989: ['ftps-data', ''], 990: ['ftps', ''],
  1433: ['mssql', '数据库'], 1521: ['oracle', '数据库'], 2049: ['nfs', ''],
  3306: ['mysql', '数据库'], 3389: ['rdp', '远程桌面'], 5432: ['postgresql', '数据库'],
  5900: ['vnc', '远程桌面'], 5985: ['winrm', '远程管理'], 5984: ['couchdb', ''],
  6379: ['redis', '数据库'], 8080: ['http-alt', 'Web 服务'], 8081: ['http-alt', ''],
  8086: ['influxdb', '数据库'], 9090: ['prometheus', ''], 9160: ['cassandra', ''],
  8443: ['https-alt', '加密 Web'], 8888: ['http-alt', 'Web 服务'], 81: ['http-alt', 'Web 服务'],
  8008: ['http-alt', 'Web 服务'], 8000: ['http-alt', 'Web 服务'], 7000: ['http-alt', 'Web 服务'],
  10000: ['http-alt', 'Web 服务'], 10001: ['http-alt', 'Web 服务'], 448: ['ethersis', '工业控制'],
  8089: ['http-alt', ''], 8081: ['http-alt', ''], 9200: ['elasticsearch', ''],
  6224: ['tftp-opy', ''], 6001: ['x11', ''],
  8080: ['http-alt', 'Web 服务'], 8081: ['http-alt', ''],
  9200: ['elasticsearch', ''], 11211: ['memcached', ''], 27017: ['mongodb', '数据库'],
  5000: ['docker-registry', ''], 5004: ['rtp', ''], 5060: ['sip', '语音'],
  554: ['rtsp', '音视频'], 1883: ['mqtt', '物联网'], 8883: ['mqtts', '物联网'],
  502: ['modbus-tcp', '工业控制'], 102: ['s7comm', '工业控制'], 108: ['iec60870', '工业控制'],
  2404: ['iec61850', '工业控制'], 4840: ['opc-ua', '工业控制'], 44818: ['enip-cip', '工业控制'],
  34962: ['dup-hp', '工业控制'], 3141: ['gosy', '工业控制'], 4711: ['profinet', '工业控制'],
  8291: ['router-os', '网管'], 830: ['netconf', '网管'], 1610: ['netconf', '网管']
};

/** 载荷特征：命中则返回协议名 */
const PAYLOAD_SIGNATURES = [
  { proto: 'ssh', test: (b) => b.startsWith('SSH-') },
  { proto: 'telnet', test: (b) => /^\x1b\[[0-9;]*[A-Za-z]/.test(b.toString('latin1')) || b[0] === 0xff },
  { proto: 'http', test: (b) => /^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|CONNECT) \S+ HTTP\/1\.[01]\r\n/i.test(b.toString('latin1')) },
  { proto: 'http', test: (b) => /^HTTP\/1\.[01] \d{3} /i.test(b.toString('latin1')) },
  {
    proto: 'tls', test: (b) => b[0] === 0x16 && b[1] === 0x03 && (b[5] === 0x01 || b[5] === 0x02) // ClientHello / ServerHello
  },
  { proto: 'dns', test: (b) => b[0] === 0x00 && b[1] === 0x00 && (b[3] === 0x84 || b[3] === 0x81 || b[3] === 0x82 || b[3] === 0x86 || b[3] === 0x05) },
  { proto: 'dns', test: (b) => b.length >= 12 && ((b[11] & 0x80) === 0) && b[2] === 0x00 && b[3] === 0x00 && b[4] === 0x00 && b[5] === 0x00 }, // 标准查询头
  { proto: 'smb', test: (b) => b.toString('latin1', 4, 8) === '\xffSMBr' || b.toString('latin1', 8, 10) === ')b\x00' },
  // 注意：netbios 不做载荷判定（\x00\x00 头与 Modbus MBAP 头冲突），改由 137/139 端口兜底
  { proto: 'modbus-tcp', test: (b) => b.length >= 12 && b.readUInt16BE(2) === 0 && b.readUInt16BE(4) === 0 && (b[6] === 0x03 || b[6] === 0x04 || b[6] === 0x10 || b[6] === 0x06) },
  { proto: 's7comm', test: (b) => b.toString('latin1', 2, 4) === '\x00\x00' && b.toString('latin1', 6, 8) === '\x00\x00' && b[0] === 0x03 && b[1] === 0x00 },
  { proto: 'opc-ua', test: (b) => b.length >= 8 && b.readUInt32LE(2) === 0x425e0000 },
  { proto: 'mqtt', test: (b) => b.length > 4 && (b[0] >> 4) === 1 && (b[0] & 0x0f) <= 0x0d && b[2] === 0x00 },
  { proto: 'kv', test: (b) => b.toString('latin1', 0, 4) === 'KvKv' }
];

/**
 * 自定义协议匹配：端口 / 源-目的 IP 正则 / HEX 魔数（偏移+字节）三选一组合命中即视为匹配。
 * 自定义协议优先级高于内置 DPI——同一端口上既有标准协议又有业务自定义协议时，自定义胜出。
 * @returns {boolean}
 */
function customMatch(f, def) {
  if (Array.isArray(def.ports) && def.ports.length) {
    if (!def.ports.includes(f.srcPort) && !def.ports.includes(f.dstPort)) return false;
  }
  if (def.ipFilter) {
    try {
      const re = new RegExp(def.ipFilter, 'i');
      if (!(re.test(f.srcIp) || re.test(f.dstIp))) return false;
    } catch { /* 非法正则忽略该过滤器 */ }
  }
  if (def.hexOffset != null && def.hexBytes) {
    const off = Number(def.hexOffset) || 0;
    let bytes = null;
    try { bytes = Buffer.from(String(def.hexBytes).replace(/\s+/g, '').replace(/^0x/, ''), 'hex'); } catch { bytes = null; }
    if (!bytes || !bytes.length) return false;
    if (!f.payload || f.payload.length < off + bytes.length) return false;
    if (!f.payload.subarray(off, off + bytes.length).equals(bytes)) return false;
  }
  // 三项都没设 = 无效规则，永不命中
  if (!((Array.isArray(def.ports) && def.ports.length) || def.ipFilter || (def.hexOffset != null && def.hexBytes))) return false;
  return true;
}

/** 把命中的自定义协议应用到会话：覆盖 appProto 并记录业务含义 */
function applyCustomDefs(f, s, defs) {
  if (!defs || !defs.length) return;
  for (const def of defs) {
    if (def.enabled === false) continue;
    if (customMatch(f, def)) {
      s.appProto = def.name;
      s.customProto = def.name;
      if (def.desc) s.hint = Object.assign({}, s.hint, { custom: def.desc });
      return; // 首条命中即生效
    }
  }
}

/** 顺序无关：先按载荷特征判定，再用端口兜底 */
function identify(sport, dport, proto, payload) {
  const sigs = [];
  if (payload && payload.length) {
    for (const s of PAYLOAD_SIGNATURES) {
      let hit = false;
      try { hit = s.test(payload); } catch { hit = false; }
      if (hit) { sigs.push(s.proto); break; }
    }
  }
  if (sigs.length) return sigs[0];
  const a = PORT_MAP[dport] || PORT_MAP[sport];
  if (a) return a[0];
  return proto === 6 ? 'tcp' : (proto === 17 ? 'udp' : 'ip');
}

/** 抽取协议细节（HTTP 方法/域名、DNS 查询名、TLS SNI） */
function extractHint(proto, payload) {
  if (!payload || !payload.length) return {};
  try {
    if (proto === 'http' || proto === 'http-alt') {
      const txt = payload.toString('latin1', 0, Math.min(payload.length, 4096));
      const m = txt.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) (\S+) HTTP/i);
      const h = txt.match(/^Host:\s*(\S+)/im);
      const ua = txt.match(/^User-Agent:\s*(.+)/im);
      return { method: m ? m[1] : '', uri: m ? m[2] : '', host: h ? h[1] : '', ua: ua ? ua[1].slice(0, 80) : '' };
    }
    if (proto === 'dns') {
      // 从第 13 字节起找名字结束符：前 12 字节是 DNS 固定头（ID/标志/计数，可能为 0）
      const off = payload.indexOf(0, Math.min(13, payload.length - 1));
      if (off > 12) {
        const raw = payload.slice(12, off);
        const name = raw.toString('utf8').replace(/[^\x20-\x7e]/g, '');
        const qtype = payload.readUInt16BE(off + 1);
        return { qname: name, qtype };
      }
      return { qname: '' };
    }
    if (proto === 'tls' || proto === 'https') {
      // 标准 ClientHello 解析：在扩展区逐候选定位 server_name（0x0000）扩展，
      // 结构为 [类型2][长度2][列表长度2][名称类型1][保留1][域名长度2][域名]，通过校验才采信。
      // 不能只做 indexOf(0x0000) —— random 字段里也可能出现同样的字节组合。
      const mark = Buffer.from([0x00, 0x00]);
      let sni = '';
      let from = 32;
      for (;;) {
        const i = payload.indexOf(mark, from);
        if (i < 0 || i + 12 > payload.length) break;
        from = i + 1;
        if (payload[i + 2] !== 0x00 && payload[i + 6] !== 0x00) continue;   // 扩展长度 / 名称类型
        const hostLen = payload.readUInt16BE(i + 8);
        if (hostLen < 1 || hostLen > 255 || i + 10 + hostLen > payload.length) continue;
        if (payload[i + 7] !== 0x00) continue;                              // 域名前缀保留字节
        const host = payload.slice(i + 10, i + 10 + hostLen).toString('utf8');
        if (/^[\x21-\x7e][\x21-\x7e.\-\*]{0,253}$/.test(host)) { sni = host; break; }
      }
      const ver = `${payload[4] || 0}.${payload[5] || 0}`;
      return sni ? { sni, ver } : { ver };
    }
    if (proto === 'ssh') return { banner: payload.toString('latin1', 0, 40).replace(/[^\x20-\x7e]/g, '') };
  } catch { }
  return {};
}

/* ------------------------------ pcap 解析 ------------------------------ */
function parsePcap(buf, { maxSessions = 5000, customDefs = null } = {}) {
  const out = { sessions: [], packets: 0, truncated: false, linkType: 0, msClass: 'ms' };
  if (!buf || buf.length < 24) return out;
  const magic = buf.readUInt32LE(0);
  let be = false, nsec = false;
  if (magic === 0xa1b2c3d4) { be = false; nsec = false; }
  else if (magic === 0xd4c3b2a1) { be = true; nsec = false; }
  else if (magic === 0xa1b2cd34) { be = false; nsec = true; }
  else if (magic === 0x34cdb2a1) { be = true; nsec = true; }
  else return out;                       // 不是 pcap（可能是 pcapng 等）
  out.linkType = buf.readUInt32LE(20);
  const u32 = be ? (o) => buf.readUInt32BE(o) : (o) => buf.readUInt32LE(o);
  const u16 = be ? (o) => buf.readUInt16BE(o) : (o) => buf.readUInt16LE(o);

  const map = new Map();
  const connMap = new Map();          // 连接级（双向）性能状态
  let off = 24;
  let guard = 0;
  while (off + 16 <= buf.length && guard++ < 400000) {
    const capLen = u32(off + 8);
    const origLen = u32(off + 12);
    if (capLen <= 0 || off + 16 + capLen > buf.length) { out.truncated = true; break; }
    const tsSec = u32(off);
    const tsFrac = u32(off + 4);
    const data = buf.subarray(off + 16, off + 16 + Math.min(capLen, 2048));
    out.packets++;
    off += 16 + capLen;

    const t = nsec ? tsSec + tsFrac / 1e9 : tsSec + tsFrac / 1e6;
    const flow = decodeFrame(data, out.linkType, t);
    if (flow) record(map, connMap, flow, customDefs);
    if (map.size >= maxSessions) { out.truncated = true; break; }
  }
  // 把连接级（双向）指标镜像到各单向会话
  for (const c of connMap.values()) {
    if (c.synAt && c.synAckAt) {
      const hs = (c.synAckAt - c.synAt) * 1000;
      if (hs > 0 && hs < 600000) for (const s of c.sessions) s.perf.handshakeMs = Math.round(hs);
    }
    for (const s of c.sessions) {
      s.perf.fin = c.fin; s.perf.rst = c.rst;
      if (c.httpRespMs) s.perf.httpRespMs = Math.round(c.httpRespMs);
      if (c.httpReqAt) s.perf.httpReqAt = c.httpReqAt;
      if (c.dnsRespMs) s.perf.dnsRespMs = Math.round(c.dnsRespMs);
    }
  }
  out.sessions = [...map.values()].sort((a, b) => (b.lastAt || 0) - (a.lastAt || 0));
  return out;
}

/** 规范化连接键：两端点排序后拼接，使双向共享同一连接状态 */
function connKey(a, ap, b, bp) {
  const A = `${a}:${ap}`, B = `${b}:${bp}`;
  return A < B ? `${A}|${B}` : `${B}|${A}`;
}

function record(map, connMap, f, customDefs) {
  const key = `${f.proto}|${f.srcIp}:${f.srcPort}|${f.dstIp}:${f.dstPort}`;
  let s = map.get(key);
  if (!s) {
    s = {
      id: require('./store').uid('flw_'),
      srcIp: f.srcIp, dstIp: f.dstIp, srcPort: f.srcPort, dstPort: f.dstPort,
      proto: f.protoNum === 17 ? 'udp' : (f.protoNum === 1 ? 'icmp' : 'tcp'),
      appProto: '', bytes: 0, pkts: 0, durationMs: 0,
      startedAt: new Date(f.t * 1000).toISOString(),
      firstT: f.t, lastAt: f.t,
      hint: {}, tags: [],
      perf: { retrans: 0, synAt: 0, synAckAt: 0, handshakeMs: 0, httpReqAt: 0, httpRespMs: 0, dnsRespMs: 0, fin: false, rst: false }
    };
    map.set(key, s);
  }
  s.bytes += f.ipTotal || 0;
  s.pkts++;
  s.lastAt = f.t;
  // 时长按同一会话的首包时间戳算（不能用 startedAt 字符串做减法）
  s.durationMs = Math.max(1, Math.round((f.t - (s.firstT ?? f.t)) * 1000));
  // DPI 判定：载荷特征优先；无载荷时（如空会话的 SYN）由端口表兜底
  if (!s.appProto) {
    s.appProto = identify(f.srcPort, f.dstPort, f.protoNum, f.payload);
    const h = extractHint(s.appProto, f.payload);
    if (Object.keys(h).length) s.hint = h;
  }
  // 自定义协议：始终在默认 DPI 之后评估，命中则覆盖（业务自定义优先）
  applyCustomDefs(f, s, customDefs);
  const tag = PORT_MAP[f.dstPort]?.[1] || PORT_MAP[f.srcPort]?.[1];
  if (tag && !s.tags.includes(tag)) s.tags.push(tag);

  // ============ 连接级性能钻取 ============
  const ckey = connKey(f.srcIp, f.srcPort, f.dstIp, f.dstPort);
  let c = connMap.get(ckey);
  if (!c) { c = { sessions: [], synAt: 0, synAckAt: 0, retrans: 0, fin: false, rst: false, httpReqAt: 0, httpRespMs: 0, dnsPending: {}, dnsRespMs: 0, expectSeq: {} }; connMap.set(ckey, c); }
  if (!c.sessions.includes(s)) c.sessions.push(s);
  const dir = `${f.srcIp}:${f.srcPort}` === ckey.split('|')[0] ? 'A' : 'B';

  if (f.protoNum === 6) {                                   // TCP
    const fl = f.tcpFlags;
    if (fl & 0x02) {                                        // SYN
      if (!(fl & 0x10)) { c.synAt = f.t; c.expectSeq[dir] = (f.seq + 1) >>> 0; }
      else c.synAckAt = f.t;                                // SYN+ACK
    }
    if (fl & 0x10 && f.payloadLen > 0) {                    // 携带数据的 ACK
      const exp = c.expectSeq[dir];
      if (exp !== undefined) {
        const diff = (f.seq - exp) >>> 0;                   // 无符号 32 位差值（处理序列号回绕）
        if (diff === 0) c.expectSeq[dir] = (exp + f.payloadLen) >>> 0;        // 有序
        else if (diff > 0x80000000) { c.retrans++; s.perf.retrans++; }        // 序列号回退 => 重传
        else c.expectSeq[dir] = (f.seq + f.payloadLen) >>> 0;                 // 跳跃（丢包后补齐）
      }
    }
    if (fl & 0x01) c.fin = true;
    if (fl & 0x04) c.rst = true;
  }
  // HTTP 事务计时（请求/响应在不同方向，统一记在连接级）
  if (s.appProto === 'http' || s.appProto === 'http-alt') {
    const head = f.payload.toString('latin1', 0, Math.min(f.payload.length, 16));
    if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) /.test(head)) { if (!c.httpReqAt) c.httpReqAt = f.t; }
    else if (/^HTTP\/1\.[01] \d{3} /.test(head)) { if (c.httpReqAt && !c.httpRespMs) c.httpRespMs = (f.t - c.httpReqAt) * 1000; }
  }
  // DNS 响应计时（按事务 ID 配对）
  if (s.appProto === 'dns' && f.payload.length >= 4) {
    const qr = (f.payload[2] & 0x80) ? 1 : 0;
    const txn = f.payload.readUInt16BE(0);
    if (!qr) c.dnsPending[txn] = f.t;
    else if (c.dnsPending[txn] != null && !c.dnsRespMs) c.dnsRespMs = (f.t - c.dnsPending[txn]) * 1000;
  }
}

/** 链路层解码 → IP/TCP/UDP 头与载荷 */
function decodeFrame(d, linkType, t) {
  let p = 0;
  try {
    if (linkType === 1) {                       // Ethernet
      if (d.length < 14) return null;
      const type = d.readUInt16BE(12);
      p = 14;
      if (type === 0x8100 && d.length >= 18) { p = 18; }   // VLAN tag
      if (type !== 0x0800) return null;                     // 只看 IPv4
    } else if (linkType === 113 || linkType === 228) {      // Linux SLL / SLL2
      p = linkType === 113 ? 16 : 20;
    } else if (linkType === 12 || linkType === 101) {       // Raw IP
      p = 0;
    } else if (linkType === 0) {                            // Null/Loopback
      p = 4;
    } else {
      return null;
    }
    if (d.length < p + 20) return null;

    const proto = d[p + 9];
    const src = fmtIp(d, p + 12), dst = fmtIp(d, p + 16);
    const total = d.readUInt16BE(p + 2);
    let ihl = (d[p] & 0x0f) * 4;
    let pp = p + ihl;

    if (proto === 6 || proto === 17) {                      // TCP / UDP
      const sport = d.readUInt16BE(pp), dport = d.readUInt16BE(pp + 2);
      const dataOff = proto === 6 ? (d[pp + 12] >> 4) * 4 : 8;
      const payloadStart = pp + dataOff;
      const payload = d.subarray(payloadStart, Math.min(d.length, payloadStart + 1024));
      const payloadLen = Math.max(0, d.length - payloadStart);
      const tcpFlags = proto === 6 ? d[pp + 13] : 0;
      const seq = proto === 6 ? d.readUInt32BE(pp + 4) : 0;
      const ack = proto === 6 ? d.readUInt32BE(pp + 8) : 0;
      const win = proto === 6 ? d.readUInt16BE(pp + 14) : 0;
      return { srcIp: src, dstIp: dst, srcPort: sport, dstPort: dport, protoNum: proto, payload, payloadLen, t, ipTotal: total, tcpFlags, seq, ack, win };
    }
    if (proto === 1) {                                      // ICMP
      return { srcIp: src, dstIp: dst, srcPort: 0, dstPort: 0, protoNum: 1, payload: d.subarray(pp + 4), payloadLen: Math.max(0, d.length - pp - 4), t, ipTotal: total, tcpFlags: 0, seq: 0, ack: 0, win: 0 };
    }
    return { srcIp: src, dstIp: dst, srcPort: 0, dstPort: 0, protoNum: proto, payload: Buffer.alloc(0), payloadLen: 0, t, ipTotal: total, tcpFlags: 0, seq: 0, ack: 0, win: 0 };
  } catch { return null; }
}

function fmtIp(d, o) {
  return `${d[o] & 0xff}.${d[o + 1] & 0xff}.${d[o + 2] & 0xff}.${d[o + 3] & 0xff}`;
}

/** 对外：解析 pcap 文件 → { sessions, packets, ... } */
function parsePcapFile(file, opts = {}) {
  const fs = require('fs');
  if (!fs.existsSync(file)) return { sessions: [], packets: 0, error: '文件不存在' };
  const buf = fs.readFileSync(file);
  const r = parsePcap(buf, opts);
  if (!r.sessions.length && !r.packets && !r.error) r.error = '未解析到会话（可能不是标准 pcap 格式）';
  return r;
}

/** 对外：从一段原始字节流做协议识别（用于设备侧抓包回显的辅助判定） */
function sniff(payload, sport = 0, dport = 0) {
  if (!payload || !payload.length) return { appProto: 'unknown', hint: {} };
  const appProto = identify(sport, dport, 6, Buffer.from(payload));
  return { appProto, hint: extractHint(appProto, Buffer.from(payload)) };
}

module.exports = { identify, extractHint, parsePcap, parsePcapFile, sniff, PORT_MAP };
