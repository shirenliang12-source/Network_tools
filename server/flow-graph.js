'use strict';
/**
 * 主机通信关系图：把会话聚合成节点（主机 IP）/ 边（通信），并通过时间分桶产出
 * 一系列图快照，供前端做「力导向布局 + 时间演化播放」的通信关系时序图。
 *
 * 设计要点：
 *  - 节点 = 主机 IP（附 /24 子网分类用于着色）；边 = 一对主机的双向/单向流量聚合。
 *  - 边的权重 = 字节数（按 App 协议取该会话的主要应用）。
 *  - buckets：把时间轴均分为 N 段，每个快照里只有「该时间窗内活跃」的节点/边被点亮，
 *    节点/边的大小按其在窗口内的流量占比缩放，从而呈现流量随时间演化的过程。
 */

function ipv4ToNum(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (let i = 0; i < 4; i++) { const x = Number(p[i]); if (!(x >= 0 && x <= 255)) return null; n = (n << 8) | x; }
  return n >>> 0;
}
/** /24 子网前缀 */
function subnet24(ip) {
  const n = ipv4ToNum(ip);
  if (n === null) return String(ip);
  return [ (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255 ].join('.') + '.0/24';
}

/** 取会话的主要应用协议（优先自定义协议） */
function appOf(s) {
  if (s.customProto) return s.customProto;
  if (s.appProto && s.appProto !== 'tcp' && s.appProto !== 'udp' && s.appProto !== 'ip') return s.appProto;
  return s.appProto || 'other';
}

function buildGraph(sessions, { buckets = 10, group = 'host' } = {}) {
  const list = Array.isArray(sessions) ? sessions : [];
  if (!list.length) return { nodes: [], links: [], buckets: [], meta: { span: 0, hosts: 0 } };

  let minT = Infinity, maxT = -Infinity;
  for (const s of list) {
    const a = Number(s.firstT || s.startedAt ? new Date(s.startedAt).getTime() / 1000 : s.lastAt || 0);
    const b = Number(s.lastAt || s.firstT || 0);
    if (isFinite(a) && a < minT) minT = a;
    if (isFinite(b) && b > maxT) maxT = b;
  }
  if (!isFinite(minT) || !isFinite(maxT)) { minT = 0; maxT = 0; }
  if (maxT <= minT) maxT = minT + 1;
  const span = maxT - minT;
  const N = Math.max(1, Math.min(60, Number(buckets) || 10));

  // 节点聚合（主机级）
  const nodeMap = new Map();
  const keyOf = (ip) => (group === 'subnet' ? subnet24(ip) : ip);
  function node(ip) {
    const k = keyOf(ip);
    let n = nodeMap.get(k);
    if (!n) { n = { id: k, ip: k, subnet: subnet24(ip), inBytes: 0, outBytes: 0, pkts: 0, apps: {}, peers: new Set() }; nodeMap.set(k, n); }
    return n;
  }

  // 边聚合
  const linkMap = new Map();
  function link(src, dst) {
    const k = src + '|' + dst;
    let l = linkMap.get(k);
    if (!l) { l = { source: src, target: dst, bytes: 0, pkts: 0, app: '' }; linkMap.set(k, l); }
    return l;
  }

  for (const s of list) {
    const src = keyOf(s.srcIp), dst = keyOf(s.dstIp);
    const ns = node(s.srcIp), nd = node(s.dstIp);
    const bytes = Number(s.bytes || 0), pkts = Number(s.pkts || 0);
    ns.outBytes += bytes; nd.inBytes += bytes; ns.pkts += pkts; nd.pkts += pkts;
    ns.peers.add(dst); nd.peers.add(src);
    const ap = appOf(s);
    ns.apps[ap] = (ns.apps[ap] || 0) + bytes; nd.apps[ap] = (nd.apps[ap] || 0) + bytes;

    const l = link(src, dst);
    l.bytes += bytes; l.pkts += pkts;
    if (!l.app) l.app = ap;
  }

  const nodes = [...nodeMap.values()].map(n => ({
    id: n.id, ip: n.ip, subnet: n.subnet,
    value: n.inBytes + n.outBytes, inBytes: n.inBytes, outBytes: n.outBytes,
    pkts: n.pkts, degree: n.peers.size,
    topApp: Object.entries(n.apps).sort((a, b) => b[1] - a[1])[0]?.[0] || ''
  }));

  const links = [...linkMap.values()].map(l => ({
    source: l.source, target: l.target, value: l.bytes, bytes: l.bytes, pkts: l.pkts, app: l.app
  }));

  // 时间分桶快照：把每个会话的流量按重叠比例分配到对应窗口
  const bucketArr = [];
  for (let i = 0; i < N; i++) {
    const t0 = minT + span * (i / N);
    const t1 = minT + span * ((i + 1) / N);
    bucketArr.push({
      index: i, t0: Math.round(t0 * 1000), t1: Math.round(t1 * 1000),
      nodes: new Map(), links: new Map()
    });
  }
  for (const s of list) {
    const a = Number(s.firstT || new Date(s.startedAt).getTime() / 1000 || s.lastAt || 0);
    const b = Number(s.lastAt || s.firstT || 0);
    if (!isFinite(a) || !isFinite(b)) continue;
    const bytes = Number(s.bytes || 0), pkts = Number(s.pkts || 0);
    const src = keyOf(s.srcIp), dst = keyOf(s.dstIp);
    let overlapTotal = 0;
    const overlaps = [];
    if (b <= a) {
      // 瞬时会话（单包/单时间戳）：归入包含该时刻的桶
      const bi = Math.min(N - 1, Math.max(0, Math.floor((a - minT) / span * N)));
      overlaps.push([bi, 1]); overlapTotal = 1;
    } else {
      for (let i = 0; i < N; i++) {
        const t0 = minT + span * (i / N), t1 = minT + span * ((i + 1) / N);
        const o0 = Math.max(a, t0), o1 = Math.min(b, t1);
        const ov = o1 > o0 ? (o1 - o0) : 0;
        if (ov > 0) { overlaps.push([i, ov]); overlapTotal += ov; }
      }
    }
    if (!overlapTotal) continue;
    for (const [i, ov] of overlaps) {
      const ratio = ov / overlapTotal;
      const bb = bucketArr[i];
      const nb = bb.nodes;
      const ns = nb.get(src) || { id: src, bytes: 0, pkts: 0 }; ns.bytes += bytes * ratio; ns.pkts += pkts * ratio; nb.set(src, ns);
      const nd = nb.get(dst) || { id: dst, bytes: 0, pkts: 0 }; nd.bytes += bytes * ratio; nd.pkts += pkts * ratio; nb.set(dst, nd);
      const lk = bb.links;
      const lkKey = src + '|' + dst;
      const ln = lk.get(lkKey) || { source: src, target: dst, bytes: 0, pkts: 0 };
      ln.bytes += bytes * ratio; ln.pkts += pkts * ratio; lk.set(lkKey, ln);
    }
  }
  const bucketsOut = bucketArr.map(b => ({
    index: b.index, t0: b.t0, t1: b.t1,
    nodes: [...b.nodes.values()].map(n => ({ id: n.id, bytes: Math.round(n.bytes), pkts: Math.round(n.pkts) })),
    links: [...b.links.values()].map(l => ({ source: l.source, target: l.target, bytes: Math.round(l.bytes) }))
  }));

  return {
    nodes, links, buckets: bucketsOut,
    meta: { span: Math.round(span * 1000), minT: Math.round(minT * 1000), maxT: Math.round(maxT * 1000), hosts: nodeMap.size, links: links.length }
  };
}

module.exports = { buildGraph, subnet24 };
