'use strict';
/**
 * 流量性能钻取聚合（对齐 AnaTraf「分钟级定位」能力）
 * 输入：dpi.parsePcap 产出的 sessions（已含 perf 字段）+ 原始报文数
 * 输出：KPI / 协议报表 / Top Talker / 1s 粒度流量时序
 *
 * 说明：
 *  - 重传率 = 连接级重传段数 / TCP 报文数（%）。重传段在单向会话里按方向计数，避免双向重复。
 *  - 握手时延 = SYN→SYN-ACK 时间差（连接级）；HTTP/DNS 响应时间按事务配对。
 *  - 微突发/峰值速率 = 按秒聚合的「最忙 1 秒」字节×8，作为链路拥塞的快速指示（非逐项到达间隔）。
 */

function mean(a) { return a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : 0; }

function computeFlowMetrics(sessions, packets) {
  sessions = Array.isArray(sessions) ? sessions : [];
  let totalBytes = 0, tcpPkts = 0, totalPkts = 0;
  let retrans = 0, retransSessions = 0, finSessions = 0, rstSessions = 0;
  const hsList = [], httpList = [], dnsList = [];
  const byProto = {};
  const pairMap = new Map();
  let tMin = Infinity, tMax = -Infinity;

  for (const s of sessions) {
    const b = s.bytes || 0, p = s.pkts || 0;
    totalBytes += b; totalPkts += p;
    if (s.proto === 'tcp') tcpPkts += p;
    if (s.perf) {
      retrans += s.perf.retrans || 0;
      if (s.perf.retrans > 0) retransSessions++;
      if (s.perf.fin) finSessions++;
      if (s.perf.rst) rstSessions++;
      if (s.perf.handshakeMs > 0) hsList.push(s.perf.handshakeMs);
      if (s.perf.httpRespMs > 0) httpList.push(s.perf.httpRespMs);
      if (s.perf.dnsRespMs > 0) dnsList.push(s.perf.dnsRespMs);
    }
    const proto = s.appProto || s.proto || 'other';
    if (!byProto[proto]) byProto[proto] = { proto, sessions: 0, bytes: 0, pkts: 0 };
    byProto[proto].sessions++; byProto[proto].bytes += b; byProto[proto].pkts += p;

    const key = `${s.srcIp}:${s.srcPort} → ${s.dstIp}:${s.dstPort}`;
    if (!pairMap.has(key)) pairMap.set(key, { key, srcIp: s.srcIp, dstIp: s.dstIp, appProto: s.appProto, bytes: 0, sessions: 0 });
    const pm = pairMap.get(key);
    pm.bytes += b; pm.sessions++;

    if (typeof s.firstT === 'number') {
      tMin = Math.min(tMin, s.firstT);
      tMax = Math.max(tMax, s.lastAt || s.firstT);
    }
  }

  const spanMs = tMax >= tMin ? (tMax - tMin) * 1000 : 0;
  const spanSec = spanMs / 1000 || 1;
  const avgBps = Math.round(totalBytes * 8 / spanSec);

  // 1 秒粒度聚合，取最忙一秒作为微突发/峰值速率
  const buckets = new Map();
  for (const s of sessions) {
    if (typeof s.firstT !== 'number') continue;
    const bsec = Math.floor(s.firstT);
    buckets.set(bsec, (buckets.get(bsec) || 0) + (s.bytes || 0));
  }
  let peakBps = 0;
  for (const v of buckets.values()) peakBps = Math.max(peakBps, Math.round(v * 8));

  const retransRate = tcpPkts ? +(retrans / tcpPkts * 100).toFixed(2) : 0;
  const byProtoArr = Object.values(byProto).sort((a, b) => b.bytes - a.bytes).slice(0, 30);
  const topTalkers = [...pairMap.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 20);
  const timeline = [...buckets.entries()].sort((a, b) => a[0] - b[0])
    .map(([t, bytes]) => ({ t, bytes, bps: bytes * 8 }));

  return {
    ok: true,
    span: {
      from: tMin !== Infinity ? new Date(tMin * 1000).toISOString() : null,
      to: tMax !== -Infinity ? new Date(tMax * 1000).toISOString() : null,
      ms: Math.round(spanMs)
    },
    totals: {
      sessions: sessions.length,
      packets: totalPkts || (packets || 0),
      bytes: totalBytes,
      tcp: sessions.filter(s => s.proto === 'tcp').length,
      udp: sessions.filter(s => s.proto === 'udp').length
    },
    kpi: {
      retransRate, retransSegments: retrans, retransSessions,
      avgHandshakeMs: mean(hsList), handshakeSamples: hsList.length,
      avgHttpRespMs: mean(httpList), httpSamples: httpList.length,
      avgDnsRespMs: mean(dnsList), dnsSamples: dnsList.length,
      avgBps, peakBps, finSessions, rstSessions
    },
    byProto: byProtoArr,
    topTalkers,
    timeline
  };
}

module.exports = { computeFlowMetrics };
