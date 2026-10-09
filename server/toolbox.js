'use strict';
/**
 * 网络运维工具箱（NetToolbox 能力原生移植）
 * ---------------------------------------------------------------------------
 * 12 个工具，全部基于 Node 内置模块实现，Windows / Linux 双平台可用，
 * 不引入任何新的 npm 依赖，也不依赖 Python / nmap / dig / whois 等外部程序：
 *
 *   Web / 应用层   redirect       HTTP 重定向链追踪（逐跳 3xx、环路、https→http 降级）
 *                 httpcheck      HTTP(S) 可用性探测（状态码 / 耗时 / 关键字 / 标题）
 *                 sslcert        SSL/TLS 证书检测（链 / 签发者 / 剩余天数 / 弱加密）
 *                 whois          Whois / IP 归属查询（RDAP 优先，whois 回落）+ 公网出口 IP
 *   网络诊断       ping           连续探测（丢包 / 延迟 / 抖动，复用 netutil）
 *                 mtr            逐跳路由统计（系统 tracert / traceroute 采样聚合）
 *                 dnsdiag        DNS 诊断（多类型解析 + 多公共 DNS 对比 + 一致性判定）
 *                 fingerprint    服务 / OS / 设备指纹（Banner + TLS + TTL + 端口组合）
 *                 ifstat         接口实时流量（Windows 计数器 / Linux /proc/net/dev）
 *                 ntp            NTP 时间检测（UDP 123，时钟偏差 offset 与往返延迟 delay）
 *   工具           subnet         子网计算器（CIDR 解析 / VLSM 划分 / 同网段判断）
 *                 wol            远程唤醒 WoL（Magic Packet 广播）
 *
 * 安全边界：所有主动探测类接口（ping/mtr/fingerprint/ifstat/wol）在 API 层要求
 * scan 权限；目标地址由已登录的运维人员输入，请仅在自有或已获授权的网络内使用。
 */
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const dns = require('dns');
const dgram = require('dgram');
const os = require('os');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');
const netutil = require('./netutil');

const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const UA = 'NetOpsToolbox/1.0 (+netops-console)';

/* =========================================================================
   通用工具
   ========================================================================= */
function clamp(v, lo, hi, def) {
  const n = Number(v);
  if (v === undefined || v === null || v === '' || Number.isNaN(n)) return def;
  return Math.max(lo, Math.min(hi, n));
}

/** 补协议头并做合法性校验，返回规范 URL 或 null */
function normalizeUrl(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)) {
    if (/^[a-zA-Z0-9.-]+:\d+/.test(s) || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(s)) s = 'http://' + s;
    else return null;
  }
  try {
    const u = new URL(s);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.href;
  } catch { return null; }
}

function isIPv4(s) { return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(s || '').trim()); }
function isIPv6(s) { return /^[0-9a-f:]+$/i.test(String(s || '').trim()) && String(s).includes(':'); }

/** execFile 的 Promise 版，永远 resolve（不 throw），便于上层统一处理 */
function execFileP(cmd, args, timeoutMs = 30000) {
  return new Promise(resolve => {
    execFile(cmd, args, { windowsHide: true, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        code: err && typeof err.code === 'number' ? err.code : (err ? -1 : 0),
        out: String(stdout || ''),
        err: String(stderr || (err && err.message) || '')
      });
    });
  });
}

function hostToIp(host) {
  return new Promise(resolve => {
    if (isIPv4(host) || isIPv6(host)) return resolve(host);
    dns.lookup(host, (e, addr) => resolve(e ? '' : addr));
  });
}

function decodeEntities(s) {
  return String(s || '')
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (m, d) => String.fromCharCode(Number(d)))
    .replace(/\s+/g, ' ').trim();
}

/* =========================================================================
   底层 HTTP：单次请求，不自动跟随跳转（重定向追踪需要逐跳观察）
   ========================================================================= */
function requestOnce(rawUrl, opts = {}) {
  const {
    method = 'GET', timeoutMs = 8000, headers = {}, body = null,
    maxBytes = 65536, verifyCert = true, readBody = true
  } = opts;
  return new Promise(resolve => {
    let u;
    try { u = new URL(rawUrl); } catch { return resolve({ error: 'URL 解析失败：' + rawUrl }); }
    const mod = u.protocol === 'https:' ? https : (u.protocol === 'http:' ? http : null);
    if (!mod) return resolve({ error: '仅支持 http / https 协议' });
    const t0 = Date.now();
    const reqOpts = {
      method, timeout: timeoutMs,
      headers: { 'User-Agent': UA, Accept: '*/*', Connection: 'close', ...headers },
      rejectUnauthorized: verifyCert, servername: u.hostname
    };
    let settled = false;
    const done = (payload) => { if (settled) return; settled = true; clearTimeout(wd); resolve(payload); };
    /* 整体看门狗：node 的 http.request 超时只覆盖「已连接后的 socket」，
       不覆盖 DNS 解析阶段；无外网时 DNS 会静默挂起。这里兜底，保证任何情况都能返回。 */
    const wd = setTimeout(() => done({ error: '请求超时（对端不可达或 DNS 无响应）', url: rawUrl, ms: Date.now() - t0 }), timeoutMs);
    const req = mod.request(u, reqOpts, res => {
      const chunks = [];
      let size = 0;
      const finish = () => {
        const sock = res.socket || {};
        const out = {
          url: rawUrl, method,
          status: res.statusCode || 0, statusText: res.statusMessage || '',
          httpVersion: res.httpVersion || '',
          headers: res.headers || {},
          ms: Date.now() - t0,
          ip: String(sock.remoteAddress || '').replace(/^::ffff:/, ''),
          port: u.port || (u.protocol === 'https:' ? '443' : '80'),
          body: Buffer.concat(chunks).toString('utf8'),
          truncated: size > maxBytes
        };
        if (sock.getPeerX509Certificate) {
          try {
            const x = sock.getPeerX509Certificate();
            out.cert = x ? {
              subject: x.subject || '', issuer: x.issuer || '',
              validFrom: x.validFrom || '', validTo: x.validTo || '',
              serial: x.serialNumber || '', fingerprint: x.fingerprint256 || '',
              sigAlg: x.signatureAlgorithm || ''
            } : null;
            out.tlsProtocol = sock.getProtocol ? sock.getProtocol() : '';
            const c = sock.getCipher ? sock.getCipher() : null;
            out.tlsCipher = c ? c.name : '';
          } catch { /* 自签/握手异常时忽略 */ }
        }
        done(out);
      };
      if (!readBody) { res.destroy(); finish(); return; }
      res.on('data', d => { const b = Buffer.isBuffer(d) ? d : Buffer.from(d); if (size < maxBytes) { chunks.push(b); size += b.length; } });
      res.on('end', finish);
      res.on('error', finish);
    });
    req.on('timeout', () => { try { req.destroy(Object.assign(new Error('请求超时'), { code: 'timeout' })); } catch { } });
    req.on('error', e => done({ error: e.code || e.message || 'ERR', ms: Date.now() - t0, url: rawUrl }));
    if (body) { try { req.write(body); } catch { } }
    req.end();
  });
}

/** 跟随跳转取 JSON（用于 RDAP / 公网信息接口） */
async function fetchJson(url, { timeoutMs = 8000, headers = {}, maxHops = 5, maxBytes = 524288 } = {}) {
  let cur = url;
  for (let i = 0; i <= maxHops; i++) {
    const r = await requestOnce(cur, { timeoutMs, headers, maxBytes, readBody: true, verifyCert: true });
    if (r.error) return { ok: false, error: r.error };
    if (r.status >= 300 && r.status < 400 && r.headers.location) {
      cur = new URL(r.headers.location, cur).href;
      continue;
    }
    if (r.status >= 400) return { ok: false, error: `HTTP ${r.status}`, status: r.status, url: cur };
    try { return { ok: true, data: JSON.parse(r.body), url: cur, status: r.status }; }
    catch { return { ok: false, error: '响应不是合法 JSON', url: cur, status: r.status }; }
  }
  return { ok: false, error: '重定向次数过多' };
}

/* =========================================================================
   1. HTTP 重定向链追踪
   ========================================================================= */
async function redirectTrace(rawUrl, opts = {}) {
  const maxHops = clamp(opts.maxHops, 1, 30, 10);
  const timeoutMs = clamp(opts.timeoutMs, 1000, 30000, 8000);
  const method = String(opts.method || 'GET').toUpperCase();
  const verifyCert = opts.verifyCert !== false;

  let url = normalizeUrl(rawUrl);
  if (!url) return { ok: false, error: '请输入合法的起始 URL，例如 http://baidu.com' };

  const hops = [], seen = new Set();
  let loop = false, downgrade = false, upgrade = false, crossDomain = false, crossPort = false;
  let totalMs = 0, prevHost = '', prevProto = '', totalBytes = 0;

  for (let i = 0; i < maxHops; i++) {
    if (seen.has(url)) { loop = true; break; }
    seen.add(url);
    const r = await requestOnce(url, { method, timeoutMs, verifyCert, readBody: false });
    if (r.error) {
      hops.push({ n: i + 1, url, error: r.error, ms: r.ms || 0 });
      break;
    }
    let u;
    try { u = new URL(url); } catch { u = null; }
    const proto = u ? u.protocol.replace(':', '') : '';
    const host = u ? u.hostname : '';
    const hop = {
      n: i + 1, url, host, port: r.port, protocol: proto,
      status: r.status, statusText: r.statusText,
      httpVersion: r.httpVersion, ms: r.ms, ip: r.ip,
      server: r.headers.server || '',
      contentType: r.headers['content-type'] || '',
      contentLength: Number(r.headers['content-length'] || 0) || null,
      hsts: !!(r.headers['strict-transport-security']),
      setCookie: !!(r.headers['set-cookie']),
      cache: r.headers['cache-control'] || '',
      location: r.headers.location || '',
      tls: r.tlsProtocol ? { protocol: r.tlsProtocol, cipher: r.tlsCipher || '', issuer: r.cert ? r.cert.issuer : '' } : null,
      redirect: r.status >= 300 && r.status < 400
    };
    totalMs += r.ms;
    totalBytes += hop.contentLength || 0;
    hops.push(hop);

    if (prevHost && prevHost !== host) crossDomain = true;
    if (prevProto === 'https' && proto === 'http') downgrade = true;
    if (prevProto === 'http' && proto === 'https') upgrade = true;
    prevHost = host; prevProto = proto;

    if (hop.redirect && hop.location) {
      let next;
      try { next = new URL(hop.location, url).href; } catch { break; }
      const nu = new URL(next);
      if (u && nu.port !== u.port) crossPort = true;
      url = next;
      continue;
    }
    break;
  }

  const final = hops.length ? hops[hops.length - 1] : {};
  const notes = [];
  if (upgrade) notes.push('包含 http → https 升级 ✓');
  if (downgrade) notes.push('⚠ 存在 https → http 降级，链路上的凭据与内容可能被明文窃听');
  if (crossDomain) notes.push('链路跨域名跳转（可能涉及 CDN / 统一认证 / 短链服务）');
  if (crossPort) notes.push('链路跨端口跳转（常见于 80 → 8080 之类的服务迁移）');
  if (loop) notes.push('⚠ 检测到重定向环路，已提前终止，请检查服务端 Location 配置');
  const finalHop = hops.find(h => !h.redirect);
  if (finalHop && finalHop.hsts) notes.push('最终站点启用了 HSTS（Strict-Transport-Security）');
  if (!notes.length) notes.push('未发现跳转异常');

  return {
    ok: true,
    startUrl: hops[0] ? hops[0].url : url,
    hops, hopCount: hops.length,
    redirectCount: hops.filter(h => h.redirect).length,
    totalMs,
    finalUrl: final.url || '',
    finalStatus: final.status || 0,
    loop, downgrade, upgrade, crossDomain, crossPort,
    notes
  };
}

/* =========================================================================
   2. HTTP(S) 可用性探测
   ========================================================================= */
async function httpCheck(rawUrl, opts = {}) {
  const method = String(opts.method || 'GET').toUpperCase() === 'HEAD' ? 'HEAD' : 'GET';
  const timeoutMs = clamp(opts.timeoutMs, 1000, 30000, 8000);
  const keyword = String(opts.keyword || '').trim();
  const follow = opts.followRedirects !== false;
  const verifyCert = opts.verifyCert !== false;
  const expectedCode = opts.expectedCode === undefined || opts.expectedCode === null || opts.expectedCode === ''
    ? null : clamp(opts.expectedCode, 100, 599, null);

  let url = normalizeUrl(rawUrl);
  if (!url) return { ok: false, error: '请输入合法的 URL，例如 https://www.baidu.com' };

  const chain = [];
  let r = null, totalMs = 0;
  const limit = follow ? 11 : 1;
  for (let i = 0; i < limit; i++) {
    r = await requestOnce(url, {
      method, timeoutMs, verifyCert, maxBytes: 262144, readBody: method === 'GET',
      headers: method === 'GET' ? { Accept: 'text/html,application/xhtml+xml,*/*' } : {}
    });
    if (r.error) {
      return { ok: false, url, error: `请求失败：${r.error}`, chain, method };
    }
    totalMs += r.ms;
    chain.push({
      n: i + 1, url, status: r.status, statusText: r.statusText,
      ms: r.ms, location: r.headers.location || '', ip: r.ip
    });
    if (follow && r.status >= 300 && r.status < 400 && r.headers.location) {
      try { url = new URL(r.headers.location, url).href; } catch { break; }
      continue;
    }
    break;
  }

  const title = method === 'GET' ? decodeEntities((r.body.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [, ''])[1]).slice(0, 200) : '';
  const bodyLen = method === 'GET' ? Buffer.byteLength(r.body || '', 'utf8') : 0;
  const keywordFound = keyword && method === 'GET' ? r.body.includes(keyword) : null;
  const okStatus = r.status > 0 && r.status < 400;
  const codeMatched = expectedCode === null ? null : r.status === expectedCode;

  const warnings = [];
  if (!okStatus) warnings.push(`最终状态码 ${r.status}，服务可能不可用`);
  if (codeMatched === false) warnings.push(`实际状态码 ${r.status}，与预期 ${expectedCode} 不一致`);
  if (keywordFound === false) warnings.push(`响应正文中未找到关键字「${keyword}」`);
  if (r.url && r.url.startsWith('https:') && !r.tlsProtocol) warnings.push('HTTPS 握手信息缺失，证书可能异常');
  if (r.cert) {
    const days = daysUntil(r.cert.validTo);
    if (days !== null && days < 0) warnings.push(`证书已于 ${r.cert.validTo} 过期`);
    else if (days !== null && days <= 30) warnings.push(`证书 ${days} 天后到期（${r.cert.validTo}）`);
  }

  return {
    ok: true, method, url: chain[0].url,
    finalUrl: r.url, status: r.status, statusText: r.statusText,
    httpVersion: r.httpVersion, ms: r.ms, totalMs,
    ip: r.ip, server: r.headers.server || '',
    contentType: (r.headers['content-type'] || '').split(';')[0],
    contentLength: Number(r.headers['content-length'] || 0) || bodyLen || null,
    expectedCode, codeMatched, keyword, keywordFound,
    title, redirectCount: chain.length - 1, chain,
    tls: r.tlsProtocol ? { protocol: r.tlsProtocol, cipher: r.tlsCipher || '', validTo: r.cert ? r.cert.validTo : '', issuer: r.cert ? r.cert.issuer : '' } : null,
    headers: pickHeaders(r.headers),
    okStatus, warnings
  };
}

function pickHeaders(h) {
  const keys = ['server', 'content-type', 'content-length', 'cache-control', 'strict-transport-security',
    'x-powered-by', 'location', 'set-cookie', 'last-modified', 'etag', 'via', 'x-cache'];
  const out = {};
  for (const k of keys) if (h[k] !== undefined) out[k] = Array.isArray(h[k]) ? h[k].join(' | ') : String(h[k]).slice(0, 300);
  return out;
}

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const t = Date.parse(dateStr);
  if (Number.isNaN(t)) return null;
  return Math.floor((t - Date.now()) / 86400000);
}

/* =========================================================================
   3. SSL / TLS 证书检测
   ========================================================================= */
function sslCert(host, opts = {}) {
  const port = clamp(opts.port, 1, 65535, 443);
  const timeoutMs = clamp(opts.timeoutMs, 1000, 30000, 8000);
  const target = String(host || '').trim();
  if (!target) return Promise.resolve({ ok: false, error: '请填写目标主机名或 IP' });

  return new Promise(resolve => {
    const t0 = Date.now();
    let socket;
    const done = (payload) => { try { socket && socket.destroy(); } catch { } resolve(payload); };
    try {
      socket = tls.connect({ host: target, port, servername: target, rejectUnauthorized: false, timeout: timeoutMs }, () => {
        let x = null, peer = null;
        try { x = socket.getPeerX509Certificate ? socket.getPeerX509Certificate() : null; } catch { }
        try { peer = socket.getPeerCertificate(true) || null; } catch { }
        if (!x && !peer) return done({ ok: false, host: target, port, error: '未取到对端证书' });

        const chain = [];
        if (peer && peer.raw) {
          let cur = peer, guard = 0;
          while (cur && guard < 12) {
            chain.push({
              subject: (cur.subject && cur.subject.CN) || '',
              issuer: (cur.issuer && cur.issuer.CN) || '',
              validFrom: cur.valid_from || '', validTo: cur.valid_to || '',
              daysLeft: daysUntil(toISO(cur.valid_to))
            });
            const nx = cur.issuerCertificate;
            if (!nx || nx === cur || !nx.raw) break;
            cur = nx; guard++;
          }
        }

        const validFrom = x ? x.validFrom : toISO(peer.valid_from);
        const validTo = x ? x.validTo : toISO(peer.valid_to);
        const daysLeft = daysUntil(validTo);
        const subject = x ? x.subject : ((peer.subject && peer.subject.CN) || '');
        const issuer = x ? x.issuer : ((peer.issuer && peer.issuer.CN) || '');
        const sigAlg = x ? String(x.signatureAlgorithm || '') : '';
        const altName = x ? String(x.subjectAltName || '') : '';
        const san = altName.split(/,\s*/).map(s => s.replace(/^DNS:/, '').trim()).filter(Boolean).slice(0, 60);
        const subjCN = (subject.match(/CN=([^,\n]+)/) || [, subject])[1].trim();
        const issCN = (issuer.match(/CN=([^,\n]+)/) || [, issuer])[1].trim();
        const selfSigned = !!subjCN && subjCN === issCN;

        let keyBits = null;
        try { keyBits = x && x.publicKey && x.publicKey.asymmetricKeyDetails ? x.publicKey.asymmetricKeyDetails.modulusLength || null : null; } catch { }
        let protocol = '', cipher = '';
        try { protocol = socket.getProtocol() || ''; } catch { }
        try { const c = socket.getCipher(); cipher = c ? `${c.name}${c.version ? ' / ' + c.version : ''}` : ''; } catch { }

        const warnings = [];
        if (daysLeft !== null && daysLeft < 0) warnings.push({ level: 'critical', text: `证书已过期 ${Math.abs(daysLeft)} 天（${validTo}）` });
        else if (daysLeft !== null && daysLeft <= 30) warnings.push({ level: 'high', text: `证书 ${daysLeft} 天后到期，请及时续签` });
        if (selfSigned) warnings.push({ level: 'high', text: '自签名证书：浏览器与客户端会提示不受信任' });
        if (socket.authorized === false) warnings.push({ level: 'high', text: `证书链校验未通过：${socket.authorizationError || '未知原因'}` });
        if (/^TLSv1(\.0|\.1)?$/i.test(protocol)) warnings.push({ level: 'high', text: `使用了过时的 ${protocol}，建议升级到 TLS 1.2+` });
        if (/sha1|md5/i.test(sigAlg)) warnings.push({ level: 'high', text: `签名算法为 ${sigAlg}，已被认为不安全` });
        if (keyBits && keyBits < 2048) warnings.push({ level: 'medium', text: `公钥仅 ${keyBits} 位，低于 2048 位最低要求` });
        if (!san.length) warnings.push({ level: 'low', text: '证书未包含 SAN 扩展，部分客户端会拒绝' });
        if (!warnings.length) warnings.push({ level: 'ok', text: '证书链、有效期与加密套件均正常' });

        done({
          ok: true, host: target, port, ms: Date.now() - t0,
          subject: { raw: subject, cn: subjCN },
          issuer: { raw: issuer, cn: issCN },
          validFrom, validTo, daysLeft,
          expired: daysLeft !== null && daysLeft < 0,
          expiringSoon: daysLeft !== null && daysLeft >= 0 && daysLeft <= 30,
          selfSigned,
          authorized: socket.authorized === true,
          authorizationError: String(socket.authorizationError || ''),
          serial: x ? x.serialNumber : (peer.serialNumber || ''),
          fingerprint: x ? x.fingerprint256 : (peer.fingerprint256 || ''),
          sigAlg, keyBits, san, protocol, cipher, chain, warnings
        });
      });
      socket.on('error', e => done({ ok: false, host: target, port, error: e.code || e.message, ms: Date.now() - t0 }));
      socket.on('timeout', () => done({ ok: false, host: target, port, error: 'timeout', ms: Date.now() - t0 }));
    } catch (e) {
      done({ ok: false, host: target, port, error: e.message || String(e) });
    }
  });
}

/** node 的 valid_to 形如 "Sep 29 00:00:00 2026 GMT" → ISO */
function toISO(s) {
  if (!s) return '';
  const t = Date.parse(s);
  return Number.isNaN(t) ? '' : new Date(t).toISOString();
}

/* =========================================================================
   4. Whois / IP 归属查询 + 公网出口 IP
   ========================================================================= */
function whoisTcp(server, query, timeoutMs) {
  return new Promise(resolve => {
    const s = net.createConnection({ host: server, port: 43 });
    let buf = '';
    let done = false;
    const fin = (r) => { if (done) return; done = true; try { s.destroy(); } catch { } resolve(r); };
    const t = setTimeout(() => fin({ ok: false, server, error: 'timeout', raw: buf }), timeoutMs);
    s.setEncoding('utf8');
    s.on('connect', () => s.write(query + '\r\n'));
    s.on('data', d => { buf += d; if (buf.length > 262144) fin({ ok: true, server, raw: buf.slice(0, 262144) }); });
    s.on('end', () => { clearTimeout(t); fin({ ok: true, server, raw: buf }); });
    s.on('error', e => { clearTimeout(t); fin({ ok: false, server, error: e.code || e.message, raw: buf }); });
  });
}

function vcardName(ent) {
  try {
    const vc = ent.vcardArray && ent.vcardArray[1];
    if (Array.isArray(vc)) {
      const fn = vc.find(x => Array.isArray(x) && x[0] === 'fn');
      if (fn && fn[3]) return String(fn[3]);
    }
  } catch { }
  return '';
}
function entityByRole(list, role) {
  const hit = (list || []).find(e => Array.isArray(e.roles) && e.roles.includes(role));
  return hit ? { name: vcardName(hit) || hit.handle || '', handle: hit.handle || '' } : null;
}
function rdapEvents(list) {
  const out = {};
  for (const e of (list || [])) {
    if (e && e.eventAction) out[e.eventAction] = e.eventDate || '';
  }
  return out;
}

/** RDAP 查询：域名 / IP 统一入口 */
async function rdapLookup(query, isIp, timeoutMs) {
  const url = `https://rdap.org/${isIp ? 'ip' : 'domain'}/${encodeURIComponent(query)}`;
  const r = await fetchJson(url, { timeoutMs });
  if (!r.ok) return { ok: false, error: r.error };
  const d = r.data || {};
  const ev = rdapEvents(d.events);
  if (isIp) {
    const org = entityByRole(d.entities, 'registrar') || entityByRole(d.entities, 'administrative') || entityByRole(d.entities, 'abuse');
    return {
      ok: true, kind: 'ip', source: 'RDAP', sourceUrl: r.url,
      query,
      network: { handle: d.handle || '', name: d.name || '', type: d.type || '', country: d.country || '', parent: d.parentHandle || '' },
      range: [d.startAddress || '', d.endAddress || ''],
      organization: org ? org.name : '',
      registration: ev.registration || '', lastChanged: ev['last changed'] || '',
      status: d.status || [],
      raw: ''
    };
  }
  const registrar = entityByRole(d.entities, 'registrar');
  const registrant = entityByRole(d.entities, 'registrant');
  const ns = (d.nameservers || []).map(n => n.ldhName || n.unicodeName || '').filter(Boolean);
  return {
    ok: true, kind: 'domain', source: 'RDAP', sourceUrl: r.url,
    query,
    ldhName: d.ldhName || query, unicodeName: d.unicodeName || '',
    registrar: registrar ? registrar.name : '',
    registrarHandle: registrar ? registrar.handle : '',
    registrant: registrant ? registrant.name : '',
    nameservers: ns,
    status: d.status || [],
    registration: ev.registration || '',
    expiration: ev.expiration || '',
    lastChanged: ev['last changed'] || '',
    dnssec: !!(d.secureDNS && d.secureDNS.delegationSigned),
    raw: ''
  };
}

/** whois 协议查询（IANA 取权威服务器后再查一次） */
async function whoisFallback(query, isIp, timeoutMs) {
  const first = await whoisTcp('whois.iana.org', query, timeoutMs);
  if (!first.ok && !first.raw) return { ok: false, error: first.error || 'whois.iana.org 不可达' };
  const ref = (first.raw.match(/^(?:refer|whois|ReferralServer):\s*(?:whois:\/\/)?(\S+)/im) || [, ''])[1];
  let raw = first.raw, server = 'whois.iana.org';
  if (ref && !/^r?whois\.iana\.org$/i.test(ref)) {
    const second = await whoisTcp(ref, query, timeoutMs);
    if (second.raw) { raw = second.raw; server = ref; }
  }
  const grab = (re) => { const m = raw.match(re); return m ? String(m[1]).trim() : ''; };
  const fields = {
    'Domain Name': grab(/^\s*Domain Name:\s*(.+)$/im) || grab(/^\s*NetName:\s*(.+)$/im),
    'Registrar': grab(/^\s*Registrar:\s*(.+)$/im),
    'Registrant': grab(/^\s*Registrant Organization:\s*(.+)$/im) || grab(/^\s*OrgName:\s*(.+)$/im) || grab(/^\s*owner:\s*(.+)$/im),
    'Creation Date': grab(/^\s*Creation Date:\s*(.+)$/im) || grab(/^\s*created:\s*(.+)$/im),
    'Registry Expiry Date': grab(/^\s*Registry Expiry Date:\s*(.+)$/im) || grab(/^\s*Expiry Date:\s*(.+)$/im),
    'Name Server': (raw.match(/^\s*Name Server:\s*(.+)$/gim) || []).map(x => x.split(':').slice(1).join(':').trim()).filter(Boolean),
    'CIDR': grab(/^\s*CIDR:\s*(.+)$/im) || grab(/^\s*inetnum:\s*(.+)$/im) || grab(/^\s*NetRange:\s*(.+)$/im),
    'Country': grab(/^\s*Country:\s*(.+)$/im),
    'OrgName': grab(/^\s*OrgName:\s*(.+)$/im) || grab(/^\s*org-name:\s*(.+)$/im)
  };
  return { ok: true, kind: isIp ? 'ip' : 'domain', source: 'whois', server, query, fields, raw: raw.slice(0, 20000) };
}

async function whoisLookup(rawQuery, opts = {}) {
  const timeoutMs = clamp(opts.timeoutMs, 2000, 30000, 8000);
  const raw = opts.raw === true;
  let q = String(rawQuery || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '');
  if (!q) return { ok: false, error: '请输入要查询的域名或 IP' };
  const ip = isIPv4(q) || isIPv6(q);

  if (!raw) {
    const rd = await rdapLookup(q, ip, timeoutMs).catch(() => ({ ok: false, error: 'RDAP 查询异常' }));
    if (rd.ok) return rd;
    const w = await whoisFallback(q, ip, timeoutMs).catch(e => ({ ok: false, error: e.message }));
    if (w.ok) return Object.assign(w, { notice: 'RDAP 不可用，已回落到 whois 协议：' + (rd.error || '') });
    return { ok: false, error: `查询失败：RDAP ${rd.error || '-'}；whois ${w.error || '-'}` };
  }
  const w = await whoisFallback(q, ip, timeoutMs);
  return w.ok ? w : { ok: false, error: w.error || '查询失败' };
}

/** 本机公网出口 IP + 归属（Cloudflare 元数据接口，失败回落到 ipify） */
async function publicIp(opts = {}) {
  const timeoutMs = clamp(opts.timeoutMs, 2000, 20000, 6000);
  const providers = [
    {
      name: 'cloudflare', url: 'https://speed.cloudflare.com/meta',
      ip: d => d.clientIp || d.ip,
      extra: d => ({
        asn: d.asn || '', organization: d.asOrganization || d.asnOrganization || '',
        country: d.country || '', city: d.city || '', colo: d.colo || '',
        httpProtocol: d.httpProtocol || '', timezone: d.timezone || ''
      })
    },
    { name: 'ipify', url: 'https://api.ipify.org?format=json', ip: d => d.ip, extra: () => ({}) },
    { name: 'myip', url: 'https://api.my-ip.com', ip: d => d.ip, extra: () => ({}) }
  ];
  let lastErr = '';
  for (const p of providers) {
    const r = await fetchJson(p.url, { timeoutMs: Math.min(timeoutMs, 8000) });
    if (r.ok && r.data) {
      const ip = p.ip(r.data);
      if (ip) return Object.assign({ ok: true, source: p.name, ip }, p.extra(r.data));
    }
    if (r.error) lastErr = r.error;
  }
  return { ok: false, error: lastErr || '公网出口查询失败（可能无外网访问或被网络策略拦截）' };
}

/* =========================================================================
   5. Ping（复用 netutil 的跨平台实现，补 TTL / 汇总）
   ========================================================================= */
async function pingTest(host, opts = {}) {
  const target = String(host || '').trim();
  if (!target) return { ok: false, error: '请填写目标主机或 IP' };
  const count = clamp(opts.count, 1, 200, 4);
  const intervalMs = clamp(opts.intervalMs, 100, 5000, 400);
  const timeoutMs = clamp(opts.timeoutMs, 300, 10000, 1500);
  const ip = await hostToIp(target);
  const res = await netutil.ping(target, { count, intervalMs, timeoutMs });
  const ttl = await pingTtl(target);
  const grade = !res.recv ? { level: 'critical', text: '完全不通：目标无应答' }
    : res.loss >= 20 ? { level: 'high', text: `丢包 ${res.loss}%，链路质量差` }
      : res.loss > 0 ? { level: 'medium', text: `存在 ${res.loss}% 丢包` }
        : res.avg > 200 ? { level: 'medium', text: `平均延迟 ${res.avg}ms 偏高` }
          : res.avg > 80 ? { level: 'low', text: `平均延迟 ${res.avg}ms 略高` }
            : { level: 'ok', text: '连通正常，延迟与抖动均在健康区间' };
  return Object.assign({ ok: true, target, ip, ttl }, res, { grade });
}

/** 从系统 ping 的 TTL 反推对端操作系统（仅取首个有响应的包） */
function pingTtl(host) {
  return new Promise(resolve => {
    const args = IS_WIN ? ['-n', '1', '-w', '1500', host] : ['-c', '1', '-W', '2', host];
    const p = spawn('ping', args, { windowsHide: true });
    let buf = '';
    const t = setTimeout(() => { try { p.kill(); } catch { } resolve(null); }, 4000);
    p.stdout.on('data', d => buf += d.toString('latin1'));
    p.stderr.on('data', d => buf += d.toString('latin1'));
    p.on('close', () => {
      clearTimeout(t);
      const m = buf.match(/ttl[=\s](\d+)/i);
      resolve(m ? Number(m[1]) : null);
    });
    p.on('error', () => { clearTimeout(t); resolve(null); });
  });
}

/* =========================================================================
   6. MTR 逐跳路由统计
   ========================================================================= */
async function mtrTrace(host, opts = {}) {
  const target = String(host || '').trim();
  if (!target) return { ok: false, error: '请填写目标主机或 IP' };
  const maxHops = clamp(opts.maxHops, 1, 64, 20);
  const rounds = clamp(opts.rounds, 1, 6, 2);
  const probeTimeoutMs = clamp(opts.probeTimeoutMs, 500, 5000, 1000);
  const ip = await hostToIp(target);

  const args = IS_WIN
    ? ['-d', '-h', String(maxHops), '-w', String(probeTimeoutMs), target]
    : ['-n', '-q', '3', '-w', String(Math.max(1, Math.round(probeTimeoutMs / 1000))), '-m', String(maxHops), target];
  const cmd = IS_WIN ? 'tracert' : 'traceroute';

  const hops = [];
  let anyOk = false, lastErr = '', elapsedAll = 0;
  for (let i = 0; i < rounds; i++) {
    const t0 = Date.now();
    const r = await execFileP(cmd, args, maxHops * probeTimeoutMs * 3 + 15000);
    elapsedAll += Date.now() - t0;
    if (!r.out.trim()) { lastErr = r.err || r.code === -1 ? '未找到 tracert / traceroute 命令' : '无输出'; continue; }
    anyOk = true;
    mergeTrace(parseTrace(r.out), hops);
  }

  if (!anyOk) return { ok: false, target, ip, error: lastErr || '路由追踪执行失败（系统缺少 tracert / traceroute）' };

  const totalLost = hops.reduce((a, h) => a + h.lost, 0);
  const totalProbes = hops.reduce((a, h) => a + h.probes, 0);
  const reached = hops.length ? hops[hops.length - 1] : null;
  const highJitter = hops.filter(h => h.avg !== null && h.jitter > 30).map(h => h.ttl);
  const lossHops = hops.filter(h => h.loss > 20).map(h => h.ttl);
  const notes = [];
  if (lossHops.length) notes.push(`第 ${lossHops.join('、')} 跳丢包率偏高，可重点关注`);
  if (highJitter.length) notes.push(`第 ${highJitter.join('、')} 跳抖动较大（>30ms），链路可能拥塞`);
  if (reached && reached.ip && reached.ip === ip) notes.push('已完整到达目标');
  if (reached && (!reached.ip || reached.ip !== ip)) notes.push('未追踪到目标地址，可能存在防火墙拦截或路径超时');
  if (!notes.length) notes.push('各跳延迟平稳，未发现明显异常');

  return {
    ok: true, target, ip, rounds,
    hops, hopCount: hops.length,
    loss: totalProbes ? +(100 * totalLost / totalProbes).toFixed(1) : 0,
    elapsedMs: elapsedAll, notes
  };
}

/** 解析 tracert / traceroute 输出 → [{ttl, ip, ms:[], stars}]
 *  刻意不匹配 "ms" / "毫秒" 这类本地化单位词：中文 Windows 的 tracert 输出为
 *  「<1 毫秒」，按单位匹配会全部漏掉。改为「按位置取数」——除 IP 外的纯数字 /
 *  <数字 / * 才是探测样本，中英文与 Linux traceroute 三种格式都能覆盖。 */
function parseTrace(out) {
  const rows = [];
  for (const raw of String(out).split(/\r?\n/)) {
    const head = raw.match(/^\s*(\d{1,2})\s+(\S.*)$/);
    if (!head) continue;                                  // 不含表头 / 结束语
    const ttl = Number(head[1]);
    if (ttl < 1 || ttl > 64) continue;
    const ms = [];
    let stars = 0, ip = '';
    for (const tk of head[2].trim().split(/\s+/)) {
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(tk)) { if (!ip) ip = tk; continue; }
      if (tk === '*') { stars++; continue; }
      const m = tk.match(/^<?(\d+(?:\.\d+)?)$/);
      if (m) { ms.push(parseFloat(m[1])); continue; }
      if (/^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,}$/i.test(tk) && !ip) ip = tk;   // IPv6 跳
    }
    if (!ip && !ms.length && !stars) continue;
    rows.push({ ttl, ip, ms, stars });
  }
  return rows;
}

function mergeTrace(rows, hops) {
  for (const r of rows) {
    let h = hops.find(x => x.ttl === r.ttl);
    if (!h) { h = { ttl: r.ttl, ip: r.ip, ms: [], lost: 0, probes: 0 }; hops.push(h); }
    if (r.ip && !h.ip) h.ip = r.ip;
    if (r.ip) h.lastIp = r.ip;
    h.ms.push(...r.ms);
    h.lost += r.stars;
    h.probes += r.ms.length + r.stars;
  }
  hops.sort((a, b) => a.ttl - b.ttl);
  for (const h of hops) {
    const ok = h.ms.length;
    h.avg = ok ? +(h.ms.reduce((a, b) => a + b, 0) / ok).toFixed(2) : null;
    h.min = ok ? Math.min(...h.ms) : null;
    h.max = ok ? Math.max(...h.ms) : null;
    h.stddev = ok > 1 ? +Math.sqrt(h.ms.reduce((a, b) => a + (b - h.avg) ** 2, 0) / ok).toFixed(2) : 0;
    h.jitter = h.stddev;
    h.loss = h.probes ? +(100 * h.lost / h.probes).toFixed(1) : 0;
  }
}

/* =========================================================================
   7. DNS 诊断：多类型解析 + 多公共 DNS 对比
   ========================================================================= */
const PUBLIC_DNS = [
  { name: '阿里 DNS', ip: '223.5.5.5' },
  { name: '腾讯 DNSPod', ip: '119.29.29.29' },
  { name: 'Google', ip: '8.8.8.8' },
  { name: 'Cloudflare', ip: '1.1.1.1' }
];
const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA'];

function resolveWith(server, domain, type, timeoutMs) {
  return new Promise(resolve => {
    const res = new dns.Resolver({ timeout: timeoutMs, tries: 1 });
    if (server) { try { res.setServers([server]); } catch { } }
    const fn = res.resolve ? res.resolve.bind(res) : null;
    if (!fn) return resolve({ type, ok: false, error: 'unsupported' });
    fn(domain, type, (e, recs) => {
      if (e) return resolve({ type, ok: false, code: e.code || '', error: e.code || e.message });
      resolve({ type, ok: true, records: formatRecords(type, recs) });
    });
  });
}

function formatRecords(type, recs) {
  const list = Array.isArray(recs) ? recs : (recs ? [recs] : []);
  return list.map(r => {
    if (typeof r === 'string') return r;
    if (type === 'MX') return `${r.exchange} (优先级 ${r.priority})`;
    if (type === 'SOA') return `${r.nsname} / ${r.hostmaster} 序列号 ${r.serial}`;
    if (type === 'SRV') return `${r.name}:${r.port} 权重 ${r.weight} 优先级 ${r.priority}`;
    if (r.address) return r.address;
    if (r.value) return r.value;
    return JSON.stringify(r);
  });
}

async function dnsDiag(rawDomain, opts = {}) {
  const domain = String(rawDomain || '').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  if (!domain) return { ok: false, error: '请输入要诊断的域名，例如 baidu.com' };
  const timeoutMs = clamp(opts.timeoutMs, 1000, 15000, 4000);
  const types = Array.isArray(opts.types) && opts.types.length
    ? opts.types.filter(t => DNS_TYPES.includes(String(t).toUpperCase())).map(t => String(t).toUpperCase())
    : ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'];
  const wantCompare = opts.compare !== false;

  const systemRes = await Promise.all(types.map(t => resolveWith(null, domain, t, timeoutMs)));
  const system = {};
  for (const r of systemRes) system[r.type] = { ok: r.ok, records: r.records || [], error: r.error || '' };

  let servers = [];
  if (wantCompare) {
    servers = await Promise.all(PUBLIC_DNS.map(async s => {
      const t0 = Date.now();
      const out = {};
      const rs = await Promise.all(types.map(t => resolveWith(s.ip, domain, t, timeoutMs)));
      for (const r of rs) out[r.type] = { ok: r.ok, records: r.records || [], error: r.error || '' };
      const aOnly = (out.A && out.A.records) || [];
      return { name: s.name, ip: s.ip, ms: Date.now() - t0, results: out, a: aOnly, ok: aOnly.length > 0 || !!out.NS };
    }));
  }

  const systemA = (system.A && system.A.records) || [];
  const notes = [], sets = new Map();
  for (const s of servers) {
    if (!s.ok) { notes.push(`${s.name}（${s.ip}）解析失败：${(s.results.A && s.results.A.error) || '无响应'}`); continue; }
    const key = [...s.a].sort().join('|');
    if (!sets.has(key)) sets.set(key, []);
    sets.get(key).push(s.name);
  }
  const consistent = sets.size <= 1;
  let hijack = false;
  if (sets.size > 1) {
    const groups = [...sets.values()];
    notes.push(`不同 DNS 返回结果不一致：${groups.map(g => g.join('/')).join('  ≠  ')}`);
    const aHasPrivate = systemA.some(ip => isPrivateIp(ip));
    const pubHas = servers.some(s => s.a.some(ip => !isPrivateIp(ip)));
    if (aHasPrivate && pubHas) { hijack = true; notes.push('⚠ 本机 DNS 返回了内网地址而公共 DNS 返回公网地址，疑似被劫持或存在内网分流'); }
    else notes.push('可能是 CDN 就近调度（多地解析结果本就不同），需结合业务判断');
  } else if (sets.size === 1 && servers.length) {
    notes.push('所有公共 DNS 解析结果一致');
  }
  if (!systemA.length) notes.push('本机系统 DNS 未能解析出 A 记录');
  if (!notes.length) notes.push('解析行为正常');

  return {
    ok: true, domain, system, servers, types,
    consistent, hijack, notes,
    systemA
  };
}

function isPrivateIp(ip) {
  const p = String(ip).split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n))) return false;
  if (p[0] === 10 || p[0] === 127) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  return false;
}

/* =========================================================================
   8. 服务 / OS / 设备指纹
   ========================================================================= */
const SERVICE_MAP = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 554: 'RTSP',
  587: 'SMTP', 631: 'IPP', 873: 'Rsync', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
  1521: 'Oracle', 2049: 'NFS', 2375: 'Docker API', 3306: 'MySQL', 3389: 'RDP',
  5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy',
  8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9100: 'Printer(RAW)', 9200: 'Elasticsearch',
  11211: 'Memcached', 27017: 'MongoDB', 161: 'SNMP', 162: 'SNMPTrap', 5000: 'UPnP'
};
const DEFAULT_FP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 631, 1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9100, 9200, 11211, 27017];
const HIGH_RISK_PORTS = {
  23: { level: 'high', text: 'Telnet 明文管理端口开放，口令与配置可被嗅探' },
  2375: { level: 'critical', text: 'Docker API 未加密开放，等同于把宿主机控制权暴露出去' },
  9200: { level: 'critical', text: 'Elasticsearch 默认无鉴权，数据可被任意读写' },
  11211: { level: 'critical', text: 'Memcached 开放，可被用于放大攻击与数据泄露' },
  6379: { level: 'high', text: 'Redis 开放，未设口令时可写入文件获取权限' },
  27017: { level: 'high', text: 'MongoDB 开放，暴露在外网风险极高' },
  5900: { level: 'high', text: 'VNC 开放，弱口令即可远程接管桌面' },
  3389: { level: 'medium', text: 'RDP 开放，注意口令强度与暴力破解防护' },
  445: { level: 'medium', text: 'SMB 开放，注意永恒之蓝类漏洞与共享权限' },
  21: { level: 'medium', text: 'FTP 明文传输，建议改用 SFTP / FTPS' },
  1433: { level: 'high', text: 'MSSQL 数据库直接暴露' },
  3306: { level: 'high', text: 'MySQL 数据库直接暴露' },
  5432: { level: 'high', text: 'PostgreSQL 数据库直接暴露' },
  161: { level: 'medium', text: 'SNMP 开放，请确认已改默认团体字并做访问控制' }
};

function grabBanner(host, port, timeoutMs, probe) {
  return new Promise(resolve => {
    const s = net.createConnection({ host, port });
    let buf = '';
    let done = false;
    const fin = (r) => { if (done) return; done = true; try { s.destroy(); } catch { } resolve(r); };
    const t = setTimeout(() => fin({ ok: false, error: 'timeout', banner: clean(buf) }), timeoutMs);
    s.setTimeout(timeoutMs);
    s.on('connect', () => { if (probe) { try { s.write(probe); } catch { } } });
    s.setEncoding('latin1');
    s.on('data', d => { buf += d; if (buf.length > 4096) { clearTimeout(t); fin({ ok: true, banner: clean(buf) }); } });
    s.on('close', () => { clearTimeout(t); fin({ ok: true, banner: clean(buf) }); });
    s.on('timeout', () => { clearTimeout(t); fin({ ok: true, banner: clean(buf) }); });
    s.on('error', e => { clearTimeout(t); fin({ ok: false, error: e.code || e.message, banner: clean(buf) }); });
  });
}
function clean(s) { return String(s || '').replace(/[\x00-\x08\x0e-\x1f]/g, '').trim().slice(0, 400); }

async function fingerprintHost(rawHost, opts = {}) {
  const host = String(rawHost || '').trim();
  if (!host) return { ok: false, error: '请填写目标主机或 IP' };
  const timeoutMs = clamp(opts.timeoutMs, 300, 8000, 1200);
  let ports = Array.isArray(opts.ports) ? opts.ports : [];
  if (typeof opts.ports === 'string' && opts.ports.trim()) {
    ports = opts.ports.split(/[,\s]+/).map(x => Number(String(x).split('-')[0])).filter(n => n > 0 && n <= 65535);
  }
  if (!ports.length) ports = opts.full ? DEFAULT_FP_PORTS : [21, 22, 23, 80, 135, 139, 443, 445, 554, 3389, 3306, 6379, 8080, 8443];
  ports = [...new Set(ports)].slice(0, 64);

  const ip = await hostToIp(host);
  const results = [];
  const concurrency = 24;
  let idx = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, async () => {
    while (idx < ports.length) {
      const port = ports[idx++];
      const c = await netutil.tcpConnect(host, port, timeoutMs);
      const item = { port, service: SERVICE_MAP[port] || '', open: !!c.ok, ms: c.ms, banner: '', title: '', server: '', cert: null, error: c.error || '' };
      if (c.ok) {
        if (port === 443 || port === 8443) {
          const t = await tlsProbe(host, port, timeoutMs + 2000);
          item.banner = t.banner || '';
          item.cert = t.cert || null;
          item.server = t.server || '';
        } else if ([80, 8000, 8080, 8888, 5000].includes(port)) {
          const b = await grabBanner(host, port, timeoutMs + 1200, `HEAD / HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: ${UA}\r\n\r\n`);
          item.banner = b.banner || '';
          item.server = headerOf(b.banner, 'server');
          item.title = '';
        } else {
          const b = await grabBanner(host, port, timeoutMs + 1000, null);
          item.banner = b.banner || '';
        }
      }
      results.push(item);
    }
  }));
  results.sort((a, b) => a.port - b.port);
  const open = results.filter(r => r.open);

  const ttl = await pingTtl(host);
  const osGuess = guessOs(ttl);
  const device = guessDevice(open, results, osGuess);
  const risks = riskOf(open, device);
  const vendorHint = detectFromBanner(open);

  return {
    ok: true, host, ip, ttl, osGuess, deviceType: device, vendorHint,
    ports: results, openPorts: open.map(r => r.port),
    services: open.map(r => `${r.port}/${r.service || 'unknown'}`),
    risks,
    scanned: ports.length, openCount: open.length
  };
}

function headerOf(banner, name) {
  const m = String(banner || '').match(new RegExp('^' + name + ':\\s*(.+)$', 'im'));
  return m ? m[1].trim().slice(0, 200) : '';
}

function tlsProbe(host, port, timeoutMs) {
  return new Promise(resolve => {
    let s;
    let done = false;
    const fin = (r) => { if (done) return; done = true; try { s && s.destroy(); } catch { } resolve(r); };
    try {
      s = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
        let cert = null;
        try {
          const x = s.getPeerX509Certificate ? s.getPeerX509Certificate() : null;
          if (x) cert = { subject: x.subject || '', issuer: x.issuer || '', validTo: x.validTo || '', sigAlg: String(x.signatureAlgorithm || '') };
        } catch { }
        let protocol = '';
        try { protocol = s.getProtocol() || ''; } catch { }
        fin({ banner: protocol ? `TLS ${protocol}` : '', cert, server: '' });
      });
      s.on('error', () => fin({ banner: '', cert: null, server: '' }));
      s.on('timeout', () => fin({ banner: '', cert: null, server: '' }));
    } catch { fin({ banner: '', cert: null, server: '' }); }
  });
}

function guessOs(ttl) {
  if (!ttl) return { name: '未知', hint: '未取到 ICMP TTL（可能被防火墙拦截，或目标禁 Ping）', ttl: null };
  if (ttl <= 65) return { name: 'Linux / Unix', hint: 'TTL ≈ 64，典型 Linux、BSD 或网络设备', ttl };
  if (ttl <= 129) return { name: 'Windows', hint: 'TTL ≈ 128，典型 Windows 主机', ttl };
  return { name: '网络设备 / 其他', hint: 'TTL ≈ 255，多为路由器 / 交换机 / 防火墙', ttl };
}

function guessDevice(open, all, osGuess) {
  const p = new Set(open.map(o => o.port));
  const has = (...x) => x.every(v => p.has(v));
  const any = (...x) => x.some(v => p.has(v));
  if (has(30678) || (any(554, 8000, 37777) && any(80, 443, 8000)) || p.has(34567)) return '视频监控（IPC / NVR / DVR）';
  if (p.has(9100) || p.has(631)) return '网络打印机';
  if (has(445, 139) || has(445, 135) || (p.has(3389) && p.has(135))) return 'Windows 主机';
  if (p.has(161) && !any(80, 443, 445, 3389)) return '网络设备（交换机 / 路由器 / 防火墙）';
  if (any(2375, 3306, 5432, 6379, 9200, 11211, 27017) && any(22, 80, 443, 8080)) return '服务器（含数据库 / 容器服务）';
  if (p.has(22) || p.has(23)) return osGuess && osGuess.name === 'Windows' ? 'Windows 主机' : 'Linux / Unix 主机';
  if (any(80, 443, 8080, 8443)) return 'Web 服务主机';
  if (!open.length) return '未识别（无开放端口或全被过滤）';
  return '通用主机（' + all.filter(a => a.open).slice(0, 3).map(a => a.service || a.port).join(' / ') + '）';
}

function detectFromBanner(open) {
  for (const o of open) {
    const b = (o.banner || '') + ' ' + (o.server || '') + ' ' + ((o.cert && o.cert.subject) || '');
    const hit = b.match(/MikroTik|RouterOS|Cisco|Huawei|H3C|Fortinet|FortiGate|Palo Alto|pfSense|OpenWrt|Ubiquiti|Hikvision|Dahua|Axis|TP-LINK|HPE|Aruba|Linux|Ubuntu|Debian|CentOS|Windows|Microsoft-IIS|nginx|Apache|Tomcat|Jetty|lighttpd|OpenSSH/i);
    if (hit) return hit[0];
  }
  return '';
}

function riskOf(open, device) {
  const risks = [];
  for (const o of open) {
    const r = HIGH_RISK_PORTS[o.port];
    if (r) risks.push({ port: o.port, service: SERVICE_MAP[o.port] || '', level: r.level, text: r.text });
  }
  if (/视频监控/.test(device)) {
    risks.push({ port: 554, service: 'RTSP', level: 'high', text: '疑似视频监控设备，注意 RTSP 是否可未鉴权拉流（可在诊断工具箱做摄像头专扫）' });
  }
  if (!risks.length) {
    risks.push({ port: 0, service: '', level: open.length ? 'low' : 'ok', text: open.length ? '未命中高危端口规则，仍建议核对每个开放端口的业务必要性' : '未发现开放端口' });
  }
  return risks;
}

/* =========================================================================
   9. 接口实时流量
   ========================================================================= */
function readCounters() {
  if (IS_WIN) {
    return execFileP('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Csv -NoTypeInformation'
    ], 15000).then(r => {
      if (!r.out) return [];
      const out = [];
      const lines = r.out.split(/\r?\n/).filter(l => l.trim());
      for (const line of lines.slice(1)) {
        const cols = line.split(',').map(c => c.replace(/^"|"$/g, '').trim());
        if (cols.length < 3) continue;
        const name = cols[0]; const rx = Number(cols[1]); const tx = Number(cols[2]);
        if (!name || Number.isNaN(rx) || Number.isNaN(tx)) continue;
        out.push({ name, rx, tx });
      }
      return out;
    }).catch(() => []);
  }
  return new Promise(resolve => {
    if (IS_MAC) {
      // macOS 无 /proc/net/dev，用 netstat -ib
      execFileP('netstat', ['-ib'], 5000).then(r => {
        if (!r.out) return resolve([]);
        const out = [];
        const lines = r.out.split(/\r?\n/).filter(l => l.trim());
        for (const line of lines.slice(1)) {
          const cols = line.split(/\s+/);
          // Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
          if (cols.length < 11) continue;
          const name = cols[0];
          const rx = Number(cols[6]);
          const tx = Number(cols[9]);
          if (!name || Number.isNaN(rx) || Number.isNaN(tx)) continue;
          out.push({ name, rx, tx });
        }
        resolve(out);
      }).catch(() => resolve([]));
      return;
    }
    const fs = require('fs');
    fs.readFile('/proc/net/dev', 'utf8', (e, txt) => {
      if (e) return resolve([]);
      const out = [];
      for (const line of txt.split('\n').slice(2)) {
        const [namePart, rest] = line.split(':');
        if (!rest) continue;
        const cols = rest.trim().split(/\s+/);
        const rx = Number(cols[0]); const tx = Number(cols[8]);
        const name = String(namePart || '').trim();
        if (!name || Number.isNaN(rx) || Number.isNaN(tx)) continue;
        out.push({ name, rx, tx });
      }
      resolve(out);
    });
  });
}

async function ifstat(opts = {}) {
  const rounds = clamp(opts.rounds, 2, 20, 6);
  const intervalMs = clamp(opts.intervalMs, 500, 5000, 1000);
  const first = await readCounters();
  if (!first.length) return { ok: false, error: IS_WIN ? '未能读取网卡计数器（Get-NetAdapterStatistics 无输出）' : (IS_MAC ? '未能读取网卡计数器（netstat -ib 无输出）' : '未能读取 /proc/net/dev') };

  const t0 = Date.now();
  const series = [];
  let prev = first;
  for (let i = 0; i < rounds - 1; i++) {
    await new Promise(r => setTimeout(r, intervalMs));
    const cur = await readCounters();
    const snap = { ts: Date.now(), adapters: {} };
    for (const c of cur) {
      const p = prev.find(x => x.name === c.name);
      if (!p) continue;
      const sec = intervalMs / 1000;
      snap.adapters[c.name] = {
        rxBps: Math.max(0, (c.rx - p.rx) * 8 / sec),
        txBps: Math.max(0, (c.tx - p.tx) * 8 / sec),
        rxBytes: c.rx, txBytes: c.tx
      };
    }
    series.push(snap);
    prev = cur;
  }

  const names = [...new Set(series.flatMap(s => Object.keys(s.adapters)))];
  const adapters = names.map(name => {
    const samples = series.map(s => s.adapters[name]).filter(Boolean);
    const avg = (k) => samples.length ? samples.reduce((a, b) => a + b[k], 0) / samples.length : 0;
    const rxBps = avg('rxBps'), txBps = avg('txBps');
    const last = samples[samples.length - 1] || {};
    return {
      name,
      rxBps, txBps,
      rxHuman: humanBps(rxBps), txHuman: humanBps(txBps),
      peakRx: samples.length ? Math.max(...samples.map(s => s.rxBps)) : 0,
      peakTx: samples.length ? Math.max(...samples.map(s => s.txBps)) : 0,
      rxBytes: last.rxBytes || 0, txBytes: last.txBytes || 0,
      history: samples.map(s => ({ rx: Math.round(s.rxBps), tx: Math.round(s.txBps) }))
    };
  }).filter(a => a.rxBytes || a.txBytes).sort((a, b) => (b.rxBps + b.txBps) - (a.rxBps + a.txBps));

  return {
    ok: true, rounds, intervalMs, seconds: (rounds - 1) * intervalMs / 1000,
    adapters,
    totalRxBps: adapters.reduce((a, b) => a + b.rxBps, 0),
    totalTxBps: adapters.reduce((a, b) => a + b.txBps, 0),
    labels: series.map((s, i) => `${(i + 1) * intervalMs / 1000}s`),
    timestamps: series.map(s => s.ts)
  };
}

function humanBps(v) {
  v = Number(v) || 0;
  if (v >= 1e9) return (v / 1e9).toFixed(2) + ' Gbps';
  if (v >= 1e6) return (v / 1e6).toFixed(2) + ' Mbps';
  if (v >= 1e3) return (v / 1e3).toFixed(2) + ' Kbps';
  return Math.round(v) + ' bps';
}

/* =========================================================================
   10. NTP 时间检测
   ========================================================================= */
const NTP_SERVERS = ['ntp.aliyun.com', 'time.windows.com', 'cn.pool.ntp.org', 'time.cloudflare.com'];
const NTP_EPOCH_DELTA = 2208988800;

function ntpOnce(server, timeoutMs) {
  return new Promise(resolve => {
    const sock = dgram.createSocket('udp4');
    const buf = Buffer.alloc(48);
    buf[0] = 0x1b;                       // LI=0 VN=3 Mode=3（客户端）
    const t1 = Date.now();
    let done = false;
    const fin = (r) => { if (done) return; done = true; try { sock.close(); } catch { } resolve(r); };
    const timer = setTimeout(() => fin({ server, ok: false, error: 'timeout' }), timeoutMs);
    sock.on('message', msg => {
      const t4 = Date.now();
      clearTimeout(timer);
      if (msg.length < 48) return fin({ server, ok: false, error: '应答长度不足' });
      const stratum = msg[1] & 0x7f;
      const refId = msg.subarray(12, 16).toString('latin1').replace(/[\x00-\x1f]/g, '');
      const t2 = readNtpTs(msg, 32), t3 = readNtpTs(msg, 40);
      const offset = ((t2 - t1) + (t3 - t4)) / 2;
      const delay = (t4 - t1) - (t3 - t2);
      fin({
        server, ok: true,
        offsetMs: +offset.toFixed(2), delayMs: +Math.max(0, delay).toFixed(2),
        stratum, refId, version: (msg[0] >> 3) & 0x7, leap: msg[0] >> 6,
        serverTime: new Date(t3).toISOString()
      });
    });
    sock.on('error', e => { clearTimeout(timer); fin({ server, ok: false, error: e.code || e.message }); });
    sock.send(buf, 0, 48, 123, server, err => { if (err) { clearTimeout(timer); fin({ server, ok: false, error: err.code || err.message }); } });
  });
}

function readNtpTs(buf, off) {
  const secs = buf.readUInt32BE(off);
  const frac = buf.readUInt32BE(off + 4);
  return (secs - NTP_EPOCH_DELTA) * 1000 + (frac / 4294967296) * 1000;
}

async function ntpQuery(opts = {}) {
  const timeoutMs = clamp(opts.timeoutMs, 1000, 15000, 3000);
  let servers = opts.servers;
  if (typeof servers === 'string') servers = servers.split(/[,\s]+/).filter(Boolean);
  if (!Array.isArray(servers) || !servers.length) servers = NTP_SERVERS.slice(0, 4);
  servers = servers.slice(0, 8).map(s => String(s).trim()).filter(Boolean);
  if (!servers.length) return { ok: false, error: '请至少提供一个 NTP 服务器地址' };

  const results = await Promise.all(servers.map(s => ntpOnce(s, timeoutMs)));
  const usable = results.filter(r => r.ok);
  const best = usable.slice().sort((a, b) => Math.abs(a.offsetMs) - Math.abs(b.offsetMs))[0] || null;
  const notes = [];
  if (!usable.length) notes.push('所有时间源均无响应，请检查本机是否放行 UDP 123 出方向');
  else if (best && Math.abs(best.offsetMs) < 50) notes.push(`本机时钟偏差 ${best.offsetMs}ms，处于健康区间（±50ms 内）`);
  else if (best && Math.abs(best.offsetMs) < 1000) notes.push(`本机时钟偏差 ${best.offsetMs}ms，建议校时（w32tm /resync 或 chronyc makestep）`);
  else if (best) notes.push(`⚠ 本机时钟偏差达 ${best.offsetMs}ms（约 ${(Math.abs(best.offsetMs) / 1000).toFixed(1)} 秒），会明显影响日志取证与证书校验，请立即校时`);
  if (usable.length > 1) {
    const spread = Math.max(...usable.map(r => r.offsetMs)) - Math.min(...usable.map(r => r.offsetMs));
    if (spread > 100) notes.push(`各时间源之间读数差异达 ${spread.toFixed(0)}ms，网络不对称或某源不准确`);
  }
  return { ok: true, servers, results, best, usableCount: usable.length, notes, now: new Date().toISOString() };
}

/* =========================================================================
   11. 子网计算器（纯计算，零依赖）
   ========================================================================= */
function ipToInt(ip) {
  const p = String(ip).trim().split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}
function intToIp(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
function maskOf(prefix) { return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0; }
function cls(ip) {
  const f = Number(String(ip).split('.')[0]);
  if (f < 128) return 'A';
  if (f < 192) return 'B';
  if (f < 224) return 'C';
  if (f < 240) return 'D（组播）';
  return 'E（保留）';
}

function parseCidrSpec(spec) {
  const s = String(spec || '').trim();
  const m = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*\/\s*(\d{1,2})$/);
  if (m) {
    const ip = ipToInt(m[1]), prefix = Number(m[2]);
    if (ip === null) return { error: `IP 地址不合法：${m[1]}` };
    if (prefix < 0 || prefix > 32) return { error: `前缀长度不合法：/${m[2]}` };
    return { ip, prefix };
  }
  const m2 = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (m2) {
    const ip = ipToInt(m2[1]), mask = ipToInt(m2[2]);
    if (ip === null) return { error: `IP 地址不合法：${m2[1]}` };
    if (mask === null) return { error: `掩码不合法：${m2[2]}` };
    const inv = (~mask) >>> 0;
    if ((inv & (inv + 1)) !== 0) return { error: `掩码不是连续 1：${m2[2]}` };
    return { ip, prefix: 32 - Math.log2((inv + 1) >>> 0) };
  }
  const m3 = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (m3) {
    const ip = ipToInt(m3[1]);
    if (ip === null) return { error: `IP 地址不合法：${m3[1]}` };
    return { ip, prefix: 32 };
  }
  return { error: '格式应为 192.168.10.0/24、192.168.10.0 255.255.255.0 或 192.168.10.10' };
}

function subnetAnalyze(spec) {
  const p = parseCidrSpec(spec);
  if (p.error) return { ok: false, error: p.error };
  const { ip, prefix } = p;
  const mask = maskOf(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const total = Math.pow(2, 32 - prefix);
  const usable = prefix >= 31 ? total : total - 2;
  const first = prefix >= 31 ? network : network + 1;
  const last = prefix >= 31 ? broadcast : broadcast - 1;
  return {
    ok: true,
    input: String(spec).trim(),
    address: intToIp(ip),
    prefix, mask: intToIp(mask), wildcard: intToIp((~mask) >>> 0),
    network: intToIp(network), broadcast: intToIp(broadcast),
    firstHost: usable > 0 ? intToIp(first) : '',
    lastHost: usable > 0 ? intToIp(last) : '',
    total, usable,
    isNetworkAddr: ip === network,
    isBroadcastAddr: ip === broadcast,
    addressClass: cls(intToIp(ip)),
    scope: isPrivateIp(intToIp(ip)) ? '私有地址（RFC1918 / 保留段）' : '公网地址',
    notes: [
      prefix === 32 ? '单个主机地址（/32）' : prefix === 31 ? '点对点链路（/31，两个地址均可用）' : `可用主机地址 ${usable} 个`
    ]
  };
}

/** VLSM：按需求大小从大到小分配，需求形如 "50,20,10" 或 [{"name":"财务","size":50}] */
function subnetVlsm(cidr, needs) {
  const p = parseCidrSpec(cidr);
  if (p.error) return { ok: false, error: p.error };
  const base = (p.ip & maskOf(p.prefix)) >>> 0;
  const poolEnd = (base | (~maskOf(p.prefix) >>> 0)) >>> 0;
  let list = [];
  if (typeof needs === 'string') {
    list = needs.split(/[,\s]+/).filter(Boolean).map((s, i) => ({ name: `子网 ${i + 1}`, size: Number(s) }));
  } else if (Array.isArray(needs)) {
    list = needs.map((n, i) => (typeof n === 'object' && n !== null)
      ? { name: String(n.name || `子网 ${i + 1}`), size: Number(n.size || n.hosts || 0) }
      : { name: `子网 ${i + 1}`, size: Number(n) });
  }
  list = list.filter(n => n.size > 0);
  if (!list.length) return { ok: false, error: '请提供至少一个子网大小需求，例如 50,20,10' };
  list.sort((a, b) => b.size - a.size);

  const out = [];
  let cursor = base;
  for (const n of list) {
    const need = n.size + 2;
    let bits = Math.ceil(Math.log2(need));
    if (bits < 2) bits = 2;
    const size = Math.pow(2, bits);
    const prefix = 32 - bits;
    if (cursor + size - 1 > poolEnd) {
      out.push({ name: n.name, size: n.size, error: '地址空间不足，无法分配' });
      continue;
    }
    const net = cursor, bc = (cursor + size - 1) >>> 0;
    out.push({
      name: n.name, size: n.size, prefix: `/${prefix}`,
      network: intToIp(net), broadcast: intToIp(bc),
      firstHost: bits > 1 ? intToIp(net + 1) : intToIp(net),
      lastHost: bits > 1 ? intToIp(bc - 1) : intToIp(bc),
      total: size, usable: bits > 1 ? size - 2 : size
    });
    cursor = bc + 1;
  }
  const used = cursor - base;
  return {
    ok: true, base: `${intToIp(base)}/${p.prefix}`, poolSize: poolEnd - base + 1,
    allocations: out, used, free: (poolEnd - base + 1) - used,
    freeRange: used <= poolEnd - base ? `${intToIp(cursor)} - ${intToIp(poolEnd)}` : ''
  };
}

function subnetSame(a, b, prefix) {
  const ia = ipToInt(a), ib = ipToInt(b);
  if (ia === null) return { ok: false, error: `IP 不合法：${a}` };
  if (ib === null) return { ok: false, error: `IP 不合法：${b}` };
  const pre = clamp(prefix, 0, 32, 24);
  const m = maskOf(pre);
  const na = (ia & m) >>> 0, nb = (ib & m) >>> 0;
  return {
    ok: true, a, b, prefix: pre,
    networkA: `${intToIp(na)}/${pre}`, networkB: `${intToIp(nb)}/${pre}`,
    same: na === nb,
    note: na === nb ? '两个地址在同一网段，可直接二层互通' : '两个地址不在同一网段，需经网关三层转发'
  };
}

/* =========================================================================
   12. WoL 远程唤醒
   ========================================================================= */
function parseMac(mac) {
  const hex = String(mac || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  return hex.length === 12 ? hex : null;
}
function magicPacket(hexMac) {
  const mac = Buffer.from(hexMac, 'hex');
  const buf = Buffer.alloc(6 + 16 * 6, 0xff);
  for (let i = 0; i < 16; i++) mac.copy(buf, 6 + i * 6);
  return buf;
}
async function wolWake(macs, opts = {}) {
  const list = (Array.isArray(macs) ? macs : String(macs || '').split(/[,\s;]+/)).map(parseMac).filter(Boolean);
  if (!list.length) return { ok: false, error: '请提供合法的 MAC 地址，例如 00:11:22:33:44:55' };
  const broadcast = String(opts.broadcast || '255.255.255.255').trim();
  const port = clamp(opts.port, 1, 65535, 9);

  const sent = [];
  for (const hexMac of list) {
    const pretty = hexMac.match(/.{2}/g).join(':');
    const r = await new Promise(resolve => {
      const sock = dgram.createSocket('udp4');
      sock.once('error', e => { try { sock.close(); } catch { } resolve({ mac: pretty, ok: false, error: e.code || e.message }); });
      sock.bind(() => {
        try { sock.setBroadcast(true); } catch { }
        const pkt = magicPacket(hexMac);
        sock.send(pkt, 0, pkt.length, port, broadcast, err => {
          try { sock.close(); } catch { }
          resolve(err ? { mac: pretty, ok: false, error: err.code || err.message } : { mac: pretty, ok: true });
        });
      });
    });
    sent.push(r);
  }
  const okCount = sent.filter(s => s.ok).length;
  return {
    ok: okCount > 0,
    count: list.length, sentCount: okCount,
    broadcast, port, devices: sent,
    note: okCount === list.length
      ? `已向 ${broadcast}:${port} 广播 ${okCount} 个 Magic Packet，请确认目标主机已在 BIOS/网卡开启 Wake-on-LAN，且与发送端处于同一广播域`
      : '部分设备唤醒包发送失败，请检查广播地址与网卡权限'
  };
}

/* =========================================================================
   导出
   ========================================================================= */
module.exports = {
  redirectTrace, httpCheck, sslCert, whoisLookup, publicIp,
  pingTest, mtrTrace, dnsDiag, fingerprintHost, ifstat, ntpQuery,
  subnetAnalyze, subnetVlsm, subnetSame, wolWake,
  SERVICE_MAP, DEFAULT_FP_PORTS, DNS_TYPES, PUBLIC_DNS, NTP_SERVERS,
  humanBps, normalizeUrl, isPrivateIp
};
