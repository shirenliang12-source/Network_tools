'use strict';

/**
 * SNMP 设备查询工具。
 *
 * - 支持 v1 / v2c / v3（noAuthNoPriv、authNoPriv、authPriv）
 * - 只开放只读 GET / WALK，不提供 SET，避免误修改生产设备
 * - 所有口令只在本次请求的内存中使用，返回结果与审计日志均不包含凭据
 */
const net = require('net');
const snmp = require('net-snmp');

const DEFAULT_OIDS = {
  sysDescr: '1.3.6.1.2.1.1.1.0',
  sysObjectID: '1.3.6.1.2.1.1.2.0',
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  sysContact: '1.3.6.1.2.1.1.4.0',
  sysName: '1.3.6.1.2.1.1.5.0',
  sysLocation: '1.3.6.1.2.1.1.6.0',
  ifTable: '1.3.6.1.2.1.2.2',
  ifXTable: '1.3.6.1.2.1.31.1.1'
};

function clamp(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function validHost(value) {
  const host = String(value || '').trim();
  if (!host || host.length > 253) return '';
  if (net.isIP(host)) return host;
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(host)) return '';
  return host;
}

function normalizeOid(value) {
  const oid = String(value || '').trim().replace(/^\./, '');
  if (!/^\d+(?:\.\d+)+$/.test(oid) || oid.length > 256) return '';
  return oid;
}

function normalizeOids(value) {
  const input = Array.isArray(value) ? value : String(value || '').split(/[,\s]+/);
  const oids = [...new Set(input.map(normalizeOid).filter(Boolean))];
  return oids.slice(0, 32);
}

function protocolOf(map, value, fallback) {
  const key = String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  return map[key] === undefined ? fallback : map[key];
}

function createSession(input = {}) {
  const host = validHost(input.host);
  if (!host) throw new Error('请提供合法的 IP 地址或主机名');

  const version = String(input.version || '2c').toLowerCase();
  if (!['1', '2c', '3'].includes(version)) throw new Error('SNMP 版本仅支持 1、2c 或 3');
  const options = {
    port: clamp(input.port, 1, 65535, 161),
    retries: clamp(input.retries, 0, 3, 1),
    timeout: clamp(input.timeout, 300, 15000, 3000),
    transport: net.isIP(host) === 6 ? 'udp6' : 'udp4',
    backwardsGetNexts: false,
    reportOidMismatchErrors: true
  };

  if (version !== '3') {
    const community = String(input.community || '').slice(0, 128);
    if (!community) throw new Error('请输入 SNMP community');
    options.version = version === '1' ? snmp.Version1 : snmp.Version2c;
    return { host, version, options, session: snmp.createSession(host, community, options) };
  }

  const username = String(input.username || '').trim().slice(0, 64);
  if (!username) throw new Error('请输入 SNMPv3 用户名');
  const levelName = String(input.level || 'authPriv');
  const levels = {
    noAuthNoPriv: snmp.SecurityLevel.noAuthNoPriv,
    authNoPriv: snmp.SecurityLevel.authNoPriv,
    authPriv: snmp.SecurityLevel.authPriv
  };
  if (levels[levelName] === undefined) throw new Error('SNMPv3 安全级别无效');
  const user = { name: username, level: levels[levelName] };
  if (levelName !== 'noAuthNoPriv') {
    user.authProtocol = protocolOf(snmp.AuthProtocols, input.authProtocol, snmp.AuthProtocols.sha256);
    user.authKey = String(input.authKey || '').slice(0, 256);
    if (user.authKey.length < 8) throw new Error('SNMPv3 认证密码至少 8 位');
  }
  if (levelName === 'authPriv') {
    user.privProtocol = protocolOf(snmp.PrivProtocols, input.privProtocol, snmp.PrivProtocols.aes);
    user.privKey = String(input.privKey || '').slice(0, 256);
    if (user.privKey.length < 8) throw new Error('SNMPv3 加密密码至少 8 位');
  }
  options.version = snmp.Version3;
  options.context = String(input.context || '').slice(0, 64);
  return { host, version, options, session: snmp.createV3Session(host, user, options) };
}

function typeName(type) {
  for (const [name, value] of Object.entries(snmp.ObjectType || {})) if (value === type && !/^\d+$/.test(name)) return name;
  return String(type ?? 'Unknown');
}

function formatValue(value) {
  if (Buffer.isBuffer(value)) {
    if (!value.length) return '';
    const printable = [...value].every(b => b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126));
    return printable ? value.toString('utf8') : value.toString('hex').match(/.{1,2}/g).join(':');
  }
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function publicVarbind(vb) {
  if (snmp.isVarbindError(vb)) {
    return { oid: vb.oid || '', type: 'Error', value: '', error: snmp.varbindError(vb) };
  }
  return { oid: vb.oid, type: typeName(vb.type), value: formatValue(vb.value) };
}

function safeClose(session) {
  try { session.close(); } catch { /* 已由库关闭或尚未创建 socket */ }
}

async function get(input = {}) {
  const oids = normalizeOids(input.oids || input.oid);
  if (!oids.length) return { ok: false, error: '请输入至少一个数字 OID，例如 1.3.6.1.2.1.1.5.0' };
  let ctx;
  try { ctx = createSession(input); } catch (e) { return { ok: false, error: e.message }; }
  const startedAt = Date.now();
  return new Promise(resolve => {
    ctx.session.get(oids, (error, varbinds) => {
      safeClose(ctx.session);
      if (error) return resolve({ ok: false, error: error.message || String(error), host: ctx.host, version: ctx.version, ms: Date.now() - startedAt });
      const rows = (varbinds || []).map(publicVarbind);
      resolve({
        ok: true, host: ctx.host, version: ctx.version, port: ctx.options.port, ms: Date.now() - startedAt,
        count: rows.length, successCount: rows.filter(r => !r.error).length, errorCount: rows.filter(r => r.error).length, rows
      });
    });
  });
}

async function walk(input = {}) {
  const oid = normalizeOid(input.oid || DEFAULT_OIDS.ifTable);
  if (!oid) return { ok: false, error: '请输入数字 OID 根节点，例如 1.3.6.1.2.1.2.2' };
  const limit = clamp(input.limit, 1, 2000, 300);
  const maxRepetitions = clamp(input.maxRepetitions, 1, 50, 20);
  let ctx;
  try { ctx = createSession(input); } catch (e) { return { ok: false, error: e.message }; }
  const startedAt = Date.now();
  const rows = [];
  return new Promise(resolve => {
    ctx.session.subtree(oid, maxRepetitions, varbinds => {
      for (const vb of varbinds || []) {
        if (rows.length >= limit) break;
        rows.push(publicVarbind(vb));
      }
      return rows.length >= limit;
    }, error => {
      safeClose(ctx.session);
      if (error && !rows.length) return resolve({ ok: false, error: error.message || String(error), host: ctx.host, version: ctx.version, ms: Date.now() - startedAt });
      resolve({
        ok: true, host: ctx.host, version: ctx.version, port: ctx.options.port,
        rootOid: oid, ms: Date.now() - startedAt, count: rows.length,
        successCount: rows.filter(r => !r.error).length, errorCount: rows.filter(r => r.error).length,
        truncated: rows.length >= limit, rows,
        warning: error ? (error.message || String(error)) : ''
      });
    });
  });
}

module.exports = { get, walk, validHost, normalizeOid, normalizeOids, DEFAULT_OIDS };
