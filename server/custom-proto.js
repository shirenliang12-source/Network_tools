'use strict';
/**
 * 自定义协议定义（业务协议）存储与校验。
 * 定义保存在 settings.customProtocols（数组），解析 pcap 时由 dpi.parsePcap(buf,{customDefs}) 注入。
 * 自定义协议优先级高于内置 DPI：同端口上既有标准协议又有业务自定义协议时，自定义胜出。
 */

const db = require('./db');
const store = require('./store');

/** 内置配色，未指定颜色时轮询取用 */
const PALETTE = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#14b8a6'];

function uid() { return store.uid('cp_'); }

/** 规范化单条定义：补齐缺省字段、清理端口/IP/HEX */
function normalize(def = {}) {
  const out = {
    id: def.id || uid(),
    name: String(def.name || '').trim(),
    desc: String(def.desc || '').trim(),
    ports: [],
    ipFilter: '',
    hexOffset: null,
    hexBytes: '',
    color: String(def.color || '').trim() || PALETTE[(Math.abs(hash(def.name || '')) % PALETTE.length)],
    enabled: def.enabled === false ? false : true,
    createdAt: def.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  if (Array.isArray(def.ports)) out.ports = def.ports.map(Number).filter(n => Number.isInteger(n) && n > 0 && n < 65536);
  else if (typeof def.ports === 'string') out.ports = String(def.ports).split(/[, ]+/).map(s => Number(s)).filter(n => Number.isInteger(n) && n > 0 && n < 65536);
  if (def.ipFilter) out.ipFilter = String(def.ipFilter).trim();
  if (def.hexOffset !== '' && def.hexOffset != null) {
    const n = Number(def.hexOffset);
    if (Number.isFinite(n) && n >= 0) out.hexOffset = n;
  }
  if (def.hexBytes) out.hexBytes = String(def.hexBytes).replace(/\s+/g, '').replace(/^0x/, '');
  return out;
}

function hash(s) { let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return h; }

/** 校验单条定义，返回 { ok, error } */
function validate(def) {
  if (!def || typeof def !== 'object') return { ok: false, error: '定义不能为空' };
  if (!def.name) return { ok: false, error: '协议名称必填' };
  if (!/^[\x21-\x7e][\x21-\x7e ]{0,60}$/.test(def.name)) return { ok: false, error: '协议名称仅允许英文/数字/常见符号（≤60 字符）' };
  const hasPorts = Array.isArray(def.ports) && def.ports.length > 0;
  const hasIp = !!def.ipFilter;
  const hasHex = def.hexOffset != null && !!def.hexBytes && /^[0-9a-fA-F]{2,}$/.test(String(def.hexBytes).replace(/\s+/g, '').replace(/^0x/, ''));
  if (!hasPorts && !hasIp && !hasHex) return { ok: false, error: '至少填写一项匹配条件：端口 / IP 正则 / HEX 魔数' };
  if (hasHex && !(def.hexOffset >= 0)) return { ok: false, error: 'HEX 魔数需要有效的偏移量（≥0 的整数）' };
  if (hasIp) {
    try { new RegExp(def.ipFilter, 'i'); } catch (e) { return { ok: false, error: 'IP 正则非法：' + e.message }; }
  }
  if (def.color && !/^#[0-9a-fA-F]{6}$/.test(def.color)) return { ok: false, error: '颜色需为 #RRGGBB 格式' };
  return { ok: true, error: '' };
}

async function list() {
  const s = await db.settingsGet();
  return (s.customProtocols || []).map(normalize);
}

async function get(id) {
  const all = await list();
  return all.find(p => p.id === id) || null;
}

/** 把 definitions 数组写入 settings（整体替换） */
async function saveAll(arr) {
  const cur = await db.settingsGet();
  const next = Object.assign({}, cur, { customProtocols: arr });
  await db.settingsUpdate(next);
  return arr;
}

async function create(def) {
  const norm = normalize(def);
  const v = validate(norm);
  if (!v.ok) { const e = new Error(v.error); e.status = 400; throw e; }
  const all = await list();
  if (all.some(p => p.name.toLowerCase() === norm.name.toLowerCase())) {
    const e = new Error('已存在同名协议：' + norm.name); e.status = 409; throw e;
  }
  all.push(norm);
  await saveAll(all);
  return norm;
}

async function update(id, patch) {
  const all = await list();
  const idx = all.findIndex(p => p.id === id);
  if (idx < 0) { const e = new Error('未找到该协议定义'); e.status = 404; throw e; }
  const merged = normalize(Object.assign({}, all[idx], patch, { id }));
  const v = validate(merged);
  if (!v.ok) { const e = new Error(v.error); e.status = 400; throw e; }
  if (merged.name.toLowerCase() !== all[idx].name.toLowerCase() && all.some(p => p.id !== id && p.name.toLowerCase() === merged.name.toLowerCase())) {
    const e = new Error('已存在同名协议：' + merged.name); e.status = 409; throw e;
  }
  all[idx] = merged;
  await saveAll(all);
  return merged;
}

async function remove(id) {
  const all = await list();
  const next = all.filter(p => p.id !== id);
  if (next.length === all.length) { const e = new Error('未找到该协议定义'); e.status = 404; throw e; }
  await saveAll(next);
  return { removed: id };
}

/** 供 dpi 解析使用：抽取已启用的 {ports,ipFilter,hexOffset,hexBytes,name,desc} 形式 */
async function asDefs() {
  return (await list()).filter(p => p.enabled).map(p => ({
    name: p.name, desc: p.desc, ports: p.ports, ipFilter: p.ipFilter,
    hexOffset: p.hexOffset, hexBytes: p.hexBytes
  }));
}

module.exports = { normalize, validate, list, get, create, update, remove, saveAll, asDefs, PALETTE };
