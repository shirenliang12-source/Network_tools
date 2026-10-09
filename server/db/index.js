'use strict';
/**
 * 数据访问层入口（工厂）
 *
 * 选择驱动：
 *   设置了 DATABASE_URL        → PostgreSQL（推荐，可与应用分离部署）
 *   未设置（默认）             → data/db.json（零依赖，开箱即用）
 *
 * 环境变量：
 *   DATABASE_URL      如 postgres://user:pass@127.0.0.1:5432/netops
 *   PG_POOL_MAX       连接池最大连接数，默认 10
 *   PG_POOL_IDLE      连接空闲超时(ms)，默认 30000
 *   PG_SSL            填 1 时启用 SSL（require）
 */
const schema = require('./schema');
const jsonRepo = require('./jsonRepo');

let pool = null;
let mode = null;
let impl = null;

function usePg(url) {
  const { Pool } = require('pg');
  const max = Number(process.env.PG_POOL_MAX || 10);
  const idle = Number(process.env.PG_POOL_IDLE || 30000);
  pool = new Pool({
    connectionString: url,
    max,
    idleTimeoutMillis: idle,
    connectionTimeoutMillis: Number(process.env.PG_CONNECT_TIMEOUT || 8000),
    ssl: process.env.PG_SSL === '1' ? { rejectUnauthorized: false } : undefined
  });
  pool.on('error', (e) => console.error('[db] 连接池异常:', e.message));
  const pgRepo = require('./pgRepo');
  return pgRepo.build(pool);
}

/** 连接健康检查（不建连接池） */
async function probe(url) {
  const { Client } = require('pg');
  const c = new Client({ connectionString: url, connectionTimeoutMillis: 8000 });
  const t = Date.now();
  try {
    await c.connect();
    const r = await c.query('select version()');
    const db = await c.query('select current_database() as db, current_user as us, inet_server_addr()::text as addr, inet_server_port() as port');
    return { ok: true, ms: Date.now() - t, version: (r.rows[0]?.version || '').slice(0, 60), ...db.rows[0] };
  } finally {
    try { await c.end(); } catch { }
  }
}

/* 同步设置快照：供 findTshark / findIperf / getProvider 这类同步调用点使用。
   JSON 模式下它就是内存里那份对象（永远最新）；PG 模式下由 settingsUpdate 自动刷新。 */
let mirror = null;

async function init() {
  if (impl) return impl;
  const url = (process.env.DATABASE_URL || '').trim();
  if (url) {
    mode = 'postgres';
    impl = usePg(url);
  } else {
    mode = 'json';
    impl = jsonRepo.build();
  }
  // 包一层：任何写设置的操作之后都刷新同步快照（raw 指向未被包装的原实现，避免自调用）
  const raw = impl;
  const impl2 = Object.assign(Object.create(raw), raw, {
    settingsUpdate: async (patch) => {
      const r = await raw.settingsUpdate(patch);
      mirror = r;
      return r;
    }
  });
  impl = impl2;
  mirror = await raw.settingsGet().catch(() => null);
  module.exports = Object.assign(module.exports, impl, {
    settingsSync: () => mirror,
    kind: mode,
    ready: true,
    async status() {
      if (mode !== 'postgres') {
        const store = require('../store');
        return {
          driver: 'JSON 文件', kind: 'json', url: 'data/db.json',
          pool: { max: 0, active: 0, idle: 0 }, latencyMs: 0,
          tables: Object.keys(schema.TABLES).length
        };
      }
      const t = Date.now();
      await pool.query('select 1');
      return {
        driver: 'PostgreSQL', kind: 'postgres',
        url: String(url).replace(/\/[^/]*$/, '/***'),   // 隐藏库名以外的敏感信息
        pool: { max: pool.options?.max ?? pool.max ?? 0, active: 0, idle: 0 },
        latencyMs: Date.now() - t,
        version: (await pool.query('select version()')).rows[0]?.version?.slice(0, 60) || '',
        tables: Object.keys(schema.TABLES).length
      };
    },
    async end() { if (pool) { try { await pool.end(); } catch { } pool = null; } }
  });
  return impl;
}

/** 首屏同步可用的 getter：未 init 时退回 JSON 实现，保证 require 时不会炸 */
function get() {
  if (impl) return impl;
  impl = jsonRepo.build();
  mode = mode || 'json';
  return impl;
}

module.exports = { init, probe, get, settingsSync: () => mirror, TABLES: schema.TABLES };
