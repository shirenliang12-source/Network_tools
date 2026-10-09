'use strict';
/**
 * PostgreSQL 迁移脚本：建表 / 补齐列 / 索引，以及 data/db.json → PostgreSQL 的数据迁移。
 *
 * 用法：
 *   node tools/migrate.js --url postgres://user:pass@127.0.0.1:5432/netops
 *   node tools/migrate.js --check              # 只体检，不写入
 *   node tools/migrate.js --dry-run            # 打印 SQL，不执行
 *   node tools/migrate.js --data data/db.json  # 附带迁移 JSON 库里的数据
 *   node tools/migrate.js --force              # 已存在的行用新数据覆盖（默认保留）
 *
 * 环境变量同样生效：DATABASE_URL / PG_SSL=1
 * 说明：全部语句均为幂等（IF NOT EXISTS），可反复执行。
 */
const fs = require('fs');
const path = require('path');
const schema = require('../server/db/schema');

/* ------------------------------ 参数解析 ------------------------------ */
const argv = process.argv.slice(2);
const arg = (name, def = '') => {
  const i = argv.indexOf('--' + name);
  return i >= 0 ? (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : def) : (argv.includes('--' + name) ? def : def);
};
const has = (name) => argv.includes('--' + name);
const CHECK = has('check');
const DRY = has('dry-run');
const FORCE = has('force');
const QUIET = has('quiet');
const DB_URL = (process.env.DATABASE_URL || '').trim()
  || (fs.existsSync(path.join(__dirname, '..', '.env')) ? loadDotEnv('DATABASE_URL', path.join(__dirname, '..', '.env')) : '')
  || arg('url', '');

function loadDotEnv(key, file) {
  try {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && m[1] === key) return m[2].replace(/^["']|["']$/g, '');
    }
  } catch { }
  return '';
}

let pass = 0, fail = 0;
const line = (s = '') => { if (!QUIET) console.log(s); };
const ok = (n, c, d) => { if (c) { pass++; line(`  ✓ ${n}${d ? ' — ' + d : ''}`); } else { fail++; line(`  ✗ ${n}${d ? ' — ' + d : ''}`); } };

/* ------------------------------ 类型解析 ------------------------------ */
/** 从 DDL 行里取列类型，用于 ALTER TABLE 补列 */
function typeOf(lineText) {
  const s = lineText.trim().replace(/\(.*?\)\s*$/, (m) => m);   // 保留括号类型（如 NUMERIC(10,2)）
  const parts = s.split(/\s+/);
  return parts[1] || 'TEXT';
}
/** 判定列的 PG 类别，决定序列化方式 */
function colKind(type) {
  const t = String(type).toLowerCase();
  if (t.includes('json')) return 'json';
  if (t.includes('[]')) return 'array';
  if (t.includes('timestamp')) return 'ts';
  if (t.includes('boolean')) return 'bool';
  return 'plain';
}

/** 每张表：列名 → 类别 */
function colMeta(t) {
  const body = String(t.ddl).replace(/^[\s\S]*?\(([\s\S]*)\)\s*;?\s*$/, '$1');
  const out = {};
  for (const raw of body.split(',')) {
    const s = raw.trim();
    if (!s || /^(PRIMARY|UNIQUE|FOREIGN|CONSTRAINT|CHECK)/i.test(s)) continue;
    const name = s.split(/\s+/)[0];
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue;
    out[name] = colKind(typeOf(s));
  }
  return out;
}

/* ------------------------------ JSON → 行 ------------------------------ */
function pick(o, ...keys) { const out = {}; for (const k of keys) if (o[k] !== undefined) out[k] = o[k]; return out; }

/** 通用：把 JSON 里的记录按 DDL 列映射成 PG 行（camel → snake，未建列的进 data） */
function genericRows(list, t) {
  const cols = schema.colsOf(t);
  const hasData = cols.includes('data');
  return list.map(o => {
    const row = {};
    const rest = {};
    for (const [k, v] of Object.entries(o || {})) {
      const col = schema.snake(k);
      if (cols.includes(col)) row[col] = v; else rest[k] = v;
    }
    if (hasData && Object.keys(rest).length) row.data = rest;
    return row;
  });
}

function buildRows(db) {
  const T = schema.TABLES;
  const out = [];
  out.push({ table: T.settings.pg, rows: [{ k: 'settings', v: db.settings || {} }] });
  for (const key of ['users', 'credentials', 'templates', 'alarms', 'aiHistory', 'audit', 'speedResults', 'recordingMeta', 'captureFiles', 'captureTasks', 'flowSessions']) {
    const t = T[key]; if (!t) continue;
    const list = db[key];
    if (!Array.isArray(list) || !list.length) continue;
    if (key === 'aiHistory') {
      out.push({
        table: t.pg, rows: list.map(r => ({
          id: r.id, user: r.user || r.username || '', question: r.question || '',
          answer: r.answer || '', at: r.at || new Date().toISOString(),
          provider: r.provider || '', model: r.model || ''
        }))
      });
    } else if (key === 'speedResults') {
      out.push({ table: t.pg, rows: list.map(r => ({ id: r.id, at: r.at || new Date().toISOString(), data: r })) });
    } else if (key === 'recordingMeta') {
      out.push({ table: t.pg, rows: list.map(r => ({ id: r.id, started_at: r.startedAt || r.started_at || new Date().toISOString(), data: r })) });
    } else if (key === 'captureFiles') {
      out.push({
        table: t.pg, rows: list.map(r => ({
          id: r.id, name: r.name || '', path: r.path || '', size: r.size ?? 0, iface: r.iface || '',
          mode: r.mode || '', filter: r.filter || '', source: r.source || '',
          started_at: r.startedAt || r.started_at || new Date().toISOString(), ended_at: r.endedAt || r.ended_at || null, data: r
        }))
      });
    } else if (key === 'captureTasks') {
      out.push({
        table: t.pg, rows: list.map(r => {
          const known = ['id', 'name', 'iface', 'bpf', 'pcapSize', 'retainHours', 'enabled', 'status', 'lastStartedAt', 'lastEndedAt', 'runs'];
          const extra = {};
          for (const [k, v] of Object.entries(r || {})) if (!known.includes(k) && k !== 'data') extra[k] = v;
          return {
            id: r.id, name: r.name, iface: r.iface ?? '', bpf: r.bpf ?? '',
            pcap_size: Number(r.pcapSize ?? 100), retain_hours: Number(r.retainHours ?? 72),
            enabled: !!r.enabled, status: r.status || 'idle',
            last_started_at: r.lastStartedAt || r.last_started_at || null,
            last_ended_at: r.lastEndedAt || r.last_ended_at || null,
            runs: Number(r.runs || 0), data: extra
          };
        })
      });
    } else if (key === 'flowSessions') {
      out.push({
        table: t.pg, rows: list.map(r => ({
          id: r.id, started_at: r.startedAt || new Date().toISOString(),
          src_ip: r.srcIp || '', dst_ip: r.dstIp || '', src_port: r.srcPort ?? 0, dst_port: r.dstPort ?? 0,
          proto: r.proto || 'tcp', app_proto: r.appProto || '',
          task_id: r.taskId || null, file_id: r.fileId || r.file_id || null,
          bytes: Number(r.bytes || 0), pkts: Number(r.pkts || 0), duration_ms: Number(r.durationMs || r.duration_ms || 0),
          hint: r.hint || {}, tags: Array.isArray(r.tags) ? r.tags : []
        }))
      });
    } else {
      out.push({ table: t.pg, rows: genericRows(list, t) });
    }
  }
  if (db.inventory && typeof db.inventory === 'object' && Object.keys(db.inventory).length) {
    out.push({ table: T.inventory.pg, rows: Object.entries(db.inventory).map(([host, data]) => ({ host, data })) });
  }
  if (db.topology && typeof db.topology === 'object' && (db.topology.nodes || db.topology.links)) {
    out.push({ table: T.topology.pg, rows: [{ id: 1, data: { nodes: db.topology.nodes || [], links: db.topology.links || [] } }] });
  }
  return out;
}

/* ------------------------------ 写入 ------------------------------ */
function serialize(v, kind) {
  if (v === undefined || v === null) return null;
  if (kind === 'json') return typeof v === 'string' ? v : JSON.stringify(v);
  if (kind === 'array') return Array.isArray(v) ? v : (v ? [v] : []);
  if (kind === 'ts') { const n = Number(v); if (Number.isFinite(n) && n > 0) return new Date(n < 1e12 ? n * 1000 : n).toISOString(); return String(v); }
  if (kind === 'bool') return v === undefined ? false : (!!v || v === 'true' || v === 1);
  return v;
}

function makeInsert(t, row, force) {
  const cols = schema.colsOf(t);
  const pk = t.pk;
  const keys = cols.filter(c => row[c] !== undefined);
  const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
  const sets = keys.filter(c => c !== pk).map(c => `"${c}" = EXCLUDED."${c}"`).join(', ');
  return {
    sql: `INSERT INTO "${t.pg}" (${keys.map(c => `"${c}"`).join(', ')}) VALUES (${placeholders})
          ON CONFLICT ("${pk}") DO ${force ? 'UPDATE SET ' + sets : 'NOTHING'}`,
    params: keys.map(c => serialize(row[c], colMeta(t)[c] || 'plain'))
  };
}

/* ------------------------------ 主流程 ------------------------------ */
async function main() {
  console.log('\n=== PostgreSQL 迁移 ===\n');
  // 注意：这里判断的是连接串变量 DB_URL，不是全局 URL 类
  if (!DB_URL) {
    console.log('  未配置 DATABASE_URL。用法示例：\n');
    console.log('    node tools/migrate.js --url postgres://user:pass@127.0.0.1:5432/netops');
    console.log('    或在项目根目录 .env 里写 DATABASE_URL=postgres://...\n');
    process.exit(2);
  }
  const redacted = DB_URL.replace(/\/\/[^@]*@/, '//***@');
  line(`  目标：${redacted}\n`);

  let pg;
  try { pg = require('pg'); } catch {
    console.log('  ✗ 未安装 pg 驱动，请先执行：npm install pg（或 npm install）');
    process.exit(2);
  }
  const ssl = process.env.PG_SSL === '1' ? { rejectUnauthorized: false } : undefined;

  /** 先连一次；报 3D000（库不存在）则建库后再连 */
  async function connect(target) {
    const c = new pg.Client({ connectionString: target, connectionTimeoutMillis: 8000, ssl });
    try { await c.connect(); return c; }
    catch (e) {
      try { await c.end(); } catch { }
      if (e.code === '3D000' && !has('no-create-db')) {
        const u = new URL(target.replace('postgres://', 'postgresql://'));
        const dbName = u.pathname.replace(/^\//, '');
        u.pathname = '/postgres';
        const admin = new pg.Client({ connectionString: u.toString(), connectionTimeoutMillis: 8000, ssl });
        await admin.connect();
        await admin.query(`SELECT 1 FROM pg_database WHERE datname = $1`, [dbName]);
        await admin.query(`CREATE DATABASE "${dbName.replace(/"/g, '""')}"`);
        await admin.end();
        console.log(`  ✓ 数据库不存在，已创建：${dbName}`);
        return connect(target);
      }
      const hint = {
        ECONNREFUSED: '目标地址被拒绝，确认 PostgreSQL 服务已启动、端口(默认5432)与防火墙放行',
        ENOTFOUND: '主机名解析失败，确认地址拼写，或 PostgreSQL 未监听 TCP',
        ECONNRESET: '连接被对端重置，确认是否要求 SSL（可设 PG_SSL=1）',
        ETIMEDOUT: '连接超时，确认网络可达与 pg_hba.conf 是否允许该来源 IP'
      }[e.code];
      throw new Error(`${e.code || e.message}${hint ? '：' + hint : ''}`);
    }
  }

  const client = await connect(DB_URL);
  const dbName = new URL(DB_URL.replace('postgres://', 'postgresql://')).pathname.replace(/^\//, '');
  const ver = (await client.query('select version()')).rows[0].version;
  ok('连接数据库', true, dbName + ' · ' + String(ver).split(',')[0]);

  /* --- 建表 / 索引 --- */
  const applied = [];
  for (const t of Object.values(schema.TABLES)) {
    applied.push({ sql: t.ddl, name: t.pg });
  }
  for (const t of Object.values(schema.TABLES)) for (const ix of (t.indexes || [])) applied.push({ sql: ix, name: t.pg + ' 索引' });

  if (DRY) {
    line('\n--- 待执行 SQL ---');
    applied.forEach(a => line(a.sql + ';'));
    line('');
  } else if (!CHECK) {
    let n = 0;
    for (const a of applied) { await client.query(a.sql); n++; }
    ok('建表与索引', true, `${n} 条语句`);
  }

  /* --- 检查缺失表 / 缺失列 --- */
  if (!DRY) {
    const tables = (await client.query(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()`)).rows.map(r => r.table_name);
    for (const [key, t] of Object.entries(schema.TABLES)) {
      if (!tables.includes(t.pg)) { fail++; line(`  ✗ ${key} → ${t.pg} 表不存在`); }
    }
    const colsByTable = {};
    for (const [key, t] of Object.entries(schema.TABLES)) {
      if (!tables.includes(t.pg)) continue;
      const r = await client.query(
        `SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1`, [t.pg]);
      colsByTable[t.pg] = new Set(r.rows.map(x => x.column_name));
      const meta = colMeta(t);
      for (const c of schema.colsOf(t)) {
        if (!colsByTable[t.pg].has(c)) {
          const type = (String(t.ddl).split(',').map(s => s.trim()).find(s => s.split(/\s+/)[0] === c) || '').split(/\s+/)[1] || 'TEXT';
          if (CHECK) { fail++; line(`  ✗ ${t.pg}.${c} 列缺失`); }
          else { await client.query(`ALTER TABLE "${t.pg}" ADD COLUMN IF NOT EXISTS "${c}" ${type}`); }
        }
      }
    }
    if (!CHECK) ok('列结构补齐', true, `${Object.keys(schema.TABLES).length} 张表`);
  }

  /* --- 数据迁移 --- */
  const dataFile = path.resolve(__dirname, '..', arg('data', 'data/db.json'));
  if (fs.existsSync(dataFile)) {
    const db = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
    const jobs = buildRows(db).filter(j => j.rows.length);
    let total = 0;
    for (const job of jobs) {
      const t = Object.values(schema.TABLES).find(x => x.pg === job.table);
      let done = 0, skipped = 0;
      for (let i = 0; i < job.rows.length; i += 500) {
        const batch = job.rows.slice(i, i + 500);
        if (DRY) { done += batch.length; continue; }
        for (const row of batch) {
          const { sql, params } = makeInsert(t, row, FORCE);
          const r = await client.query(sql, params);
          if (r.command === 'INSERT') done++; else skipped++;
        }
      }
      total += done;
      line(`  · ${job.table}：导入 ${done} 行${skipped ? `（${skipped} 行已存在，跳过；加 --force 可覆盖）` : ''}`);
    }
    ok('JSON 数据迁移', true, `共 ${total} 行，来源 ${path.relative(process.cwd(), dataFile)}`);
  } else if (!QUIET) {
    line(`  · 未找到数据文件 ${path.relative(process.cwd(), dataFile)}，跳过数据迁移`);
  }

  await client.end();
  console.log(`\n=== 迁移完成：${pass} 项通过，${fail} 项失败（${CHECK ? '体检模式' : DRY ? '预演模式' : '已写入'}）===\n`);
  process.exit(fail ? 1 : 0);
}

main().catch(e => { console.error('\n  迁移失败：' + (e.message || e)); console.error(e.stack?.split('\n').slice(1, 3).join('\n') || ''); process.exit(2); });
