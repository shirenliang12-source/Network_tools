'use strict';
/**
 * PostgreSQL 驱动实现
 * 与 jsonRepo.js 实现完全相同的接口，上层业务代码零改动切换。
 * 约定：对外一律输出 camelCase 键名的普通对象，时间统一为 ISO 字符串，
 *       JSONB 列自动解析为对象/数组（与 JSON 驱动读出来的一致）。
 */
const schema = require('./schema');

const arr = (a) => (Array.isArray(a) ? a : []);
const first = (r) => (Array.isArray(r) ? r[0] : r);
/** 风险等级由低到高，配合 array_position 做排序 */
const LEVELS = ['info', 'low', 'medium', 'high', 'critical'];

/* --------------------------- 行 ↔ 对象 转换 --------------------------- */
function rowToObj(row, table) {
  if (!row) return null;
  const o = {};
  for (const [k, v] of Object.entries(row)) {
    if (v === null || v === undefined) { o[schema.camel(k)] = null; continue; }
    if (v instanceof Date) { o[schema.camel(k)] = v.toISOString(); continue; }
    if (Buffer.isBuffer(v)) { o[schema.camel(k)] = v.toString('utf8'); continue; }
    if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(v)) {
      o[schema.camel(k)] = new Date(v.replace(' ', 'T') + 'Z').toISOString();
      continue;
    }
    if (typeof v === 'bigint') { o[schema.camel(k)] = Number(v); continue; }
    if (Array.isArray(v)) { o[schema.camel(k)] = v; continue; }   // TEXT[] / date[]
    o[schema.camel(k)] = (typeof v === 'object') ? v : v;         // JSONB → 已由 pg 解析
  }
  return o;
}

/** 把业务对象按表列裁剪/映射，供 INSERT / UPDATE 使用 */
function objToRow(obj, table) {
  const cols = schema.colsOf(table).filter(c => c !== 'id' || obj.id !== undefined);
  const out = {};
  for (const c of cols) {
    let v = obj[schema.camel(c)];
    if (v === undefined) continue;
    if (c === 'created_at' && (v === undefined || v === null)) continue;   // 交给 DEFAULT now()
    if (c === 'enabled' || c === 'danger') v = v === false || v === 0 || v === 'false' ? false : (v === true || v === 1 || v === 'true' ? true : !!v);
    out[c] = v;
  }
  return out;
}

function build(pool) {
  const q = async (sql, params) => {
    const r = await pool.query(sql, params);
    return r.rows || [];
  };
  const T = (name) => schema.TABLES[name];
  const PG = (name) => T(name).pg;

  /** 通用：按主键 upsert / update */
  const upsert = async (name, obj) => {
    const t = T(name), pg = PG(name);
    const row = objToRow(obj, t);
    if (!Object.keys(row).length) return null;
    const cols = Object.keys(row);
    if (!cols.includes('created_at')) {
      cols.push('created_at');
      row.created_at = row.created_at || new Date().toISOString();
    }
    const keys = cols.map(c => `"${c}"`).join(', ');
    const ph = cols.map((_, i) => `$${i + 1}`).join(', ');
    const sets = cols.filter(c => c !== 'id').map((c, i) => `"${c}" = $${cols.length + i + 1}`).join(', ');
    const vals = cols.map(c => row[c]);
    const sql = `INSERT INTO ${pg} (${keys}) VALUES (${ph}) ON CONFLICT ("${t.pk}") DO UPDATE SET ${sets} RETURNING *`;
    return rowToObj(first(await q(sql, vals)), t);
  };

  /**
   * 通用批量插入（多值元组）。conflict 传列名数组时按该唯一键 upsert，
   * 传 'id' 时按主键覆盖，传 null 时不做冲突处理（纯追加）。
   * jsonCols 里的字段自动 JSON.stringify，避免 pg 把对象当 "object Object"。
   */
  const bulkInsert = async (name, rows, { jsonCols = [], touchCols = [], conflict = 'id' } = {}) => {
    const list = (rows || []).filter(Boolean);
    if (!list.length) return 0;
    const t = T(name), pg = PG(name);
    const cols = schema.colsOf(t);
    const params = [];
    const tuples = list.map(r => {
      const marks = cols.map(c => {
        let v = r[schema.camel(c)];
        if (touchCols.includes(c)) v = v || new Date().toISOString();
        if (jsonCols.includes(c) && v != null && typeof v !== 'string') v = JSON.stringify(v);
        params.push(v === undefined ? null : v);
        return '$' + params.length;
      });
      return `(${marks.join(', ')})`;
    });
    const target = conflict ? (Array.isArray(conflict) ? conflict : [conflict]) : null;
    let tail = '';
    if (target) {
      const upd = cols.filter(c => !target.includes(c)).map(c => `"${c}" = EXCLUDED."${c}"`).join(', ');
      tail = `ON CONFLICT (${target.map(c => `"${c}"`).join(', ')}) DO UPDATE SET ${upd}`;
    }
    await q(`INSERT INTO ${pg} (${cols.map(c => `"${c}"`).join(', ')}) VALUES ${tuples.join(', ')} ${tail}`, params);
    return list.length;
  };

  return {
    kind: 'postgres',

    /* ------------------------------ 设置 ------------------------------ */
    async settingsGet() {
      const r = await q(`SELECT v FROM ${PG('settings')} WHERE k = $1`, ['settings']);
      return r[0] ? r[0].v : null;
    },
    async settingsUpdate(patch) {
      const cur = (await this.settingsGet()) || {};
      const next = schema.TABLES ? mergeDeep(cur, patch || {}) : cur;
      await q(`INSERT INTO ${PG('settings')} (k, v) VALUES ($1, $2)
               ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`, ['settings', next]);
      return next;
    },

    /* ------------------------------ 用户 ------------------------------ */
    async usersList() { return (await q(`SELECT * FROM ${PG('users')} ORDER BY created_at`)).map(r => rowToObj(r, T('users'))); },
    async usersFind(id) { return rowToObj(first(await q(`SELECT * FROM ${PG('users')} WHERE id = $1`, [id])), T('users')); },
    async usersFindByUsername(n) { return rowToObj(first(await q(`SELECT * FROM ${PG('users')} WHERE username = $1`, [n])), T('users')); },
    async usersCreate(o) {
      return upsert('users', Object.assign({ enabled: true, created_at: new Date().toISOString() }, o));
    },
    async usersUpdate(id, patch) {
      const cur = await this.usersFind(id);
      if (!cur) return null;
      return upsert('users', { ...cur, ...patch, id });
    },
    async usersRemove(id) { const r = await q(`DELETE FROM ${PG('users')} WHERE id = $1 RETURNING id`, [id]); return r.length > 0; },

    /* ----------------------------- 凭据库 ----------------------------- */
    async credentialsList() { return (await q(`SELECT * FROM ${PG('credentials')} ORDER BY created_at`)).map(r => rowToObj(r, T('credentials'))); },
    async credentialsFind(id) { return rowToObj(first(await q(`SELECT * FROM ${PG('credentials')} WHERE id = $1`, [id])), T('credentials')); },
    async credentialsCreate(o) { return upsert('credentials', Object.assign({ created_at: new Date().toISOString() }, o)); },
    async credentialsUpdate(id, patch) {
      const cur = await this.credentialsFind(id);
      if (!cur) return null;
      return upsert('credentials', { ...cur, ...patch, id });
    },
    async credentialsRemove(id) { const r = await q(`DELETE FROM ${PG('credentials')} WHERE id = $1 RETURNING id`, [id]); return r.length > 0; },

    /* ---------------------------- 命令模板 ---------------------------- */
    async templatesList() { return (await q(`SELECT * FROM ${PG('templates')} ORDER BY created_at`)).map(r => rowToObj(r, T('templates'))); },
    async templatesFind(id) { return rowToObj(first(await q(`SELECT * FROM ${PG('templates')} WHERE id = $1`, [id])), T('templates')); },
    async templatesCreate(o) { return upsert('templates', Object.assign({ commands: [], danger: false, created_at: new Date().toISOString() }, o)); },
    async templatesUpdate(id, patch) {
      const cur = await this.templatesFind(id);
      if (!cur) return null;
      return upsert('templates', { ...cur, ...patch, id });
    },
    async templatesRemove(id) { const r = await q(`DELETE FROM ${PG('templates')} WHERE id = $1 RETURNING id`, [id]); return r.length > 0; },

    /* ------------------------------ 告警 ------------------------------ */
    async alarmsList() { return (await q(`SELECT * FROM ${PG('alarms')} ORDER BY created_at`)).map(r => rowToObj(r, T('alarms'))); },
    async alarmsFind(idOrEventid) {
      return rowToObj(first(await q(`SELECT * FROM ${PG('alarms')} WHERE id = $1 OR eventid = $1 LIMIT 1`, [idOrEventid])), T('alarms'));
    },
    async alarmsCreate(o) {
      return upsert('alarms', Object.assign({
        source: 'manual', severity: 'information', status: 'open',
        clock: Math.floor(Date.now() / 1000), created_at: new Date().toISOString()
      }, o));
    },
    async alarmsUpdate(idOrEventid, patch) {
      const row = { ...(patch || {}) };
      if (row.status === 'acknowledged' && !row.ackAt) { row.ackAt = new Date().toISOString(); row.ackBy = row.ackBy || 'system'; }
      const r = await q(`UPDATE ${PG('alarms')} SET ${Object.keys(row).map((c, i) => `"${schema.snake(c)}" = $${i + 2}`).join(', ')}
                         WHERE id = $1 OR eventid = $1 RETURNING *`, [idOrEventid, ...Object.values(row)]);
      return r.length ? rowToObj(r[0], T('alarms')) : null;
    },
    async alarmsRemove(idOrEventid) {
      const r = await q(`DELETE FROM ${PG('alarms')} WHERE id = $1 OR eventid = $1 RETURNING id`, [idOrEventid]);
      return r.length > 0;
    },

    /* -------------------------- 设备补充信息 -------------------------- */
    async inventoryGet(host) {
      const r = await q(`SELECT data FROM ${PG('inventory')} WHERE host = $1`, [host]);
      return r[0] ? (r[0].data || {}) : {};
    },
    async inventorySet(host, data) {
      await q(`INSERT INTO ${PG('inventory')} (host, data) VALUES ($1, $2)
               ON CONFLICT (host) DO UPDATE SET data = EXCLUDED.data`, [host, data || {}]);
      return data || {};
    },
    async inventoryAll() {
      const r = await q(`SELECT host, data FROM ${PG('inventory')}`);
      const out = {};
      for (const x of r) out[x.host] = x.data || {};
      return out;
    },

    /* ------------------------------ 拓扑 ------------------------------ */
    async topologyGet() {
      const r = await q(`SELECT data FROM ${PG('topology')} WHERE id = 1`);
      return r[0] ? (r[0].data || { nodes: [], links: [] }) : { nodes: [], links: [] };
    },
    async topologySet(v) {
      const data = { nodes: (v && v.nodes) || [], links: (v && v.links) || [] };
      await q(`INSERT INTO ${PG('topology')} (id, data) VALUES (1, $1)
               ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`, [data]);
      return data;
    },

    /* --------------------------- AI 问答历史 --------------------------- */
    async aiAdd(row) {
      await q(`INSERT INTO ${PG('aiHistory')} (id, user, question, answer, at, provider, model)
               VALUES ($1,$2,$3,$4,$5,$6,$7)
               ON CONFLICT (id) DO UPDATE SET answer = EXCLUDED.answer, at = EXCLUDED.at`,
        [row.id || 'ai_' + require('../store').uid(''), row.user, row.question, row.answer,
        row.at || new Date().toISOString(), row.provider || '', row.model || '']);
      return row;
    },
    async aiList(limit = 50, username = '') {
      const sql = `SELECT * FROM ${PG('aiHistory')} ${username ? 'WHERE "user" = $1' : ''}
                   ORDER BY at DESC LIMIT ${Number(limit) || 50}`;
      const r = await q(sql, username ? [username] : []);
      return r.map(x => rowToObj(x, T('aiHistory')));
    },

    /* ----------------------------- 审计日志 ---------------------------- */
    async auditWrite(entry) {
      const row = {
        ts: entry.ts || new Date().toISOString(),
        user: entry.user || 'system', role: entry.role || '-', ip: entry.ip || '-',
        action: entry.action || 'unknown', target: entry.target || '',
        result: entry.result || 'ok', detail: entry.detail || ''
      };
      await q(`INSERT INTO ${PG('audit')} (ts, user, role, ip, action, target, result, detail)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [row.ts, row.user, row.role, row.ip, row.action, row.target, row.result, row.detail]);
      return row;
    },
    async auditRead({ limit = 200, user = '', action = '', from = '', to = '' } = {}) {
      const w = [], p = [];
      if (user) { w.push(`"user" = $${p.length + 1}`); p.push(user); }
      if (action) { w.push(`action ILIKE $${p.length + 1}`); p.push(`%${action}%`); }
      if (from) { w.push(`ts >= $${p.length + 1}`); p.push(from); }
      if (to) { w.push(`ts <= $${p.length + 1}`); p.push(to); }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const rows = await q(`SELECT * FROM ${PG('audit')} ${where} ORDER BY id DESC LIMIT ${Number(limit) || 200}`, p);
      return rows.map(r => rowToObj(r, T('audit')));
    },
    async auditCount() { return (await q(`SELECT count(*)::int AS n FROM ${PG('audit')}`))[0]?.n ?? 0; },

    /* ----------------------------- 测速结果 ---------------------------- */
    async speedSave(row) {
      await q(`INSERT INTO ${PG('speedResults')} (id, at, data) VALUES ($1, $2, $3)
               ON CONFLICT (id) DO UPDATE SET at = EXCLUDED.at, data = EXCLUDED.data`,
        [row.id, row.at || new Date().toISOString(), row]);
      return row;
    },
    async speedList(limit = 50) {
      const r = await q(`SELECT data FROM ${PG('speedResults')} ORDER BY at DESC LIMIT ${Number(limit) || 50}`);
      return r.map(x => (typeof x.data === 'object' ? x.data : safeJson(x.data))).filter(Boolean);
    },
    async speedRemoveOld(cutIso) {
      return (await q(`DELETE FROM ${PG('speedResults')} WHERE at < $1 RETURNING id`, [cutIso])).length;
    },

    /* ----------------------------- 终端录像 ---------------------------- */
    /** events 仍落盘（Wireshark/回放直接读文件），这里只管元数据 */
    async recNew(meta) {
      const { fs, path } = require('../store');
      const store = require('../store');
      const id = store.uid('rec_');
      const file = path.join(store.REC_DIR, `${id}.ndjson`);
      const startedAt = meta.startedAt || new Date().toISOString();
      const data = { t: 'meta', ...meta, id, startedAt };
      fs.writeFileSync(file, JSON.stringify(data) + '\n', 'utf8');
      await q(`INSERT INTO ${PG('recordingMeta')} (id, started_at, data) VALUES ($1,$2,$3)
               ON CONFLICT (id) DO UPDATE SET started_at = EXCLUDED.started_at, data = EXCLUDED.data`,
        [id, startedAt, { t: 'meta', ...meta, startedAt }]);
      return { id, file };
    },
    async recAppend(file, ev) {
      const { fs } = require('../store');
      try { fs.appendFileSync(file, JSON.stringify(ev) + '\n', 'utf8'); } catch { }
    },
    async recList({ limit = 100, host = '', user = '' } = {}) {
      const w = [], p = [];
      if (host) { w.push(`data->>'host' = $${p.length + 1}`); p.push(host); }
      if (user) { w.push(`data->>'user' = $${p.length + 1}`); p.push(user); }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const rows = await q(`SELECT id, started_at, data FROM ${PG('recordingMeta')} ${where}
                            ORDER BY started_at DESC LIMIT ${Number(limit) || 100}`, p);
      const out = [];
      for (const r of rows) {
        const meta = r.data || {};
        const stat = recordingStat(r.id);
        out.push({
          ...meta,
          ...stat,
          events: stat.events,
          bytes: stat.bytes,
          file: `${r.id}.ndjson`
        });
      }
      return out;
    },
    async recRead(id) {
      const { fs, path } = require('../store');
      const full = path.join(require('../store').REC_DIR, `${id}.ndjson`);
      if (!fs.existsSync(full)) return null;
      const lines = fs.readFileSync(full, 'utf8').split('\n').filter(Boolean)
        .map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      return { meta: lines.find(x => x.t === 'meta') || {}, events: lines.filter(x => x.t !== 'meta') };
    },
    async recRemove(id) {
      const { fs, path } = require('../store');
      const full = path.join(require('../store').REC_DIR, `${id}.ndjson`);
      if (fs.existsSync(full)) { try { fs.unlinkSync(full); } catch { } }
      await q(`DELETE FROM ${PG('recordingMeta')} WHERE id = $1`, [id]);
      return true;
    },

    /* ----------------------------- 抓包文件 ---------------------------- */
    async capSave(meta) {
      const row = Object.assign({ id: require('../store').uid('cap_'), at: new Date().toISOString() }, meta);
      row.fileId = row.fileId || row.id;
      await q(`INSERT INTO ${PG('captureFiles')} (id, name, path, size, iface, mode, filter, source, started_at, ended_at, data)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
               ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, data = EXCLUDED.data`,
        [row.id, row.name, row.path, row.size, row.iface, row.mode, row.filter, row.source,
        row.startedAt || row.started_at, row.endedAt || row.ended_at, row]);
      return row;
    },
    async capList({ limit = 100 } = {}) {
      const r = await q(`SELECT * FROM ${PG('captureFiles')} ORDER BY started_at DESC LIMIT ${Number(limit) || 100}`);
      return r.map(x => ({ ...(x.data || {}), ...rowToObj(x, T('captureFiles')) }));
    },
    async capRemove(id) {
      await q(`DELETE FROM ${PG('captureFiles')} WHERE id = $1`, [id]);
      return true;
    },

    /* --------------------------- 采集任务（P1） --------------------------- */
    async taskList() { return (await q(`SELECT * FROM ${PG('captureTasks')} ORDER BY created_at`)).map(r => unpackTask(r)); },
    async taskFind(id) { return unpackTask(first(await q(`SELECT * FROM ${PG('captureTasks')} WHERE id = $1`, [id]))); },
    async taskSave(t) {
      const cur = t.id ? await this.taskFind(t.id) : null;
      const row = {
        id: t.id || require('../store').uid('ctask_'),
        name: t.name || cur?.name || '采集任务',
        iface: t.iface !== undefined ? t.iface : cur?.iface ?? '',
        bpf: t.bpf !== undefined ? t.bpf : cur?.bpf ?? '',
        pcapSize: t.pcapSize !== undefined ? t.pcapSize : cur?.pcapSize ?? 100,
        retainHours: t.retainHours !== undefined ? t.retainHours : cur?.retainHours ?? 72,
        enabled: t.enabled !== undefined ? !!t.enabled : (cur?.enabled ?? false),
        status: t.status !== undefined ? t.status : cur?.status ?? 'idle',
        runs: t.runs !== undefined ? t.runs : cur?.runs ?? 0,
        data: t.data !== undefined ? t.data : cur?.data ?? {}
      };
      return upsert('captureTasks', { ...row, updatedAt: new Date().toISOString() });
    },
    /* 采集任务字段较多（seconds/hosts/credentialId/intervalSec…），未建列的放进 data 里一并存取 */
    async taskSave(t) {
      const cur = t.id ? await this.taskFind(t.id) : null;
      const known = ['id', 'name', 'iface', 'bpf', 'pcapSize', 'retainHours', 'enabled',
        'status', 'lastStartedAt', 'lastEndedAt', 'runs', 'createdAt', 'updatedAt'];
      const extra = {};
      for (const [k, v] of Object.entries(t || {})) if (!known.includes(k)) extra[k] = v;
      const row = {
        id: t.id || require('../store').uid('ctask_'),
        name: t.name ?? cur?.name ?? '采集任务',
        iface: t.iface ?? cur?.iface ?? '',
        bpf: t.bpf ?? cur?.bpf ?? '',
        pcapSize: Number(t.pcapSize ?? cur?.pcapSize ?? 100),
        retainHours: Number(t.retainHours ?? cur?.retainHours ?? 72),
        enabled: t.enabled !== undefined ? !!t.enabled : (cur?.enabled ?? false),
        status: t.status ?? cur?.status ?? 'idle',
        runs: Number(t.runs ?? cur?.runs ?? 0),
        data: { ...(cur?.data || {}), ...extra },
        updatedAt: new Date().toISOString()
      };
      const out = await upsert('captureTasks', row);
      return out ? unpackTask({ ...out, data: row.data }) : null;
    },
    async taskRemove(id) { const r = await q(`DELETE FROM ${PG('captureTasks')} WHERE id = $1 RETURNING id`, [id]); return r.length > 0; },

    /* --------------------------- 会话库（P2） --------------------------- */
    async flowInsert(rows) {
      const list = arr(rows).filter(r => r && r.id);
      if (!list.length) return 0;
      const cols = ['id', 'started_at', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'app_proto',
        'task_id', 'file_id', 'bytes', 'pkts', 'duration_ms', 'hint', 'tags'];
      const vals = [];
      const tuples = list.map((r, i) => {
        const base = i * cols.length;
        const v = {
          id: r.id, started_at: r.startedAt || new Date().toISOString(),
          src_ip: r.srcIp || r.src_ip, dst_ip: r.dstIp || r.dst_ip,
          src_port: r.srcPort ?? r.src_port, dst_port: r.dstPort ?? r.dst_port,
          proto: r.proto, app_proto: r.appProto || r.app_proto,
          task_id: r.taskId || r.task_id || null, file_id: r.fileId || r.file_id || null,
          bytes: Number(r.bytes || 0), pkts: Number(r.pkts || 0),
          duration_ms: Number(r.durationMs ?? (r.duration_ms || 0)),
          hint: r.hint || r.hint || {}, tags: Array.isArray(r.tags) ? r.tags : (r.tags ? [r.tags] : [])
        };
        cols.forEach((c, j) => vals.push(v[c]));
        return `(${cols.map((_, j) => `$${base + j + 1}`).join(', ')})`;
      });
      const sql = `INSERT INTO ${PG('flowSessions')} (${cols.map(c => `"${c}"`).join(', ')})
                   VALUES ${tuples.join(', ')}
                   ON CONFLICT (id) DO NOTHING`;
      await q(sql, vals);
      return list.length;
    },
    async flowSearch(qy = {}) {
      const { from = '', to = '', ip = '', proto = '', taskId = '', fileId = '', limit = 200, offset = 0 } = qy;
      const w = [], p = [];
      const like = (col) => { w.push(`${col} ILIKE $${p.length + 1}`); p.push(`%${ip}%`); };
      if (from) { w.push(`started_at >= $${p.length + 1}`); p.push(from); }
      if (to) { w.push(`started_at <= $${p.length + 1}`); p.push(to); }
      if (ip) { like('src_ip'); like('dst_ip'); }
      if (proto) { w.push(`app_proto = $${p.length + 1}`); p.push(proto); }
      if (taskId) { w.push(`task_id = $${p.length + 1}`); p.push(taskId); }
      if (fileId) { w.push(`file_id = $${p.length + 1}`); p.push(fileId); }
      const where = w.length ? 'WHERE ' + w.join(' OR ') : '';
      const lim = Number(limit) || 200, off = Number(offset) || 0;
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('flowSessions')} ${where}`, p))[0]?.n ?? 0;
      const rows = await q(`SELECT * FROM ${PG('flowSessions')} ${where} ORDER BY started_at DESC LIMIT ${lim} OFFSET ${off}`, p);
      return { total, rows: rows.map(r => rowToObj(r, T('flowSessions'))) };
    },
    async flowAgg(where = {}) {
      const { proto = '', ip = '' } = where || {};
      const w = [], p = [];
      if (proto) { w.push(`app_proto = $${p.length + 1}`); p.push(proto); }
      if (ip) { w.push(`(src_ip = $${p.length + 1} OR dst_ip = $${p.length + 1})`); p.push(ip, ip); }
      const cond = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const rows = await q(`SELECT src_ip, dst_ip, src_port, dst_port, app_proto,
                                   sum(bytes)::bigint AS bytes, sum(pkts)::bigint AS pkts, count(*)::int AS count
                            FROM ${PG('flowSessions')} ${cond}
                            GROUP BY src_ip, dst_ip, src_port, dst_port, app_proto
                            ORDER BY bytes DESC LIMIT 40`, p);
      return rows.map(r => ({
        key: [r.src_ip, r.dst_ip, r.src_port, r.dst_port].join('→'),
        srcIp: r.src_ip, dstIp: r.dst_ip, srcPort: r.src_port, dstPort: r.dst_port,
        appProto: r.app_proto, bytes: Number(r.bytes), pkts: Number(r.pkts), count: r.count
      }));
    },
    async flowById(id) { return rowToObj(first(await q(`SELECT * FROM ${PG('flowSessions')} WHERE id = $1`, [id])), T('flowSessions')); },

    /* --------------------------- 网络扫描（P3） --------------------------- */
    async scanRunSave(row) {
      return upsert('scanRuns', row);
    },
    async scanRunList({ limit = 50, taskId = '' } = {}) {
      const w = [], p = [];
      if (taskId) { w.push(`task_id = $${p.length + 1}`); p.push(taskId); }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const r = await q(`SELECT * FROM ${PG('scanRuns')} ${where} ORDER BY started_at DESC LIMIT ${Number(limit) || 50}`, p);
      return r.map(x => rowToObj(x, T('scanRuns')));
    },
    async scanRunFind(id) { return rowToObj(first(await q(`SELECT * FROM ${PG('scanRuns')} WHERE id = $1`, [id])), T('scanRuns')); },

    async scanHostInsert(rows) {
      const list = arr(rows).filter(r => r && r.id);
      if (!list.length) return 0;
      const cols = ['id', 'run_id', 'task_id', 'ip', 'hostname', 'mac', 'alive', 'open_ports', 'risk_level', 'risk_tags'];
      const vals = [];
      const tuples = list.map((r, i) => {
        const base = i * cols.length;
        const v = {
          id: r.id, run_id: r.runId || r.run_id || null, task_id: r.taskId || r.task_id || null,
          ip: r.ip, hostname: r.hostname || '', mac: r.mac || null,
          alive: r.alive !== false, open_ports: Number(r.openPorts || 0),
          risk_level: r.riskLevel || r.risk_level || 'info',
          risk_tags: Array.isArray(r.riskTags) ? r.riskTags : (r.riskTags ? [r.riskTags] : [])
        };
        cols.forEach((c, j) => vals.push(v[c]));
        return `(${cols.map((_, j) => `$${base + j + 1}`).join(', ')})`;
      });
      // 同一台主机只留最新一条，避免重复扫描把记录刷爆
      await q(`INSERT INTO ${PG('scanHosts')} (${cols.map(c => `"${c}"`).join(', ')}) VALUES ${tuples.join(', ')}
               ON CONFLICT (id) DO UPDATE SET open_ports = EXCLUDED.open_ports,
                 risk_level = EXCLUDED.risk_level, risk_tags = EXCLUDED.risk_tags, created_at = now()`, vals);
      return list.length;
    },
    async scanHostSearch({ runId = '', ip = '', risk = '', limit = 200, offset = 0 } = {}) {
      const w = [], p = [];
      if (runId) { w.push(`run_id = $${p.length + 1}`); p.push(runId); }
      if (ip) { w.push(`(ip = $${p.length + 1} OR ip LIKE $${p.length + 1})`); p.push(ip, `${ip}%`); }
      if (risk) { w.push(`risk_level = $${p.length + 1}`); p.push(risk); }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const lim = Number(limit) || 200, off = Number(offset) || 0;
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('scanHosts')} ${where}`, p))[0]?.n ?? 0;
      const rows = await q(`SELECT * FROM ${PG('scanHosts')} ${where}
        ORDER BY array_position(ARRAY['info','low','medium','high','critical'], risk_level) DESC, ip
        LIMIT ${lim} OFFSET ${off}`, p);
      return { total, rows: rows.map(r => rowToObj(r, T('scanHosts'))) };
    },

    async scanPortInsert(rows) {
      const list = arr(rows).filter(r => r && r.id);
      if (!list.length) return 0;
      const cols = ['id', 'run_id', 'task_id', 'host_ip', 'ip', 'port', 'proto', 'state',
        'service', 'product', 'banner', 'risk_level', 'risk_desc'];
      const vals = [];
      const tuples = list.map((r, i) => {
        const base = i * cols.length;
        const v = {
          id: r.id, run_id: r.runId || r.run_id || null, task_id: r.taskId || r.task_id || null,
          host_ip: r.hostIp || r.host_ip || r.ip, ip: r.ip,
          port: Number(r.port), proto: r.proto || 'tcp', state: r.state || 'open',
          service: r.service || '', product: r.product || '', banner: r.banner || '',
          risk_level: r.riskLevel || r.risk_level || 'info', risk_desc: r.riskDesc || r.risk_desc || ''
        };
        cols.forEach((c, j) => vals.push(v[c]));
        return `(${cols.map((_, j) => `$${base + j + 1}`).join(', ')})`;
      });
      await q(`INSERT INTO ${PG('scanPorts')} (${cols.map(c => `"${c}"`).join(', ')}) VALUES ${tuples.join(', ')}
               ON CONFLICT (id) DO NOTHING`, vals);
      return list.length;
    },
    async scanPortSearch({ runId = '', ip = '', port = '', state = '', risk = '', service = '', limit = 500, offset = 0 } = {}) {
      const w = [], p = [];
      if (runId) { w.push(`run_id = $${p.length + 1}`); p.push(runId); }
      if (ip) { w.push(`(host_ip = $${p.length + 1} OR host_ip LIKE $${p.length + 1})`); p.push(ip, `${ip}%`); }
      if (port) { w.push(`port = $${p.length + 1}`); p.push(Number(port)); }
      if (state) { w.push(`state = $${p.length + 1}`); p.push(state); }
      if (risk) { w.push(`risk_level = $${p.length + 1}`); p.push(risk); }
      if (service) { w.push(`service ILIKE $${p.length + 1}`); p.push(`%${service}%`); }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const lim = Number(limit) || 500, off = Number(offset) || 0;
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('scanPorts')} ${where}`, p))[0]?.n ?? 0;
      const rows = await q(`SELECT * FROM ${PG('scanPorts')} ${where}
        ORDER BY array_position(ARRAY['info','low','medium','high','critical'], risk_level) DESC, port
        LIMIT ${lim} OFFSET ${off}`, p);
      return { total, rows: rows.map(r => rowToObj(r, T('scanPorts'))) };
    },
    async scanPortStats({ runId = '' } = {}) {
      const p = [];
      const cond = runId ? `WHERE run_id = $${p.push(runId)}` : '';
      const byPort = await q(`SELECT port, count(*)::int AS count FROM ${PG('scanPorts')} ${cond}
                              GROUP BY port ORDER BY count DESC, port LIMIT 30`, p);
      const byRisk = await q(`SELECT risk_level, count(*)::int AS count FROM ${PG('scanPorts')} ${cond}
                              GROUP BY risk_level`, p);
      const byService = await q(`SELECT service, count(*)::int AS count FROM ${PG('scanPorts')} ${cond}
                                 GROUP BY service ORDER BY count DESC, service LIMIT 30`, p);
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('scanPorts')} ${cond}`, p))[0]?.n ?? 0;
      return {
        total,
        byPort: byPort.map(r => ({ port: r.port, count: r.count })),
        byRisk: byRisk.map(r => ({ level: r.risk_level, count: r.count }))
          .sort((a, b) => (LEVELS.indexOf(b.level) - LEVELS.indexOf(a.level))),
        byService: byService.map(r => ({ service: r.service, count: r.count }))
      };
    },

    async scanTaskList() { return (await q(`SELECT * FROM ${PG('scanTasks')} ORDER BY created_at`)).map(r => unpackScanTask(r)); },
    async scanTaskFind(id) { return unpackScanTask(first(await q(`SELECT * FROM ${PG('scanTasks')} WHERE id = $1`, [id]))); },
    async scanTaskSave(t) {
      const cur = t.id ? await this.scanTaskFind(t.id) : null;
      const row = {
        id: t.id || require('../store').uid('stask_'),
        name: t.name ?? cur?.name ?? '扫描任务',
        targets: t.targets ?? cur?.targets ?? '',
        ports: t.ports ?? cur?.ports ?? '22,80,443',
        discoverMode: t.discoverMode ?? cur?.discoverMode ?? 'tcp',
        concurrency: Number(t.concurrency ?? cur?.concurrency ?? 60),
        timeoutMs: Number(t.timeoutMs ?? cur?.timeoutMs ?? 1200),
        banner: t.banner !== undefined ? !!t.banner : (cur?.banner ?? true),
        enabled: t.enabled !== undefined ? !!t.enabled : (cur?.enabled ?? false),
        status: t.status ?? cur?.status ?? 'idle',
        intervalSec: Number(t.intervalSec ?? cur?.intervalSec ?? 3600),
        retainHours: Number(t.retainHours ?? cur?.retainHours ?? 72),
        runs: Number(t.runs ?? cur?.runs ?? 0),
        lastStartedAt: t.lastStartedAt ?? cur?.lastStartedAt ?? null,
        lastEndedAt: t.lastEndedAt ?? cur?.lastEndedAt ?? null,
        updatedAt: new Date().toISOString()
      };
      return upsert('scanTasks', row);
    },
    async scanTaskRemove(id) { const r = await q(`DELETE FROM ${PG('scanTasks')} WHERE id = $1 RETURNING id`, [id]); return r.length > 0; },
    async scanRemoveOld(cutIso, taskId = '') {
      const p = [cutIso];
      const where = taskId ? (p.push(taskId), 'task_id = $2') : 'started_at < $1';
      const ids = (await q(`SELECT id FROM ${PG('scanRuns')} WHERE ${where}`, p)).map(x => x.id);
      if (!ids.length) return { runs: 0, hosts: 0, ports: 0 };
      const ports = (await q(`DELETE FROM ${PG('scanPorts')} WHERE run_id = ANY($1::text[]) RETURNING id`, [ids])).length;
      const hosts = (await q(`DELETE FROM ${PG('scanHosts')} WHERE run_id = ANY($1::text[]) RETURNING id`, [ids])).length;
      const runs = (await q(`DELETE FROM ${PG('scanRuns')} WHERE id = ANY($1::text[]) RETURNING id`, [ids])).length;
      return { runs, hosts, ports };
    },
    async flowRemoveOld(cutIso, taskIds = []) {
      const ids = Array.isArray(taskIds) ? taskIds.filter(Boolean) : [];
      const r = await q(`DELETE FROM ${PG('flowSessions')}
        WHERE started_at < $1 ${ids.length ? 'AND (task_id IS NULL OR NOT (task_id = ANY($2::text[])))' : ''}`,
        ids.length ? [cutIso, ids] : [cutIso]);
      return r.rowCount || 0;
    },

    /* ------------------------ 网络诊断工具箱（P3） ------------------------ */
    async netdiagRunSave(row) { return upsert('netdiagRuns', row); },
    async netdiagRunList({ limit = 50, tool = '', taskId = '' } = {}) {
      const w = [], p = [];
      if (tool) { p.push(tool); w.push(`tool = $${p.length}`); }
      if (taskId) { p.push(taskId); w.push(`task_id = $${p.length}`); }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const r = await q(`SELECT * FROM ${PG('netdiagRuns')} ${where} ORDER BY started_at DESC LIMIT ${Number(limit) || 50}`, p);
      return r.map(x => rowToObj(x, T('netdiagRuns')));
    },
    async netdiagRunFind(id) { return rowToObj(first(await q(`SELECT * FROM ${PG('netdiagRuns')} WHERE id = $1`, [id])), T('netdiagRuns')); },
    async netdiagRunRemoveOld(cutIso, taskId = '') {
      const p = [cutIso], w = ['started_at < $1'];
      if (taskId) { p.push(taskId); w.push(`task_id = $${p.length}`); }
      const r = await q(`DELETE FROM ${PG('netdiagRuns')} WHERE ${w.join(' AND ')} RETURNING id`, p);
      return r.length;
    },

    async netdiagHostInsert(rows) {
      // 同一工具 + 同一 IP 只留最新一条，与 JSON 驱动行为一致
      return bulkInsert('netdiagHosts', rows, {
        jsonCols: ['data'], touchCols: ['created_at'], conflict: ['tool', 'ip']
      });
    },
    async netdiagHostSearch({ runId = '', tool = '', ip = '', risk = '', keyword = '', limit = 300, offset = 0 } = {}) {
      const w = [], p = [];
      if (runId) { p.push(runId); w.push(`run_id = $${p.length}`); }
      if (tool) { p.push(tool); w.push(`tool = $${p.length}`); }
      if (ip) { p.push(ip + '%'); w.push(`ip LIKE $${p.length}`); }
      if (risk) { p.push(risk); w.push(`risk_level = $${p.length}`); }
      if (keyword) {
        p.push('%' + keyword + '%');
        w.push(`(ip || ' ' || coalesce(mac,'') || ' ' || coalesce(vendor,'') || ' ' || coalesce(model,'') || ' ' || coalesce(kind,'') || ' ' || coalesce(risk_desc,'')) ILIKE $${p.length}`);
      }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('netdiagHosts')} ${where}`, p))[0]?.n ?? 0;
      const rows = await q(`SELECT * FROM ${PG('netdiagHosts')} ${where}
        ORDER BY array_position(ARRAY['info','low','medium','high','critical'], coalesce(risk_level,'info')) DESC, created_at DESC
        LIMIT ${Number(limit) || 300} OFFSET ${Number(offset) || 0}`, p);
      return { total, rows: rows.map(r => rowToObj(r, T('netdiagHosts'))) };
    },

    async netdiagFindingInsert(rows) {
      // 问题清单是流水：不同次诊断的同类问题也要各留一条，便于看趋势
      return bulkInsert('netdiagFindings', rows, {
        jsonCols: ['evidence'], touchCols: ['created_at'], conflict: 'id'
      });
    },
    async netdiagFindingSearch({ runId = '', tool = '', level = '', category = '', keyword = '', limit = 300, offset = 0 } = {}) {
      const w = [], p = [];
      if (runId) { p.push(runId); w.push(`run_id = $${p.length}`); }
      if (tool) { p.push(tool); w.push(`tool = $${p.length}`); }
      if (level) { p.push(level); w.push(`level = $${p.length}`); }
      if (category) { p.push(category); w.push(`category = $${p.length}`); }
      if (keyword) {
        p.push('%' + keyword + '%');
        w.push(`(coalesce(target,'') || ' ' || coalesce(title,'') || ' ' || coalesce(detail,'') || ' ' || coalesce(advice,'')) ILIKE $${p.length}`);
      }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('netdiagFindings')} ${where}`, p))[0]?.n ?? 0;
      const rows = await q(`SELECT * FROM ${PG('netdiagFindings')} ${where}
        ORDER BY array_position(ARRAY['info','low','medium','high','critical'], coalesce(level,'info')) DESC, created_at DESC
        LIMIT ${Number(limit) || 300} OFFSET ${Number(offset) || 0}`, p);
      return { total, rows: rows.map(r => rowToObj(r, T('netdiagFindings'))) };
    },
    async netdiagFindingStats({ runId = '', tool = '' } = {}) {
      const w = [], p = [];
      if (runId) { p.push(runId); w.push(`run_id = $${p.length}`); }
      if (tool) { p.push(tool); w.push(`tool = $${p.length}`); }
      const cond = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const byLevel = await q(`SELECT level, count(*)::int AS count FROM ${PG('netdiagFindings')} ${cond} GROUP BY level`, p);
      const byTool = await q(`SELECT tool, count(*)::int AS count FROM ${PG('netdiagFindings')} ${cond} GROUP BY tool ORDER BY count DESC`, p);
      const byCategory = await q(`SELECT coalesce(category,'其他') AS category, count(*)::int AS count FROM ${PG('netdiagFindings')} ${cond} GROUP BY category ORDER BY count DESC`, p);
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('netdiagFindings')} ${cond}`, p))[0]?.n ?? 0;
      const needFix = (await q(`SELECT count(*)::int AS n FROM ${PG('netdiagFindings')} ${cond ? cond + ' AND' : 'WHERE'} level IN ('high','critical')`, p))[0]?.n ?? 0;
      return {
        total,
        byLevel: byLevel.map(x => ({ level: x.level || 'info', count: x.count }))
          .sort((a, b) => LEVELS.indexOf(b.level) - LEVELS.indexOf(a.level)),
        byTool: byTool.map(x => ({ tool: x.tool, count: x.count })),
        byCategory: byCategory.map(x => ({ category: x.category, count: x.count })),
        needFix
      };
    },

    async netdiagLogInsert(rows) {
      return bulkInsert('netdiagLogs', rows, {
        touchCols: ['created_at', 'log_at'], conflict: 'id'
      });
    },
    async netdiagLogSearch({ runId = '', tool = '', rule = '', host = '', level = '', source = '', keyword = '', from = '', to = '', limit = 300, offset = 0 } = {}) {
      const w = [], p = [];
      if (runId) { p.push(runId); w.push(`run_id = $${p.length}`); }
      if (tool) { p.push(tool); w.push(`tool = $${p.length}`); }
      if (rule) { p.push(rule); w.push(`coalesce(rule,'') = $${p.length}`); }
      if (host) { p.push('%' + host + '%'); w.push(`(coalesce(host,'') ILIKE $${p.length} OR coalesce(src_ip,'') = $${p.length + 1})`); p.push(host); }
      if (level) { p.push(level); w.push(`level = $${p.length}`); }
      if (source) { p.push(source); w.push(`source = $${p.length}`); }
      if (from) { p.push(from); w.push(`log_at >= $${p.length}`); }
      if (to) { p.push(to); w.push(`log_at <= $${p.length}`); }
      if (keyword) {
        p.push('%' + keyword + '%');
        w.push(`(coalesce(message,'') || ' ' || coalesce(tag,'') || ' ' || coalesce(host,'') || ' ' || coalesce(rule,'')) ILIKE $${p.length}`);
      }
      const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('netdiagLogs')} ${where}`, p))[0]?.n ?? 0;
      const rows = await q(`SELECT * FROM ${PG('netdiagLogs')} ${where}
        ORDER BY log_at DESC LIMIT ${Number(limit) || 300} OFFSET ${Number(offset) || 0}`, p);
      return { total, rows: rows.map(r => rowToObj(r, T('netdiagLogs'))) };
    },
    async netdiagLogStats({ from = '', runId = '', tool = '' } = {}) {
      const p = [], w = [];
      if (runId) { p.push(runId); w.push(`run_id = $${p.length}`); }
      if (tool) { p.push(tool); w.push(`tool = $${p.length}`); }
      if (from) { p.push(from); w.push(`log_at >= $${p.length}`); }
      const cond = w.length ? 'WHERE ' + w.join(' AND ') : '';
      // 命中规则的日志：单独一条 AND，空条件时不能拼成 "WHERE AND ..."
      const condRule = [...w, 'rule IS NOT NULL'].join(' AND ');
      const byLevel = await q(`SELECT level, count(*)::int AS count FROM ${PG('netdiagLogs')} ${cond} GROUP BY level`, p);
      const byHost = await q(`SELECT host, count(*)::int AS count FROM ${PG('netdiagLogs')} ${cond} GROUP BY host ORDER BY count DESC LIMIT 20`, p);
      const byRule = await q(`SELECT rule, count(*)::int AS count FROM ${PG('netdiagLogs')} WHERE ${condRule} GROUP BY rule ORDER BY count DESC LIMIT 20`, p);
      const bySource = await q(`SELECT source, count(*)::int AS count FROM ${PG('netdiagLogs')} ${cond} GROUP BY source ORDER BY count DESC`, p);
      const total = (await q(`SELECT count(*)::int AS n FROM ${PG('netdiagLogs')} ${cond}`, p))[0]?.n ?? 0;
      return {
        total,
        byLevel: byLevel.map(x => ({ level: x.level || 'info', count: x.count }))
          .sort((a, b) => LEVELS.indexOf(b.level) - LEVELS.indexOf(a.level)),
        byHost, byRule, bySource
      };
    },
    async netdiagLogRemoveOld(cutIso) {
      const r = await q(`DELETE FROM ${PG('netdiagLogs')} WHERE log_at < $1`, [cutIso]);
      return r.rowCount || 0;
    },
    /** tool/runId 给了就只清该来源，行为与 JSON 驱动一致 */
    async netdiagLogClear({ tool = '', runId = '' } = {}) {
      const w = [], p = [];
      if (tool) { p.push(tool); w.push(`tool = $${p.length}`); }
      if (runId) { p.push(runId); w.push(`run_id = $${p.length}`); }
      const cond = w.length ? 'WHERE ' + w.join(' AND ') : '';
      const n = (await q(`SELECT count(*)::int AS n FROM ${PG('netdiagLogs')} ${cond}`, p))[0]?.n ?? 0;
      await q(`DELETE FROM ${PG('netdiagLogs')} ${cond}`, p);
      return n;
    },

    async netdiagTaskList() { return (await q(`SELECT * FROM ${PG('netdiagTasks')} ORDER BY created_at`)).map(r => rowToObj(r, T('netdiagTasks'))); },
    async netdiagTaskFind(id) { return rowToObj(first(await q(`SELECT * FROM ${PG('netdiagTasks')} WHERE id = $1`, [id])), T('netdiagTasks')); },
    async netdiagTaskSave(t) {
      const cur = t.id ? await this.netdiagTaskFind(t.id) : null;
      const row = Object.assign({
        mode: 'local', enabled: false, status: 'idle', intervalSec: 3600,
        retainHours: 168, runs: 0, options: {}
      }, cur || {}, t);
      if (row.options && typeof row.options === 'object' && !Array.isArray(row.options)) row.options = JSON.stringify(row.options);
      return upsert('netdiagTasks', row);
    },
    async netdiagTaskRemove(id) { const r = await q(`DELETE FROM ${PG('netdiagTasks')} WHERE id = $1 RETURNING id`, [id]); return r.length > 0; },
    async netdiagRemoveOld(cutIso, taskId = '') {
      const p = [cutIso]; let w = ['started_at < $1'];
      if (taskId) { p.push(taskId); w = ['task_id = $2']; }   // 删任务时整批删，不看时间
      const ids = (await q(`SELECT id FROM ${PG('netdiagRuns')} WHERE ${w.join(' AND ')}`, p)).map(r => r.id);
      if (!ids.length) return { runs: 0, hosts: 0, findings: 0 };
      const r1 = await q(`DELETE FROM ${PG('netdiagRuns')} WHERE id = ANY($1::text[])`, [ids]);
      const r2 = await q(`DELETE FROM ${PG('netdiagHosts')} WHERE run_id = ANY($1::text[])`, [ids]);
      const r3 = await q(`DELETE FROM ${PG('netdiagFindings')} WHERE run_id = ANY($1::text[])`, [ids]);
      return { runs: r1.rowCount || 0, hosts: r2.rowCount || 0, findings: r3.rowCount || 0 };
    }
  };
}

/* --------------------------------- 小工具 -------------------------------- */
/** 采集任务的额外字段从 data 展开到顶层，业务侧看到的就是一个扁平对象 */
function unpackTask(row) {
  if (!row) return null;
  const o = rowToObj(row, schema.TABLES.captureTasks);
  const extra = row.data && typeof row.data === 'object' ? row.data : {};
  delete o.data;
  return { ...o, ...extra };
}
/** 扫描任务：额外字段（如最近一次结果摘要）从 data 展开到顶层 */
function unpackScanTask(row) {
  if (!row) return null;
  const o = rowToObj(row, schema.TABLES.scanTasks);
  const extra = row.data && typeof row.data === 'object' ? row.data : {};
  delete o.data;
  return { ...o, ...extra };
}
function mergeDeep(base, over) {
  if (Array.isArray(over) || over === null || typeof over !== 'object') return over === undefined ? base : over;
  const out = { ...(base || {}) };
  for (const [k, v] of Object.entries(over)) out[k] = (v && typeof v === 'object' && !Array.isArray(v)) ? mergeDeep(base[k], v) : v;
  return out;
}
function safeJson(s) { try { return JSON.parse(s); } catch { return null; } }
function recordingStat(id) {
  try {
    const { fs, path } = require('../store');
    const full = path.join(require('../store').REC_DIR, `${id}.ndjson`);
    if (!fs.existsSync(full)) return { events: 0, bytes: 0 };
    const lines = fs.readFileSync(full, 'utf8').split('\n').filter(Boolean).slice(1);
    let count = 0, bytes = 0;
    for (const l of lines) { try { const e = JSON.parse(l); count++; bytes += (e.d || '').length; } catch { } }
    return { events: count, bytes };
  } catch { return { events: 0, bytes: 0 }; }
}

module.exports = { build };
