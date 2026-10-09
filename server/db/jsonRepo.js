'use strict';
/**
 * JSON 驱动实现（零依赖，默认模式）
 * 与 PG 驱动实现同一套接口，业务代码无需关心当前跑在哪一种上。
 * 直接复用 server/store.js 的内存库与落盘逻辑，行为与改造前完全一致。
 */
const store = require('../store');
const schema = require('./schema');

const arr = (a) => (Array.isArray(a) ? a : []);
const first = (r) => (Array.isArray(r) ? r[0] : r);
/** 只挑出有值的字段，undefined 一律丢弃，避免把旧值抹成空 */
const pickDefined = (o) => { const r = {}; for (const k of Object.keys(o || {})) if (o[k] !== undefined) r[k] = o[k]; return r; };
/** 风险等级排序权，用于主机/端口列表的高危优先 */
const scannerLevel = (l) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[String(l || 'info').toLowerCase()] || 0;

function build() {
  return {
    kind: 'json',

    /* ------------------------------ 设置 ------------------------------ */
    async settingsGet() { return store.db.settings; },
    async settingsUpdate(patch) {
      store.db.settings = store.deepMerge(store.db.settings, patch || {});
      store.save(true);
      return store.db.settings;
    },

    /* ------------------------------ 用户 ------------------------------ */
    async usersList() { return arr(store.db.users); },
    async usersFind(id) { return arr(store.db.users).find(u => u.id === id) || null; },
    async usersFindByUsername(n) { return arr(store.db.users).find(u => u.username === n) || null; },
    async usersCreate(o) {
      const u = Object.assign({ id: store.uid('u_'), enabled: true, createdAt: schema.nowIso() }, o);
      store.db.users.push(u); store.save(true); return u;
    },
    async usersUpdate(id, patch) {
      const u = arr(store.db.users).find(x => x.id === id);
      if (!u) return null;
      Object.assign(u, patch);
      store.save(true);
      return u;
    },
    async usersRemove(id) {
      const i = store.db.users.findIndex(x => x.id === id);
      if (i < 0) return false;
      store.db.users.splice(i, 1); store.save(true); return true;
    },

    /* ----------------------------- 凭据库 ----------------------------- */
    async credentialsList() { return arr(store.db.credentials); },
    async credentialsFind(id) { return arr(store.db.credentials).find(x => x.id === id) || null; },
    async credentialsCreate(o) {
      const c = Object.assign({ id: store.uid('cred_'), createdAt: schema.nowIso() }, o);
      store.db.credentials.push(c); store.save(true); return c;
    },
    async credentialsUpdate(id, patch) {
      const c = arr(store.db.credentials).find(x => x.id === id);
      if (!c) return null;
      Object.assign(c, patch); store.save(true); return c;
    },
    async credentialsRemove(id) {
      const i = store.db.credentials.findIndex(x => x.id === id);
      if (i < 0) return false;
      store.db.credentials.splice(i, 1); store.save(true); return true;
    },

    /* ---------------------------- 命令模板 ---------------------------- */
    async templatesList() { return arr(store.db.templates); },
    async templatesFind(id) { return arr(store.db.templates).find(x => x.id === id) || null; },
    async templatesCreate(o) {
      const t = Object.assign({ id: store.uid('tpl_'), commands: [], danger: false }, o);
      store.db.templates.push(t); store.save(true); return t;
    },
    async templatesUpdate(id, patch) {
      const t = arr(store.db.templates).find(x => x.id === id);
      if (!t) return null;
      Object.assign(t, patch); store.save(true); return t;
    },
    async templatesRemove(id) {
      const i = store.db.templates.findIndex(x => x.id === id);
      if (i < 0) return false;
      store.db.templates.splice(i, 1); store.save(true); return true;
    },

    /* ------------------------------ 告警 ------------------------------ */
    async alarmsList() { return arr(store.db.alarms); },
    async alarmsFind(idOrEventid) {
      return arr(store.db.alarms).find(a => a.id === idOrEventid || a.eventid === idOrEventid) || null;
    },
    async alarmsCreate(o) {
      const a = Object.assign({
        id: store.uid('al_'), source: 'manual', severity: 'information',
        status: 'open', clock: store.nowSec(), createdAt: schema.nowIso()
      }, o);
      store.db.alarms.push(a); store.save(true); return a;
    },
    async alarmsUpdate(idOrEventid, patch) {
      const i = store.db.alarms.findIndex(a => a.id === idOrEventid || a.eventid === idOrEventid);
      if (i < 0) return null;
      Object.assign(store.db.alarms[i], patch);
      store.save(true);
      return store.db.alarms[i];
    },
    async alarmsRemove(idOrEventid) {
      const i = store.db.alarms.findIndex(a => a.id === idOrEventid || a.eventid === idOrEventid);
      if (i < 0) return false;
      store.db.alarms.splice(i, 1); store.save(true); return true;
    },

    /* -------------------------- 设备补充信息 -------------------------- */
    async inventoryGet(host) { return (store.db.inventory || {})[host] || {}; },
    async inventorySet(host, data) {
      store.db.inventory = store.db.inventory || {};
      store.db.inventory[host] = { ...((store.db.inventory[host] || {})), ...(data || {}) };
      store.save(true);
      return store.db.inventory[host];
    },
    async inventoryAll() { return store.db.inventory || {}; },

    /* ------------------------------ 拓扑 ------------------------------ */
    async topologyGet() { return store.db.topology || { nodes: [], links: [] }; },
    async topologySet(v) {
      store.db.topology = { nodes: (v && v.nodes) || [], links: (v && v.links) || [] };
      store.save(true);
      return store.db.topology;
    },

    /* --------------------------- AI 问答历史 --------------------------- */
    async aiAdd(row) {
      store.db.aiHistory = arr(store.db.aiHistory);
      store.db.aiHistory.push(Object.assign({ id: store.uid('ai_'), at: schema.nowIso() }, row));
      if (store.db.aiHistory.length > 500) store.db.aiHistory = store.db.aiHistory.slice(-500);
      store.save();
      return row;
    },
    async aiList(limit = 50, username = '') {
      const rows = arr(store.db.aiHistory).filter(h => !username || h.user === username);
      return rows.slice(-limit).reverse();
    },

    /* ----------------------------- 审计日志 ---------------------------- */
    async auditWrite(entry) { return store.audit(entry); },
    async auditRead(opts = {}) { return store.readAudit(opts); },
    async auditCount() { return store.readAudit({ limit: 10000 }).length; },

    /* ----------------------------- 测速结果 ---------------------------- */
    async speedSave(row) { return store.saveSpeedResult(row); },
    async speedList(limit = 50) { return store.listSpeedResults(limit); },

    /* ----------------------------- 终端录像 ---------------------------- */
    async recNew(meta) { return store.newRecording(meta); },
    async recAppend(file, ev) { return store.appendRecording(file, ev); },
    async recList(opts = {}) { return store.listRecordings(opts); },
    async recRead(id) { return store.readRecording(id); },
    async recRemove(id) { return store.deleteRecording(id); },

    /* ----------------------------- 抓包文件 ---------------------------- */
    async capSave(meta) {
      store.db.captureFiles = arr(store.db.captureFiles);
      const i = store.db.captureFiles.findIndex(x => x.id === meta.id);
      const row = Object.assign({ id: store.uid('cap_'), at: schema.nowIso() }, meta);
      if (i >= 0) store.db.captureFiles[i] = row; else store.db.captureFiles.push(row);
      store.save(true);
      return row;
    },
    async capList({ limit = 100 } = {}) {
      return arr(store.db.captureFiles)
        .slice().sort((a, b) => String(b.at || '').localeCompare(String(a.at || '')))
        .slice(0, limit);
    },
    async capRemove(id) {
      const i = store.db.captureFiles.findIndex(x => x.id === id);
      if (i < 0) return false;
      store.db.captureFiles.splice(i, 1); store.save(true); return true;
    },

    /* --------------------------- 采集任务（P1） --------------------------- */
    async taskList() { return arr(store.db.captureTasks); },
    async taskFind(id) { return arr(store.db.captureTasks).find(x => x.id === id) || null; },
    async taskSave(t) {
      store.db.captureTasks = arr(store.db.captureTasks);
      const row = Object.assign({ id: store.uid('ctask_'), iface: '', bpf: '', pcapSize: 100, retainHours: 72, enabled: false, status: 'idle', runs: 0, updatedAt: schema.nowIso() }, t);
      const i = store.db.captureTasks.findIndex(x => x.id === row.id);
      if (i >= 0) store.db.captureTasks[i] = row; else store.db.captureTasks.push(row);
      store.save(true);
      return row;
    },
    async taskRemove(id) {
      const i = store.db.captureTasks.findIndex(x => x.id === id);
      if (i < 0) return false;
      store.db.captureTasks.splice(i, 1); store.save(true); return true;
    },

    /* --------------------------- 网络扫描（P3） --------------------------- */
    async scanRunSave(row) {
      store.db.scanRuns = arr(store.db.scanRuns);
      const i = store.db.scanRuns.findIndex(x => x.id === row.id);
      const cur = i >= 0 ? store.db.scanRuns[i] : {};
      const next = { ...cur, ...row, id: row.id };
      if (i >= 0) store.db.scanRuns[i] = next; else store.db.scanRuns.push(next);
      store.save(true);
      return next;
    },
    async scanRunList({ limit = 50, taskId = '' } = {}) {
      let rows = arr(store.db.scanRuns);
      if (taskId) rows = rows.filter(r => r.taskId === taskId);
      return rows.slice().sort((a, b) => String(b.startedAt || '').localeCompare(String(a.startedAt || ''))).slice(0, limit);
    },
    async scanRunFind(id) { return arr(store.db.scanRuns).find(r => r.id === id) || null; },

    async scanHostInsert(rows) {
      store.db.scanHosts = arr(store.db.scanHosts);
      // 同一台主机只保留最新一条，避免重复扫描把记录刷爆
      const seen = new Set();
      const keep = [];
      for (const r of rows.slice().reverse()) {
        if (seen.has(r.ip)) continue;
        seen.add(r.ip);
        keep.push(r);
      }
      for (const r of keep) store.db.scanHosts.push(r);
      if (store.db.scanHosts.length > 100000) store.db.scanHosts = store.db.scanHosts.slice(-100000);
      store.save(true);
      return keep.length;
    },
    async scanHostSearch({ runId = '', ip = '', risk = '', limit = 200, offset = 0 } = {}) {
      let rows = arr(store.db.scanHosts);
      if (runId) rows = rows.filter(r => r.runId === runId);
      if (ip) rows = rows.filter(r => String(r.ip || '') === ip || String(r.ip || '').startsWith(ip));
      if (risk) rows = rows.filter(r => (r.riskLevel || 'info') === risk);
      rows.sort((a, b) => (scannerLevel(b.riskLevel) - scannerLevel(a.riskLevel)) || String(b.ip).localeCompare(String(a.ip)));
      const total = rows.length;
      return { total, rows: rows.slice(offset, offset + limit) };
    },

    async scanPortInsert(rows) {
      store.db.scanPorts = arr(store.db.scanPorts);
      for (const r of rows) store.db.scanPorts.push(r);
      if (store.db.scanPorts.length > 500000) store.db.scanPorts = store.db.scanPorts.slice(-500000);
      store.save(true);
      return rows.length;
    },
    async scanPortSearch({ runId = '', ip = '', port = '', state = '', risk = '', service = '', limit = 500, offset = 0 } = {}) {
      let rows = arr(store.db.scanPorts);
      if (runId) rows = rows.filter(r => r.runId === runId);
      if (ip) rows = rows.filter(r => String(r.ip || r.hostIp || '') === ip || String(r.ip || '').startsWith(ip));
      if (port) rows = rows.filter(r => Number(r.port) === Number(port));
      if (state) rows = rows.filter(r => (r.state || 'open') === state);
      if (risk) rows = rows.filter(r => (r.riskLevel || 'info') === risk);
      if (service) rows = rows.filter(r => String(r.service || '').includes(service));
      rows.sort((a, b) => scannerLevel(b.riskLevel) - scannerLevel(a.riskLevel) || Number(a.port) - Number(b.port));
      const total = rows.length;
      return { total, rows: rows.slice(offset, offset + limit) };
    },
    async scanPortStats({ runId = '' } = {}) {
      let rows = arr(store.db.scanPorts);
      if (runId) rows = rows.filter(r => r.runId === runId);
      const byPort = new Map(), byRisk = new Map(), byService = new Map();
      for (const r of rows) {
        const p = Number(r.port);
        const e1 = byPort.get(p) || { port: p, count: 0 };
        e1.count++; byPort.set(p, e1);
        const rk = r.riskLevel || 'info';
        byRisk.set(rk, (byRisk.get(rk) || 0) + 1);
        const sv = r.service || 'unknown';
        const e2 = byService.get(sv) || { service: sv, count: 0 };
        e2.count++; byService.set(sv, e2);
      }
      return {
        total: rows.length,
        byPort: [...byPort.values()].sort((a, b) => b.count - a.count).slice(0, 30),
        byRisk: [...byRisk.entries()].map(([k, v]) => ({ level: k, count: v })).sort((a, b) => scannerLevel(b.level) - scannerLevel(a.level)),
        byService: [...byService.values()].sort((a, b) => b.count - a.count).slice(0, 30)
      };
    },

    async scanTaskList() { return arr(store.db.scanTasks); },
    async scanTaskFind(id) { return arr(store.db.scanTasks).find(x => x.id === id) || null; },
    async scanTaskSave(t) {
      const list = arr(store.db.scanTasks);
      const tid = (t && t.id) ? t.id : store.uid('stask_');
      const i = list.findIndex(x => x.id === tid);
      // 已存在就按旧行打补丁，绝不能拿默认值当合并基准：
      // runScan 收尾只回写 lastStartedAt/runs，若走默认值分支会把 targets、ports 清空
      const base = i >= 0 ? list[i] : {
        id: tid, name: '扫描任务', targets: '', ports: '22,80,443',
        discoverMode: 'tcp', concurrency: 60, timeoutMs: 1200, banner: true,
        enabled: false, status: 'idle', intervalSec: 3600, retainHours: 72,
        runs: 0, updatedAt: schema.nowIso()
      };
      const row = Object.assign({}, base, pickDefined(t), { id: tid, updatedAt: schema.nowIso() });
      if (i >= 0) list[i] = row; else list.push(row);
      store.db.scanTasks = list;
      store.save(true);
      return row;
    },
    async scanTaskRemove(id) {
      const i = store.db.scanTasks.findIndex(x => x.id === id);
      if (i < 0) return false;
      store.db.scanTasks.splice(i, 1);
      store.save(true);
      return true;
    },
    async scanRemoveOld(cutIso, taskId = '') {
      const cut = String(cutIso || '');
      const beforeH = store.db.scanHosts.length, beforeP = store.db.scanPorts.length;
      store.db.scanHosts = arr(store.db.scanHosts).filter(r => String(r.createdAt || '') >= cut && !(taskId && r.taskId === taskId));
      store.db.scanPorts = arr(store.db.scanPorts).filter(r => String(r.createdAt || '') >= cut && !(taskId && r.taskId === taskId));
      store.save(true);
      return { hosts: beforeH - store.db.scanHosts.length, ports: beforeP - store.db.scanPorts.length };
    },

    /* ------------------------ 网络诊断工具箱（P3） ------------------------ */
    async netdiagRunSave(r) {
      const list = arr(store.db.netdiagRuns);
      const rid = (r && r.id) ? r.id : store.uid('ndr_');
      const i = list.findIndex(x => x.id === rid);
      // 与扫描任务同理：已存在就按旧行打补丁，不能拿默认值当合并基准
      const base = i >= 0 ? list[i] : {
        id: rid, taskId: '', tool: '', mode: 'local', targets: '',
        status: 'running', score: 100, level: 'info', findingsCount: 0,
        targetsTotal: 0, targetsDone: 0, startedAt: schema.nowIso(), durationMs: 0
      };
      const row = Object.assign({}, base, pickDefined(r), { id: rid });
      if (i >= 0) list[i] = row; else list.unshift(row);
      store.db.netdiagRuns = list;
      store.save(true);
      return row;
    },
    async netdiagRunList({ limit = 50, tool = '', taskId = '' } = {}) {
      let rows = arr(store.db.netdiagRuns);
      if (tool) rows = rows.filter(r => r.tool === tool);
      if (taskId) rows = rows.filter(r => (r.taskId || '') === taskId);
      return rows.slice(0, limit);
    },
    async netdiagRunFind(id) { return arr(store.db.netdiagRuns).find(r => r.id === id) || null; },
    async netdiagRunRemoveOld(cutIso, taskId = '') {
      const cut = String(cutIso || '');
      const before = store.db.netdiagRuns.length;
      store.db.netdiagRuns = arr(store.db.netdiagRuns)
        .filter(r => String(r.startedAt || '') >= cut && !(taskId && r.taskId === taskId));
      store.save(true);
      return before - store.db.netdiagRuns.length;
    },

    async netdiagHostInsert(rows) {
      const list = arr(store.db.netdiagHosts);
      for (const r of rows) {
        if (!r) continue;
        // 同一工具 + 同一 IP 只留最新一条，避免反复巡检把表刷爆
        const i = list.findIndex(x => x.tool === r.tool && x.ip === r.ip);
        if (i >= 0) list[i] = Object.assign({}, list[i], r); else list.push(r);
      }
      store.db.netdiagHosts = list;
      store.save(true);
      return rows.length;
    },
    async netdiagHostSearch({ runId = '', tool = '', ip = '', risk = '', keyword = '', limit = 300, offset = 0 } = {}) {
      let rows = arr(store.db.netdiagHosts);
      if (runId) rows = rows.filter(r => r.runId === runId);
      if (tool) rows = rows.filter(r => r.tool === tool);
      if (ip) rows = rows.filter(r => String(r.ip || '').startsWith(ip));
      if (risk) rows = rows.filter(r => (r.riskLevel || 'info') === risk);
      if (keyword) {
        const k = keyword.toLowerCase();
        rows = rows.filter(r => `${r.ip} ${r.mac} ${r.vendor} ${r.model} ${r.kind} ${r.riskDesc}`.toLowerCase().includes(k));
      }
      rows = rows.slice().sort((a, b) =>
        scannerLevel(b.riskLevel) - scannerLevel(a.riskLevel) || String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
      return { total: rows.length, rows: rows.slice(offset, offset + limit) };
    },

    async netdiagFindingInsert(rows) {
      store.db.netdiagFindings = arr(store.db.netdiagFindings);
      for (const r of rows) if (r) store.db.netdiagFindings.unshift(r);
      if (store.db.netdiagFindings.length > 50000) store.db.netdiagFindings = store.db.netdiagFindings.slice(0, 50000);
      store.save(true);
      return rows.length;
    },
    async netdiagFindingSearch({ runId = '', tool = '', level = '', category = '', keyword = '', limit = 300, offset = 0 } = {}) {
      let rows = arr(store.db.netdiagFindings);
      if (runId) rows = rows.filter(r => r.runId === runId);
      if (tool) rows = rows.filter(r => r.tool === tool);
      if (level) rows = rows.filter(r => (r.level || 'info') === level);
      if (category) rows = rows.filter(r => (r.category || '') === category);
      if (keyword) {
        const k = keyword.toLowerCase();
        rows = rows.filter(r => `${r.target} ${r.title} ${r.detail} ${r.advice}`.toLowerCase().includes(k));
      }
      rows = rows.slice().sort((a, b) =>
        scannerLevel(b.level) - scannerLevel(a.level) || String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
      return { total: rows.length, rows: rows.slice(offset, offset + limit) };
    },
    async netdiagFindingStats({ runId = '', tool = '' } = {}) {
      let rows = arr(store.db.netdiagFindings);
      if (runId) rows = rows.filter(r => r.runId === runId);
      if (tool) rows = rows.filter(r => r.tool === tool);
      const byLevel = new Map(), byTool = new Map(), byCategory = new Map();
      for (const r of rows) {
        const lv = r.level || 'info';
        byLevel.set(lv, (byLevel.get(lv) || 0) + 1);
        byTool.set(r.tool || '-', (byTool.get(r.tool || '-') || 0) + 1);
        byCategory.set(r.category || '其他', (byCategory.get(r.category || '其他') || 0) + 1);
      }
      const toArr = (m) => [...m.entries()].map(([k, v]) => ({ key: k, count: v }));
      return {
        total: rows.length,
        byLevel: toArr(byLevel).map(x => ({ level: x.key, count: x.count }))
          .sort((a, b) => scannerLevel(b.level) - scannerLevel(a.level)),
        byTool: toArr(byTool).map(x => ({ tool: x.key, count: x.count })).sort((a, b) => b.count - a.count),
        byCategory: toArr(byCategory).map(x => ({ category: x.key, count: x.count })).sort((a, b) => b.count - a.count),
        needFix: rows.filter(r => ['high', 'critical'].includes(r.level || '')).length
      };
    },

    async netdiagLogInsert(rows) {
      store.db.netdiagLogs = arr(store.db.netdiagLogs);
      for (const r of rows) if (r) store.db.netdiagLogs.unshift(r);
      // 日志量大：只保留最近 50000 条（落盘体积可控）
      if (store.db.netdiagLogs.length > 50000) store.db.netdiagLogs.length = 50000;
      store.save(true);
      return rows.length;
    },
    async netdiagLogSearch({ runId = '', tool = '', rule = '', host = '', level = '', source = '', keyword = '', from = '', to = '', limit = 300, offset = 0 } = {}) {
      let rows = arr(store.db.netdiagLogs);
      if (runId) rows = rows.filter(r => r.runId === runId);
      if (tool) rows = rows.filter(r => r.tool === tool);
      if (rule) rows = rows.filter(r => (r.rule || '') === rule);
      if (host) rows = rows.filter(r => String(r.host || '').includes(host) || String(r.srcIp || '') === host);
      if (level) rows = rows.filter(r => (r.level || 'info') === level);
      if (source) rows = rows.filter(r => (r.source || 'syslog') === source);
      if (from) rows = rows.filter(r => String(r.logAt || r.createdAt || '') >= from);
      if (to) rows = rows.filter(r => String(r.logAt || r.createdAt || '') <= to);
      if (keyword) {
        const k = keyword.toLowerCase();
        rows = rows.filter(r => `${r.message} ${r.tag} ${r.host} ${r.rule}`.toLowerCase().includes(k));
      }
      rows = rows.slice().sort((a, b) => String(b.logAt || b.createdAt || '').localeCompare(String(a.logAt || a.createdAt || '')));
      return { total: rows.length, rows: rows.slice(offset, offset + limit) };
    },
    async netdiagLogStats({ from = '', runId = '', tool = '' } = {}) {
      let rows = arr(store.db.netdiagLogs);
      if (runId) rows = rows.filter(r => r.runId === runId);
      if (tool) rows = rows.filter(r => r.tool === tool);
      if (from) rows = rows.filter(r => String(r.logAt || r.createdAt || '') >= from);
      const byLevel = new Map(), byHost = new Map(), byRule = new Map(), bySource = new Map();
      for (const r of rows) {
        byLevel.set(r.level || 'info', (byLevel.get(r.level || 'info') || 0) + 1);
        byHost.set(r.host || '-', (byHost.get(r.host || '-') || 0) + 1);
        bySource.set(r.source || 'syslog', (bySource.get(r.source || 'syslog') || 0) + 1);
        if (r.rule) byRule.set(r.rule, (byRule.get(r.rule) || 0) + 1);
      }
      const toArr = (m, key) => [...m.entries()].map(([k, v]) => ({ [key]: k, count: v }));
      return {
        total: rows.length,
        byLevel: toArr(byLevel, 'level').sort((a, b) => scannerLevel(b.level) - scannerLevel(a.level)),
        byHost: toArr(byHost, 'host').sort((a, b) => b.count - a.count).slice(0, 20),
        byRule: toArr(byRule, 'rule').sort((a, b) => b.count - a.count).slice(0, 20),
        bySource: toArr(bySource, 'source').sort((a, b) => b.count - a.count)
      };
    },
    async netdiagLogRemoveOld(cutIso) {
      const cut = String(cutIso || '');
      const before = store.db.netdiagLogs.length;
      store.db.netdiagLogs = arr(store.db.netdiagLogs)
        .filter(r => String(r.logAt || r.createdAt || '') >= cut);
      store.save(true);
      return before - store.db.netdiagLogs.length;
    },
    /** tool/runId 给了就只清该来源，避免前端以为按工具过滤却把整表清空 */
    async netdiagLogClear({ tool = '', runId = '' } = {}) {
      const list = arr(store.db.netdiagLogs);
      const keep = list.filter(r => (tool && r.tool !== tool) || (runId && r.runId !== runId));
      const n = list.length - keep.length;
      store.db.netdiagLogs = keep;
      store.save(true);
      return n;
    },

    async netdiagTaskList() { return arr(store.db.netdiagTasks); },
    async netdiagTaskFind(id) { return arr(store.db.netdiagTasks).find(x => x.id === id) || null; },
    async netdiagTaskSave(t) {
      const list = arr(store.db.netdiagTasks);
      const tid = (t && t.id) ? t.id : store.uid('ndt_');
      const i = list.findIndex(x => x.id === tid);
      const base = i >= 0 ? list[i] : {
        id: tid, name: '诊断任务', tool: 'camera', mode: 'local', targets: '',
        options: {}, enabled: false, status: 'idle', intervalSec: 3600,
        retainHours: 168, runs: 0, updatedAt: schema.nowIso()
      };
      const row = Object.assign({}, base, pickDefined(t), { id: tid, updatedAt: schema.nowIso() });
      if (i >= 0) list[i] = row; else list.push(row);
      store.db.netdiagTasks = list;
      store.save(true);
      return row;
    },
    async netdiagTaskRemove(id) {
      const i = store.db.netdiagTasks.findIndex(x => x.id === id);
      if (i < 0) return false;
      store.db.netdiagTasks.splice(i, 1);
      store.save(true);
      return true;
    },
    async netdiagRemoveOld(cutIso, taskId = '') {
      const cut = String(cutIso || '');
      const list = arr(store.db.netdiagRuns);
      const keep = [], gone = [];
      for (const r of list) {
        if (taskId && r.taskId === taskId) { gone.push(r.id); continue; }
        if (String(r.startedAt || '') < cut) { gone.push(r.id); continue; }
        keep.push(r);
      }
      if (!gone.length) return { runs: 0, hosts: 0, findings: 0 };
      const set = new Set(gone);
      const beforeH = arr(store.db.netdiagHosts).length;
      const beforeF = arr(store.db.netdiagFindings).length;
      store.db.netdiagRuns = keep;
      store.db.netdiagHosts = arr(store.db.netdiagHosts).filter(r => !set.has(r.runId));
      store.db.netdiagFindings = arr(store.db.netdiagFindings).filter(r => !set.has(r.runId));
      store.save(true);
      return {
        runs: gone.length,
        hosts: beforeH - store.db.netdiagHosts.length,
        findings: beforeF - store.db.netdiagFindings.length
      };
    },

    /* --------------------------- 会话库（P2） --------------------------- */
    async flowInsert(rows) {
      store.db.flowSessions = arr(store.db.flowSessions);
      for (const r of rows) if (r && r.id) store.db.flowSessions.push(r);
      if (store.db.flowSessions.length > 200000) store.db.flowSessions = store.db.flowSessions.slice(-200000);
      store.save(true);
      return rows.length;
    },
    async flowSearch(q = {}) {
      const { from = '', to = '', ip = '', proto = '', taskId = '', fileId = '', limit = 200, offset = 0 } = q;
      let rows = arr(store.db.flowSessions);
      if (from) rows = rows.filter(r => r.startedAt >= from);
      if (to) rows = rows.filter(r => r.startedAt <= to);
      if (ip) rows = rows.filter(r => (r.srcIp || r.src_ip || '') === ip || (r.dstIp || r.dst_ip || '') === ip
        || String(r.srcIp || r.src_ip || '').startsWith(ip) || String(r.dstIp || r.dst_ip || '').startsWith(ip));
      if (proto) rows = rows.filter(r => (r.appProto || r.app_proto || '') === proto || (r.proto || r.proto || '') === proto);
      if (taskId) rows = rows.filter(r => (r.taskId || r.task_id) === taskId);
      if (fileId) rows = rows.filter(r => (r.fileId || r.file_id) === fileId);
      const total = rows.length;
      return { total, rows: rows.slice(offset, offset + limit) };
    },
    async flowAgg(where = {}) {
      const { proto = '', ip = '' } = where;
      let rows = arr(store.db.flowSessions);
      if (proto) rows = rows.filter(r => (r.appProto || r.app_proto || '') === proto);
      if (ip) rows = rows.filter(r => String(r.srcIp || r.src_ip) === ip || String(r.dstIp || r.dst_ip) === ip);
      const map = new Map();
      for (const r of rows) {
        const k = [r.srcIp || r.src_ip, r.dstIp || r.dst_ip, r.srcPort || r.src_port, r.dstPort || r.dst_port].join('→');
        const e = map.get(k) || { key: k, bytes: 0, pkts: 0, count: 0, appProto: r.appProto || r.app_proto || r.proto || '' };
        e.bytes += Number(r.bytes || 0); e.pkts += Number(r.pkts || 0); e.count++;
        map.set(k, e);
      }
      return [...map.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 40);
    },
    async flowById(id) { return arr(store.db.flowSessions).find(r => r.id === id || r.id === id) || null; },
    async flowRemoveOld(cutIso, taskIds = []) {
      const ids = Array.isArray(taskIds) ? taskIds : [];
      const before = store.db.flowSessions.length;
      store.db.flowSessions = arr(store.db.flowSessions).filter(r =>
        (r.startedAt || '') >= cutIso && !(ids.includes(r.taskId) || ids.includes(r.task_id)));
      store.save(true);
      return before - store.db.flowSessions.length;
    }
  };
}

module.exports = { build };
