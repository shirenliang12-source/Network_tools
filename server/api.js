'use strict';
/**
 * 业务 API 路由
 */
const express = require('express');
const store = require('./store');
const db = require('./db');
const dpi = require('./dpi');
const dpiMetrics = require('./dpi-metrics');
const capture = require('./capture');
const customProto = require('./custom-proto');
const flowGraph = require('./flow-graph');
const multipart = require('./multipart');
const dashboard = require('./dashboard');
const troubleshoot = require('./troubleshoot');
const deepTools = require('./deep-tools');
const scanner = require('./scanner');
const netdiag = require('./netdiag');
const auth = require('./auth');
const ds = require('./datasource');
const netutil = require('./netutil');
const notify = require('./notify');
const term = require('./term');
const toolbox = require('./toolbox');
const toolboxScan = require('./toolbox-scan');
const wifi = require('./wifi');
const path = require('path');
const fs = require('fs');

const router = express.Router();
const R = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch(e => {
  res.status(500).json({ ok: false, error: e.message || String(e) });
});

/* --------------------------- 通用：主机公开化 --------------------------- */
async function pubHost(h) {
  const inv = await db.inventoryGet(h.host);
  return {
    hostid: h.hostid, host: h.host, name: h.name || h.host, ip: h.ip,
    status: h.status, available: h.available, error: h.error || '',
    maintenance: !!h.maintenance,
    vendor: h.vendor || inv.vendor || '', model: h.model || inv.model || '', os: h.os || '',
    serial: h.serial || '', location: h.location || inv.zone || '',
    zone: inv.zone || h.location || (h.tags && h.tags.zone) || '未分组',
    role: inv.role || (h.tags && h.tags.role) || inferRole(h),
    uptimeSec: h.uptimeSec, cpu: h.cpu, mem: h.mem, temp: h.temp,
    portCount: h.portCount || null,
    health: ds.healthScore(h),
    note: inv.note || '', owner: inv.owner || '', rack: inv.rack || '',
    x: inv.x, y: inv.y
  };
}
function inferRole(h) {
  const s = `${h.name} ${h.host} ${h.model}`;
  if (/FW|Firewall|防火墙|PA-\d|FortiGate|Firepower/.test(s)) return '防火墙';
  if (/CORE|核心|N9K|Nexus|95\d\d/.test(s)) return '核心';
  if (/DIST|汇聚|93\d\d/.test(s)) return '汇聚';
  if (/^SW|S\d{4}|29\d\d|92\d\d/.test(s)) return '接入';
  return '其他';
}

async function allHosts() {
  return ds.cached('hosts', 25, async () => {
    const hs = await ds.getProvider().hosts();
    return Promise.all(hs.map(h => pubHost(h)));
  });
}

/* ================================ 认证 ================================ */
router.post('/auth/login', R(async (req, res) => {
  const { username, password } = req.body || {};
  const r = await auth.login(username, password, auth.clientIp(req));
  if (!r) return res.status(401).json({ ok: false, error: '用户名或密码错误' });
  res.json({ ok: true, ...r });
}));
router.get('/auth/me', auth.authRequired, R(async (req, res) => {
  res.json({ ok: true, user: auth.publicUser(req.user), site: (await db.settingsGet()).site });
}));
router.post('/auth/logout', R(async (req, res) => {
  const u = await auth.attach(req);
  if (u) auth.logAction(req, 'auth.logout', '', '');
  res.json({ ok: true });
}));
router.post('/auth/password', auth.authRequired, R(async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!store.verify(oldPassword, req.user.password)) return res.status(400).json({ ok: false, error: '原密码不正确' });
  await auth.setPassword(req.user.id, newPassword);
  res.json({ ok: true });
}));

/* ============================== 大屏总览 ============================== */
router.get('/overview', auth.authRequired, R(async (req, res) => {
  const hosts = await allHosts();
  const problems = await ds.cached('problems', 20, async () => {
    const p = await ds.getProvider().problems();
    const local = (await db.alarmsList()).filter(a => a.status !== 'closed');
    const map = new Map();
    for (const x of [...p, ...local]) if (!map.has(x.eventid || x.id)) map.set(x.eventid || x.id, x);
    return [...map.values()].sort((a, b) => (b.clock || 0) - (a.clock || 0));
  });
  const active = problems.filter(p => p.status !== 'resolved' && p.status !== 'closed');
  const sevCount = active.reduce((a, p) => (a[p.severity] = (a[p.severity] || 0) + 1, a), {});
  const online = hosts.filter(h => h.status === 1).length;

  const portAgg = { total: 0, up: 0, down: 0, err: 0 };
  const topTraffic = [];
  for (const h of hosts.slice(0, 14)) {
    try {
      const { ports } = await ds.cached('ports:' + h.host, 25, () => ds.getProvider().ports(h.host));
      portAgg.total += ports.length;
      portAgg.up += ports.filter(p => p.operStatus === 1).length;
      portAgg.down += ports.filter(p => p.operStatus !== 1).length;
      portAgg.err += ports.reduce((a, p) => a + (p.inErrors || 0) + (p.outErrors || 0) + (p.crcErrors || 0), 0);
      const total = ports.reduce((a, p) => a + (p.inBps || 0) + (p.outBps || 0), 0);
      topTraffic.push({ host: h.host, name: h.name, total, util: ports.length ? +Math.min(100, ports.reduce((a, p) => a + (p.util || 0), 0) / ports.length).toFixed(1) : 0 });
    } catch { }
  }
  topTraffic.sort((a, b) => b.total - a.total);

  const trend = await ds.getProvider().history(hosts[0]?.hostid, 'traffic', store.nowSec() - 86400, store.nowSec(), 96).catch(() => []);
  const health = { good: 0, warn: 0, bad: 0 };
  hosts.forEach(h => { if (h.health >= 80) health.good++; else if (h.health >= 55) health.warn++; else health.bad++; });

  res.json({
    ok: true,
    kpi: {
      total: hosts.length, online, offline: hosts.length - online,
      alarms: active.length, critical: (sevCount.disaster || 0) + (sevCount.high || 0),
      ports: portAgg, health, avgUtil: topTraffic.length ? +(topTraffic.reduce((a, t) => a + t.util, 0) / topTraffic.length).toFixed(1) : 0
    },
    sevCount,
    hosts: hosts.map(h => ({ host: h.host, name: h.name, ip: h.ip, status: h.status, health: h.health, cpu: h.cpu, mem: h.mem, temp: h.temp, role: h.role, zone: h.zone, vendor: h.vendor, model: h.model, uptimeSec: h.uptimeSec })),
    alarms: active.slice(0, 30),
    topTraffic: topTraffic.slice(0, 10),
    trend,
    datasource: { mode: ds.getProvider().name }
  });
}));

router.get('/overview/trend', auth.authRequired, R(async (req, res) => {
  const range = String(req.query.range || '24h');
  const mins = { '1h': 60, '6h': 360, '24h': 1440, '7d': 10080 }[range] || 1440;
  const to = store.nowSec(), from = to - mins * 60;
  const host = req.query.host || (await allHosts())[0]?.hostid;
  const kind = String(req.query.kind || 'traffic');
  const data = await ds.getProvider().history(host, kind, from, to, mins > 1000 ? 240 : 120).catch(() => []);
  res.json({ ok: true, kind, range, host, data });
}));

/* ============================== 可编辑大屏 ============================== */
// 数据源目录（前端组件面板挑选）
router.get('/dashboard/sources', auth.authRequired, R(async (req, res) => {
  res.json({ ok: true, sources: dashboard.SOURCES });
}));
// 单组件取数
router.get('/dashboard/data', auth.authRequired, R(async (req, res) => {
  const source = String(req.query.source || '');
  const params = {};
  for (const k of Object.keys(req.query)) if (k !== 'source') params[k] = req.query[k];
  const d = await dashboard.getData(source, params);
  res.json(Object.assign({ ok: !d.error, source }, d.error ? { error: d.error } : d));
}));
// 列表 / 新建
router.get('/dashboards', auth.authRequired, R(async (req, res) => {
  res.json({ ok: true, list: await dashboard.listDashboards(), active: (await db.settingsGet()).activeDashboard });
}));
router.post('/dashboards', auth.requirePerm('auth'), R(async (req, res) => {
  const d = await dashboard.createDashboard(String((req.body || {}).name || ''));
  auth.logAction(req, 'dashboard.create', d.id, d.name);
  res.json({ ok: true, dashboard: d });
}));
// 详情
router.get('/dashboards/:id', auth.authRequired, R(async (req, res) => {
  const d = await dashboard.getDashboard(req.params.id);
  if (!d) return res.status(404).json({ ok: false, error: '大屏不存在' });
  res.json({ ok: true, dashboard: d });
}));
// 更新（布局/组件/主题/刷新）
router.put('/dashboards/:id', auth.requirePerm('auth'), R(async (req, res) => {
  const d = await dashboard.updateDashboard(req.params.id, req.body || {});
  if (!d) return res.status(404).json({ ok: false, error: '大屏不存在' });
  auth.logAction(req, 'dashboard.update', req.params.id, d.name);
  res.json({ ok: true, dashboard: d });
}));
// 删除（禁删内置）
router.delete('/dashboards/:id', auth.requirePerm('auth'), R(async (req, res) => {
  const ok = await dashboard.deleteDashboard(req.params.id);
  if (!ok) return res.status(400).json({ ok: false, error: '内置大屏不可删除' });
  auth.logAction(req, 'dashboard.delete', req.params.id, '');
  res.json({ ok: true });
}));
// 激活（设为当前展示大屏）
router.post('/dashboards/:id/activate', auth.requirePerm('auth'), R(async (req, res) => {
  const ok = await dashboard.activateDashboard(req.params.id);
  if (!ok) return res.status(404).json({ ok: false, error: '大屏不存在' });
  auth.logAction(req, 'dashboard.activate', req.params.id, '');
  res.json({ ok: true });
}));

/* ============================== 设备管理 ============================== */
router.get('/devices', auth.authRequired, R(async (req, res) => {
  let list = await allHosts();
  const { keyword = '', zone = '', vendor = '', role = '', status = '', sort = 'name', order = 'asc' } = req.query;
  if (keyword) {
    const k = String(keyword).toLowerCase();
    list = list.filter(h => [h.host, h.name, h.ip, h.model, h.serial, h.location].join(' ').toLowerCase().includes(k));
  }
  if (zone) list = list.filter(h => h.zone === zone);
  if (vendor) list = list.filter(h => h.vendor === vendor);
  if (role) list = list.filter(h => h.role === role);
  if (status !== '') list = list.filter(h => String(h.status) === String(status));
  list.sort((a, b) => {
    const av = a[sort] ?? '', bv = b[sort] ?? '';
    const r = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
    return order === 'desc' ? -r : r;
  });
  const page = Math.max(1, Number(req.query.page || 1)), size = Math.min(200, Number(req.query.size || 20));
  const all = await allHosts();
  res.json({
    ok: true, total: list.length, page, size,
    rows: list.slice((page - 1) * size, page * size),
    meta: {
      zones: [...new Set(all.map(h => h.zone))].filter(Boolean).sort(),
      vendors: [...new Set(all.map(h => h.vendor))].filter(Boolean).sort(),
      roles: [...new Set(all.map(h => h.role))].filter(Boolean).sort()
    }
  });
}));

router.get('/devices/export', auth.authRequired, R(async (req, res) => {
  const list = await allHosts();
  const head = ['设备名', '主机ID', '管理IP', '厂商', '型号', '区域', '角色', '运行时长', '状态', '健康度', 'CPU%', '内存%', '温度℃', '序列号', '系统版本'];
  const rows = list.map(h => [h.name, h.host, h.ip, h.vendor, h.model, h.zone, h.role, ds.human(h.uptimeSec), h.status ? '在线' : '离线', h.health, h.cpu ?? '', h.mem ?? '', h.temp ?? '', h.serial, h.os]);
  const csv = '\ufeff' + [head, ...rows].map(r => r.map(c => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',')).join('\r\n');
  auth.logAction(req, 'device.export', 'all', `${list.length} 台`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="devices-${Date.now()}.csv"`);
  res.send(csv);
}));

router.get('/devices/:host', auth.authRequired, R(async (req, res) => {
  const hosts = await allHosts();
  const h = hosts.find(x => x.host === req.params.host);
  if (!h) return res.status(404).json({ ok: false, error: '设备不存在' });
  const detail = await ds.cached('ports:' + h.host, 20, () => ds.getProvider().ports(h.hostid || h.host));
  const ports = detail.ports || [];
  res.json({ ok: true, host: h, ports, summary: {
    up: ports.filter(p => p.operStatus === 1).length,
    down: ports.filter(p => p.operStatus !== 1).length,
    errTotal: ports.reduce((a, p) => a + (p.inErrors || 0) + (p.outErrors || 0) + (p.crcErrors || 0), 0),
    inTotal: ports.reduce((a, p) => a + (p.inBps || 0), 0),
    outTotal: ports.reduce((a, p) => a + (p.outBps || 0), 0),
    topPorts: [...ports].sort((a, b) => (b.inBps + b.outBps) - (a.inBps + a.outBps)).slice(0, 8)
  } });
}));

router.get('/devices/:host/ports', auth.authRequired, R(async (req, res) => {
  const hosts = await allHosts();
  const h = hosts.find(x => x.host === req.params.host);
  if (!h) return res.status(404).json({ ok: false, error: '设备不存在' });
  const d = await ds.getProvider().ports(h.hostid || h.host);
  res.json({ ok: true, host: h, ports: d.ports || [] });
}));

router.get('/devices/:host/history', auth.authRequired, R(async (req, res) => {
  const hosts = await allHosts();
  const h = hosts.find(x => x.host === req.params.host);
  if (!h) return res.status(404).json({ ok: false, error: '设备不存在' });
  const range = String(req.query.range || '24h');
  const mins = { '1h': 60, '6h': 360, '24h': 1440, '7d': 10080, '30d': 43200 }[range] || 1440;
  const to = store.nowSec(), from = to - mins * 60;
  const kinds = String(req.query.kind || 'traffic').split(',');
  const out = {};
  for (const k of kinds) out[k] = await ds.getProvider().history(h.hostid || h.host, k, from, to, 120).catch(() => []);
  res.json({ ok: true, range, data: out });
}));

router.post('/devices/:host/inventory', auth.required || auth.authRequired, auth.requirePerm('view'), R(async (req, res) => {
  const host = req.params.host;
  const b = req.body || {};
  const invRow = await db.inventorySet(host, b);
  auth.logAction(req, 'device.inventory.update', host, JSON.stringify(b).slice(0, 300));
  res.json({ ok: true, inventory: invRow });
}));

/* ============================== 告警管理 ============================== */
router.get('/alarms', auth.authRequired, R(async (req, res) => {
  const remote = await ds.cached('problems', 20, async () => {
    const p = await ds.getProvider().problems();
    const local = (await db.alarmsList()).filter(a => a.status !== 'closed');
    const map = new Map();
    for (const x of [...p, ...local]) if (!map.has(x.eventid || x.id)) map.set(x.eventid || x.id, x);
    return [...map.values()].sort((a, b) => (b.clock || 0) - (a.clock || 0));
  });
  const { severity = '', status = '', host = '', keyword = '' } = req.query;
  let list = remote;
  if (severity) list = list.filter(a => a.severity === severity);
  if (status) list = list.filter(a => a.status === status);
  if (host) list = list.filter(a => a.host === host);
  if (keyword) list = list.filter(a => (a.title + a.message + a.host).toLowerCase().includes(String(keyword).toLowerCase()));
  const stats = {
    disaster: list.filter(a => a.severity === 'disaster').length,
    high: list.filter(a => a.severity === 'high').length,
    average: list.filter(a => a.severity === 'average').length,
    warning: list.filter(a => a.severity === 'warning').length,
    information: list.filter(a => a.severity === 'information').length
  };
  res.json({ ok: true, rows: list, total: list.length, stats });
}));

router.post('/alarms/:id/ack', auth.requirePerm('alarm'), R(async (req, res) => {
  const id = req.params.id;
  const local = await db.alarmsFind(id);
  if (local) await db.alarmsUpdate(id, { acknowledged: true, status: 'acknowledged', ackBy: req.user.username, ackAt: new Date().toISOString() });
  else { try { await ds.getProvider().ack(id, (req.body || {}).message, req.user.username); } catch (e) { return res.status(502).json({ ok: false, error: 'Zabbix 确认失败: ' + e.message }); } }
  ds.cacheClear();
  auth.logAction(req, 'alarm.ack', id, (req.body || {}).message || '');
  res.json({ ok: true });
}));

router.post('/alarms/:id/close', auth.requirePerm('alarm'), R(async (req, res) => {
  const id = req.params.id;
  const curAlarm = await db.alarmsFind(id);
  if (curAlarm) await db.alarmsUpdate(id, { status: 'closed', closedBy: req.user.username, closedAt: new Date().toISOString() });
  else await db.alarmsCreate({ id, eventid: id, source: 'manual', severity: 'information', host: (req.body || {}).host || '-', title: '已关闭', status: 'closed', clock: store.nowSec() });
  ds.cacheClear();
  auth.logAction(req, 'alarm.close', id, '');
  res.json({ ok: true });
}));

/* 手动创建一个本地告警（也可被巡检脚本调用） */
router.post('/alarms', auth.authRequired, R(async (req, res) => {
  const b = req.body || {};
  const a = {
    id: store.uid('a_'), eventid: store.uid('e_'), source: b.source || 'manual',
    severity: b.severity || 'warning', host: b.host || '-', title: b.title || '手动告警',
    message: b.message || '', status: 'problem', clock: store.nowSec(), acknowledged: false
  };
  await db.alarmsCreate(a); ds.cacheClear();
  auth.logAction(req, 'alarm.create', a.host, a.title);
  notify.send(a).catch(() => { });
  res.json({ ok: true, alarm: a });
}));

/* ========================= 排障工作台 · 告警→根因闭环 ========================= */
router.get('/troubleshoot/alarms', auth.authRequired, R(async (req, res) => {
  const { severity = '', host = '', keyword = '' } = req.query;
  const list = await troubleshoot.listAlarms({ severity, host, keyword, onlyActive: true });
  const stats = { disaster: 0, high: 0, average: 0, warning: 0, information: 0 };
  list.forEach(a => { if (stats[a.severity] != null) stats[a.severity]++; });
  res.json({ ok: true, rows: list, total: list.length, stats });
}));

router.post('/troubleshoot/diagnose', auth.requirePerm('scan'), R(async (req, res) => {
  const b = req.body || {};
  const alarm = b.alarm || b;
  if (!alarm || !alarm.host) return res.status(400).json({ ok: false, error: '缺少告警信息（需传 alarm.host 等字段）' });
  const d = await troubleshoot.diagnose(alarm);
  auth.logAction(req, 'troubleshoot.diagnose', alarm.host, alarm.title || '');
  res.json(Object.assign({ ok: true }, d));
}));

/* ========================= 深度排障工具（#71） ========================= */
/* 端口错包钻取：从 datasource(SNMP/Zabbix) 拉端口计数器并做基线差值，属只读设备数据 → view */
router.post('/deep/port-error', auth.requirePerm('view'), R(async (req, res) => {
  const b = req.body || {};
  if (!b.host || !b.port) return res.status(400).json({ ok: false, error: '请指定 host 与 port' });
  const d = await deepTools.portErrorDrilldown(b.host, b.port);
  auth.logAction(req, 'deep.port-error', b.host, `${b.port} 健康=${d.health != null ? d.health : '-'}`);
  res.json(Object.assign({ ok: true }, d));
}));

/* 端口错包基线：记录当前计数器快照，供后续差值对比 */
router.post('/deep/port-error/baseline', auth.requirePerm('view'), R(async (req, res) => {
  const b = req.body || {};
  if (!b.host || !b.port) return res.status(400).json({ ok: false, error: '请指定 host 与 port' });
  const d = await deepTools.portErrorBaseline(b.host, b.port);
  auth.logAction(req, 'deep.port-error.baseline', b.host, b.port);
  res.json(Object.assign({ ok: true }, d));
}));

/* MTR 深度分析：主动逐跳探测 → scan */
router.post('/deep/mtr', auth.requirePerm('scan'), R(async (req, res) => {
  const b = req.body || {};
  if (!b.target) return res.status(400).json({ ok: false, error: '请指定 target' });
  const d = await deepTools.mtr(b.target, { maxHops: Number(b.maxHops) || 20, rounds: Number(b.rounds) || 3 });
  auth.logAction(req, 'deep.mtr', b.target, `hops=${d.hopCount || 0} health=${(d.diagnosis && d.diagnosis.health) || '-'}`);
  res.json(Object.assign({ ok: true }, d));
}));

/* PCAP 关联分析：对已抓包文件按 主机/端口 过滤做性能钻取 → view（分析既有抓包） */
router.post('/deep/pcap', auth.requirePerm('view'), R(async (req, res) => {
  const b = req.body || {};
  const d = await deepTools.pcapCorrelate({ file: b.file, host: b.host, port: b.port });
  auth.logAction(req, 'deep.pcap', b.file || '-', `host=${b.host || '-'} port=${b.port || '-'} matched=${d.matchedSessions || 0}`);
  res.json(Object.assign({ ok: true }, d));
}));

/* ========================= 终端 · 录像 · 配置下发 ========================= */
router.get('/terminal/records', auth.requirePerm('view'), R(async (req, res) => {
  const rows = await db.recList({ limit: Number(req.query.limit || 100), host: req.query.host || '', user: req.query.user || '' });
  const u = req.user;
  const scoped = auth.permsOf(u.role).includes('*') || u.role === 'admin' ? rows : rows.filter(r => r.user === u.username);
  res.json({ ok: true, rows: scoped });
}));

router.get('/terminal/records/:id', auth.requirePerm('session.read'), R(async (req, res) => {
  const data = await db.recRead(req.params.id);
  if (!data) return res.status(404).json({ ok: false, error: '录像不存在' });
  const u = req.user;
  if (!auth.permsOf(u.role).includes('*') && data.meta.user !== u.username) return res.status(403).json({ ok: false, error: '无权查看他人会话' });
  auth.logAction(req, 'session.playback', data.meta.host, data.meta.id);
  res.json({ ok: true, ...data });
}));

router.delete('/terminal/records/:id', auth.requirePerm('session.read'), R(async (req, res) => {
  const d = await db.recRead(req.params.id);
  if (!d) return res.status(404).json({ ok: false, error: '录像不存在' });
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可删除录像' });
  await db.recRemove(req.params.id);
  auth.logAction(req, 'session.delete', req.params.id, '');
  res.json({ ok: true });
}));

router.get('/terminal/templates', auth.requirePerm('view'), R(async (req, res) => {
  res.json({ ok: true, rows: await db.templatesList() });
}));
router.post('/terminal/templates', auth.requirePerm('deploy'), R(async (req, res) => {
  const b = req.body || {};
  const t = {
    id: store.uid('tpl_'), name: b.name || '未命名模板', vendor: b.vendor || '通用',
    category: b.category || '查询', danger: !!b.danger,
    commands: Array.isArray(b.commands) ? b.commands : String(b.commands || '').split(/\r?\n/).filter(Boolean),
    description: b.description || '', createdAt: new Date().toISOString(), creator: req.user.username
  };
  await db.templatesCreate(t);
  auth.logAction(req, 'template.create', t.name, t.commands.join(' ; '));
  res.json({ ok: true, template: t });
}));
router.put('/terminal/templates/:id', auth.requirePerm('deploy'), R(async (req, res) => {
  const patch = { ...(req.body || {}), id: req.params.id };
  if (typeof patch.commands === 'string') patch.commands = patch.commands.split(/\r?\n/).filter(Boolean);
  const t = await db.templatesUpdate(req.params.id, patch);
  if (!t) return res.status(404).json({ ok: false, error: '模板不存在' });
  auth.logAction(req, 'template.update', t.name, '');
  res.json({ ok: true, template: t });
}));
router.delete('/terminal/templates/:id', auth.requirePerm('deploy'), R(async (req, res) => {
  const t = await db.templatesFind(req.params.id);
  if (!t) return res.status(404).json({ ok: false, error: '模板不存在' });
  await db.templatesRemove(req.params.id);
  auth.logAction(req, 'template.delete', t.name, '');
  res.json({ ok: true });
}));

router.post('/terminal/deploy', auth.requirePerm('deploy'), R(async (req, res) => {
  const { hosts = [], commands = [], credentialId = '', confirmText = '', reason = '', dryRun = false } = req.body || {};
  if (!hosts.length) return res.status(400).json({ ok: false, error: '请选择目标设备' });
  if (!commands.length) return res.status(400).json({ ok: false, error: '命令不能为空' });
  if (dryRun) {
    return res.json({ ok: true, dryRun: true, preview: { hosts, commands, dangerHits: commands.map(c => term.checkDanger(c)).filter(Boolean) } });
  }
  const r = await term.deploy({
    hosts, commands, credentialId, user: req.user.username,
    ip: auth.clientIp(req), confirmText, reason
  });
  res.json({ ok: true, ...r });
}));

router.get('/terminal/deploys', auth.requirePerm('view'), R(async (req, res) => {
  const rows = (await db.speedList(200)).filter(r => r.kind === 'deploy');
  res.json({ ok: true, rows: rows.slice(0, Number(req.query.limit || 50)) });
}));

/* ====================== 会话与流量（地址表/会话/抓包） ====================== */
/** 跨设备查一个 IP / MAC 落在哪里 —— 网络排障最高频动作 */
router.get('/session/locate', auth.requirePerm('view'), R(async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (!q) return res.status(400).json({ ok: false, error: '请输入 IP 或 MAC' });
  const hosts = await allHosts();
  const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(q);
  const norm = q.toLowerCase().replace(/[:-]/g, '');
  const hits = { mac: [], arp: [], sessions: [] };
  const scanned = [];
  for (const h of hosts.slice(0, 10)) {
    const vendor = mapVendor(h.vendor, h.os);
    const cmds = netutil.TABLE_CMDS[vendor] || netutil.TABLE_CMDS.cisco;
    const out = await ds.cached(`table:${h.host}:arp`, 60, async () => {
      const cred = await pickCred(h);
      if (!cred) return { demo: true, arp: demoArp(h), mac: demoMac(h) };
      try {
        const r = await netutil.sshExec({ ...cred, secret: store.decrypt(cred.secretEnc) }, cmds.arp, { timeoutMs: 20000 });
        const r2 = await netutil.sshExec({ ...cred, secret: store.decrypt(cred.secretEnc) }, cmds.mac, { timeoutMs: 20000 });
        return { demo: false, arp: netutil.parseArp(r.out), mac: netutil.parseMacTable(r2.out) };
      } catch (e) { return { demo: true, error: e.message, arp: demoArp(h), mac: demoMac(h) }; }
    });
    scanned.push({ host: h.host, name: h.name, ip: h.ip, demo: out.demo, error: out.error || '' });
    if (isIp) {
      (out.arp || []).filter(r => r.ip === q).forEach(r => {
        hits.arp.push({ host: h.host, name: h.name, ...r });
        const m = String(r.mac || '').toLowerCase().replace(/[.:-]/g, '');
        (out.mac || []).filter(x => String(x.mac).toLowerCase().replace(/[.:-]/g, '') === m)
          .forEach(x => hits.mac.push({ host: h.host, name: h.name, ...x, ip: q }));
      });
    } else {
      (out.mac || []).filter(x => String(x.mac).toLowerCase().replace(/[.:-]/g, '') === norm)
        .forEach(x => hits.mac.push({ host: h.host, name: h.name, ...x }));
      (out.arp || []).filter(x => String(x.mac).toLowerCase().replace(/[.:-]/g, '') === norm)
        .forEach(x => hits.arp.push({ host: h.host, name: h.name, ...x }));
    }
  }
  auth.logAction(req, 'session.locate', q, `命中 ${hits.mac.length + hits.arp.length} 条`);
  res.json({ ok: true, query: q, type: isIp ? 'ip' : 'mac', hits, scanned });
}));

router.get('/session/table', auth.requirePerm('view'), R(async (req, res) => {
  const host = req.query.host;
  const kind = String(req.query.kind || 'mac');
  const hosts = await allHosts();
  const h = hosts.find(x => x.host === host) || hosts[0];
  if (!h) return res.json({ ok: true, rows: [], host: null });
  const data = await ds.cached(`table:${h.host}:${kind}`, 30, async () => {
    const cred = await pickCred(h);
    if (!cred) return kind === 'mac' ? demoMac(h) : kind === 'arp' ? demoArp(h) : demoSess(h);
    try {
      const vendor = mapVendor(h.vendor, h.os);
      const cmds = (netutil.TABLE_CMDS[vendor] || netutil.TABLE_CMDS.cisco)[kind] || [];
      const r = await netutil.sshExec({ ...cred, secret: store.decrypt(cred.secretEnc) }, cmds, { timeoutMs: 25000 });
      return kind === 'mac' ? netutil.parseMacTable(r.out) : kind === 'arp' ? netutil.parseArp(r.out) : netutil.parseSessions(r.out);
    } catch (e) {
      return (kind === 'mac' ? demoMac(h) : kind === 'arp' ? demoArp(h) : demoSess(h)).map(x => ({ ...x, _error: e.message }));
    }
  });
  const kw = String(req.query.keyword || '').toLowerCase();
  const rows = kw ? data.filter(r => Object.values(r).join(' ').toLowerCase().includes(kw)) : data;
  res.json({ ok: true, host: h.host, hostName: h.name, kind, rows, total: rows.length, demo: !(await pickCred(h)) });
}));

router.get('/session/flow', auth.requirePerm('view'), R(async (req, res) => {
  const hosts = await allHosts();
  const h = hosts.find(x => x.host === req.query.host) || hosts[0];
  if (!h) return res.json({ ok: true, rows: [] });
  const rows = await ds.cached(`flow:${h.host}`, 30, async () => {
    const cred = await pickCred(h);
    if (!cred) return demoFlow(h);
    try {
      const vendor = mapVendor(h.vendor, h.os);
      const cmds = (netutil.TABLE_CMDS[vendor] || {}).session || [];
      const r = await netutil.sshExec({ ...cred, secret: store.decrypt(cred.secretEnc) }, cmds, { timeoutMs: 25000 });
      const parsed = netutil.parseSessions(r.out);
      return parsed.length ? parsed : demoFlow(h);
    } catch { return demoFlow(h); }
  });
  const agg = new Map();
  for (const r of rows) {
    const k = `${r.src}→${r.dst}`;
    const o = agg.get(k) || { src: r.src, dst: r.dst, flows: 0, bytes: 0, ports: new Set(), proto: r.proto };
    o.flows++; o.bytes += r.bytes || 0;
    if (r.dport) o.ports.add(r.dport);
    agg.set(k, o);
  }
  const top = [...agg.values()].map(o => ({ ...o, ports: [...o.ports].slice(0, 6).join(',') }))
    .sort((a, b) => b.flows - a.flows).slice(0, 50);
  res.json({ ok: true, host: h.host, hostName: h.name, top, total: rows.length, raw: rows.slice(0, 100) });
}));

router.get('/capture/diagnose', auth.authRequired, R(async (req, res) => {
  const exe = netutil.findTshark();
  res.json({
    ok: true,
    engine: exe ? (/(dumpcap)/i.test(exe) ? 'dumpcap' : 'tshark') : null,
    path: exe || '',
    ready: !!exe,
    hint: exe ? '' : '未检测到 Wireshark/Npcap。安装 Wireshark（勾选 Npcap）后即可在本机抓包；否则可使用"设备侧抓包"向交换机/防火墙下发抓包命令。',
    interfaces: await netutil.listInterfaces(),
    localInterfaces: netutil.localInterfaces()
  });
}));

router.post('/capture/start', auth.requirePerm('capture'), R(async (req, res) => {
  const { iface, filter = '', seconds = 15, host = '', engine = 'auto' } = req.body || {};
  if (engine === 'device' || (engine === 'auto' && !netutil.findTshark() && host)) {
    const hosts = await allHosts();
    const h = hosts.find(x => x.host === host);
    const cred = h ? await pickCred(h) : null;
    const out = {
      id: store.uid('dcap_'), engine: 'device', host, iface: iface || 'any', filter, seconds,
      at: new Date().toISOString(),
      commands: buildDeviceCapture(h, iface, filter, seconds),
      output: ''
    };
    auth.logAction(req, 'capture.device', host, `${filter} ${seconds}s`);
    if (cred) {
      try {
        const r = await netutil.sshExec({ ...cred, secret: store.decrypt(cred.secretEnc) }, out.commands, { timeoutMs: (seconds + 30) * 1000, perCmdDelay: 1200 });
        out.output = r.out;
      } catch (e) { out.error = e.message; }
    } else out.output = `演示模式：将在设备 ${host} 上执行以下抓包命令（未配置真机凭据，故仅展示命令）\n` + out.commands.join('\n');
    fs.writeFileSync(path.join(store.CAP_DIR, `${out.id}.json`), JSON.stringify(out, null, 2), 'utf8');
    return res.json({ ok: true, ...out });
  }
  if (!iface) return res.status(400).json({ ok: false, error: '请选择抓包网卡' });
  const r = await netutil.localCapture({ iface, filter, seconds: Math.min(300, Math.max(3, Number(seconds) || 15)) });
  const meta = { ...r, at: new Date().toISOString(), host: 'local', filter };
  fs.writeFileSync(path.join(store.CAP_DIR, `${r.id}.json`), JSON.stringify(meta, null, 2), 'utf8');
  auth.logAction(req, 'capture.local', iface, `${filter} ${seconds}s -> ${r.file} (${r.size} bytes)`);
  res.json({ ok: true, ...meta });
}));

router.get('/capture/list', auth.requirePerm('view'), R(async (req, res) => {
  const files = fs.readdirSync(store.CAP_DIR);
  const rows = [];
  for (const f of files) {
    const full = path.join(store.CAP_DIR, f);
    if (f.endsWith('.json')) { try { rows.push({ ...JSON.parse(fs.readFileSync(full, 'utf8')), metaFile: f }); } catch { } }
    else if (f.endsWith('.pcap') || f.endsWith('.pcapng')) {
      if (!rows.find(r => r.file === f)) {
        const st = fs.statSync(full);
        rows.push({ id: f.replace(/\.[^.]+$/, ''), file: f, size: st.size, at: st.mtime.toISOString(), engine: 'local', host: 'local' });
      }
    }
  }
  rows.sort((a, b) => String(b.at).localeCompare(String(a.at)));
  res.json({ ok: true, rows: rows.slice(0, 100) });
}));

router.get('/capture/:id/download', auth.requirePerm('view'), R(async (req, res) => {
  const id = req.params.id.replace(/[^\w-]/g, '');
  const p = path.join(store.CAP_DIR, `${id}.pcap`);
  if (!fs.existsSync(p)) return res.status(404).json({ ok: false, error: '文件不存在' });
  auth.logAction(req, 'capture.download', id, '');
  res.download(p, `${id}.pcap`);
}));

/* =============================== 内网测速 =============================== */
let throughputServer = null, throughputPort = 0;
async function ensureThroughputServer() {
  const want = Number(((await db.settingsGet()).speed || {}).serverPort || 5201);
  if (throughputServer && throughputPort === want) return;
  if (throughputServer) { try { throughputServer.close(); } catch { } }
  throughputServer = netutil.createThroughputServer(want, log => {
    store.audit({ user: 'system', action: 'speed.server.recv', target: '-', detail: `${(log.bps / 1e6).toFixed(1)} Mbps ${log.mode}` });
  });
  throughputPort = want;
}

router.get('/speed/server', auth.authRequired, R(async (req, res) => {
  await ensureThroughputServer();
  const ifaces = netutil.localInterfaces().filter(i => !i.internal);
  const iperf = netutil.findIperf();
  res.json({
    ok: true,
    port: throughputPort,
    ips: ifaces,
    iperf: { available: !!iperf, path: iperf || '', hint: iperf ? '' : '未检测到 iperf3，已使用内置 TCP 吞吐引擎（精度略低但零依赖）。需要更权威的 iperf3 数据可在系统管理里指定 iperf3.exe 路径。' },
    httpPort: ((await db.settingsGet()).speed || {}).httpPort
  });
}));

/** 浏览器 HTTP 下载测速：GET /api/speed/http/download?bytes=52428800 */
router.get('/speed/http/download', auth.authRequired, R(async (req, res) => {
  const bytes = Math.min(500 * 1024 * 1024, Math.max(1024, Number(req.query.bytes || 50 * 1024 * 1024)));
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', String(bytes));
  res.setHeader('Cache-Control', 'no-store, no-transform');
  const chunk = Buffer.alloc(64 * 1024, 0x41);
  let sent = 0;
  const push = () => {
    while (sent < bytes) {
      const n = Math.min(chunk.length, bytes - sent);
      if (!res.write(n === chunk.length ? chunk : chunk.subarray(0, n))) { sent += n; res.once('drain', push); return; }
      sent += n;
    }
    res.end();
  };
  push();
}));

/** 浏览器 HTTP 上传测速：POST /api/speed/http/upload（统计字节数后即刻丢弃） */
router.post('/speed/http/upload', auth.authRequired, R(async (req, res) => {
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  // json / urlencoded 会被 body-parser 消费，无法再从流中读字节；其余类型（如 octet-stream）自行统计
  const parsed = /application\/json|application\/x-www-form-urlencoded/.test(ct);
  let n = 0;
  if (parsed) n = JSON.stringify(req.body || {}).length;
  if (!n) {
    // 二进制上传（application/octet-stream）不会被 body-parser 消费，需自行统计；带超时保护
    n = await new Promise(resolve => {
      let size = 0, done = false;
      const finish = () => { if (!done) { done = true; resolve(size); } };
      req.on('data', d => { size += d.length; });
      req.on('end', finish);
      req.on('aborted', finish);
      setTimeout(finish, 20000);
    });
  }
  res.json({ ok: true, bytes: n });
}));

/** 服务端向对端发起测速（内置引擎，零依赖） */
router.post('/speed/builtin', auth.requirePerm('speed'), R(async (req, res) => {
  const { host, port = 5201, seconds = 8, mode = 'download', parallel = 1, useIperf = false } = req.body || {};
  if (!host) return res.status(400).json({ ok: false, error: '请填写对端 IP' });
  auth.logAction(req, 'speed.builtin', `${host}:${port}`, `${mode} ${seconds}s x${parallel}`);
  if (useIperf) {
    const exe = netutil.findIperf();
    if (!exe) return res.status(400).json({ ok: false, error: '未找到 iperf3' });
    const args = mode === 'download'
      ? ['-c', host, '-p', String(port), '-t', String(seconds), '-P', String(parallel), '-f', 'm', '--json']
      : ['-c', host, '-p', String(port), '-t', String(seconds), '-P', String(parallel), '-f', 'm', '-R', '--json'];
    const r = await netutil.runIperf3(exe, args, (seconds + 30) * 1000);
    return res.json({ ok: r.bps != null, engine: 'iperf3', bps: r.bps, raw: r.out.slice(-3000), error: r.bps == null ? r.err : '' });
  }
  // 先探测对端是否在本机（自测）
  const self = netutil.localInterfaces().some(i => i.address === host);
  if (self) {
    // 自测：本机到本机，直接给出回环速率参考
    const r = await selftest(seconds);
    return res.json({ ok: true, engine: 'builtin', self: true, bps: r.bps, mode, seconds: r.seconds, note: '本机自测（回环），仅验证引擎可用性' });
  }
  const probe = await netutil.tcpConnect(host, port, 2500);
  if (!probe.ok) {
    return res.json({
      ok: false, engine: 'builtin', reachable: false,
      error: `无法连接 ${host}:${port}（${probe.error}）。请确认对端已运行测速服务：在本机执行 netops-console 的"作为测速服务端"或在目标机启动 iperf3 -s。`
    });
  }
  const r = await netutil.throughputClient(host, port, { seconds: Number(seconds), parallel: Number(parallel), mode });
  const rec = await db.speedSave({ id: store.uid('sp_'), kind: 'builtin', at: new Date().toISOString(), user: req.user.username, ...r });
  res.json({ ok: true, engine: 'builtin', ...r, recordId: rec.id });
}));

function selftest(seconds) {
  return new Promise(resolve => {
    const net = require('net');
    const port = 5301 + Math.floor(Math.random() * 200);
    const srv = net.createServer(sock => {
      let n = 0;
      sock.on('data', d => { n += d.length; });
      const t = setTimeout(() => { try { sock.end(); } catch { } }, seconds * 1000);
      sock.on('close', () => { clearTimeout(t); srv.close(); const sec = seconds; resolve({ bps: n * 8 / sec, seconds: sec }); });
    });
    srv.listen(port, '127.0.0.1', () => {
      const c = net.connect(port, '127.0.0.1', () => {
        const buf = Buffer.alloc(256 * 1024, 0x42);
        const end = Date.now() + seconds * 1000;
        const pump = () => {
          while (Date.now() < end && c.writable) {
            if (!c.write(buf)) { c.once('drain', pump); return; }
          }
          c.end();
        };
        pump();
      });
      c.on('error', () => resolve({ bps: 0, seconds }));
    });
  });
}

/** 延迟/丢包/抖动持续探测（SSE 也可以，这里用一次性批量） */
router.post('/speed/probe', auth.requirePerm('speed'), R(async (req, res) => {
  const { targets = [], count = 5, intervalMs = 300, timeoutMs = 1500 } = req.body || {};
  const list = (Array.isArray(targets) ? targets : String(targets).split(/[\s,;]+/)).filter(Boolean).slice(0, 20);
  if (!list.length) return res.status(400).json({ ok: false, error: '请填写探测目标' });
  const out = [];
  for (const t of list) {
    const r = await netutil.ping(t.split(':')[0], { count: Math.min(50, Math.max(1, count)), intervalMs, timeoutMs });
    if (t.includes(':')) {
      const [hh, pp] = t.split(':');
      const c = await netutil.tcpConnect(hh, Number(pp), timeoutMs);
      r.tcp = c;
    }
    out.push(r);
  }
  auth.logAction(req, 'speed.probe', list.join(','), `${count}x`);
  const rec = await db.speedSave({ id: store.uid('pb_'), kind: 'probe', at: new Date().toISOString(), user: req.user.username, targets: list, results: out });
  res.json({ ok: true, rows: out, recordId: rec.id });
}));

router.get('/speed/results', auth.requirePerm('view'), R(async (req, res) => {
  const rows = await db.speedList(100);
  res.json({ ok: true, rows });
}));

/* =============================== 系统管理 =============================== */
async function safeSettings() {
  const s = JSON.parse(JSON.stringify(await db.settingsGet()));
  if (s.datasource?.zabbix) s.datasource.zabbix.password = s.datasource.zabbix.password ? '******' : '';
  if (s.notify?.smtp) s.notify.smtp.pass = s.notify.smtp.pass ? '******' : '';
  if (s.ai) s.ai.apiKey = s.ai.apiKey ? '******' : '';
  return s;
}
router.get('/system/settings', auth.requirePerm('view'), R(async (req, res) => {
  res.json({ ok: true, settings: await safeSettings() });
}));
router.put('/system/settings', auth.requirePerm('*') ? auth.requirePerm('admin') : auth.requirePerm('admin'), R(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可修改系统配置' });
  const body = req.body || {};
  const cur = await db.settingsGet();
  const keep = (oldV, newV) => (newV === '******' || newV === undefined ? oldV : newV);
  if (body.datasource) {
    const z = body.datasource.zabbix || {};
    const oldZ = cur.datasource.zabbix;
    body.datasource.zabbix = { ...oldZ, ...z, password: z.password === '******' ? oldZ.password : (z.password !== undefined ? store.encrypt(z.password) : oldZ.password) };
  }
  if (body.notify?.smtp) body.notify.smtp.pass = keep(cur.notify.smtp.pass, body.notify.smtp.pass);
  if (body.ai) body.ai.apiKey = keep(cur.ai.apiKey, body.ai.apiKey);
  const next = store.deepMerge(cur, body);
  await db.settingsUpdate(next);
  ds.resetProvider(); ds.cacheClear();
  auth.logAction(req, 'settings.update', '', Object.keys(body).join(','));
  res.json({ ok: true, settings: await safeSettings() });
}));

router.get('/system/datasource/test', auth.requirePerm('view'), R(async (req, res) => {
  const p = ds.getProvider();
  try {
    const v = await p.health();
    const hosts = await p.hosts();
    await db.settingsUpdate({ datasource: { lastOkAt: new Date().toISOString(), lastError: '' } });
    auth.logAction(req, 'datasource.test', p.name, `OK ${v}`);
    res.json({ ok: true, mode: p.name, version: v, hostCount: hosts.length });
  } catch (e) {
    await db.settingsUpdate({ datasource: { lastError: e.message } });
    auth.logAction(req, 'datasource.test', p.name, e.message, 'fail');
    res.status(502).json({ ok: false, mode: p.name, error: e.message });
  }
}));

router.get('/system/users', auth.requirePerm('view'), R(async (req, res) => {
  res.json({ ok: true, rows: (await db.usersList()).map(auth.publicUser), roles: Object.entries(auth.ROLES).map(([k, v]) => ({ key: k, name: v.name })) });
}));
router.post('/system/users', auth.authRequired, R(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可创建用户' });
  try {
    const u = await auth.createUser(req.body || {});
    auth.logAction(req, 'user.create', u.username, u.role);
    res.json({ ok: true, user: auth.publicUser(u) });
  } catch (e) { res.status(400).json({ ok: false, error: e.message }); }
}));
router.put('/system/users/:id', auth.authRequired, R(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可修改用户' });
  const u = await db.usersFind(req.params.id);
  if (!u) return res.status(404).json({ ok: false, error: '用户不存在' });
  const b = req.body || {};
  const patchU = {};
  if (b.displayName !== undefined) patchU.displayName = b.displayName;
  if (b.role !== undefined && auth.ROLES[b.role]) patchU.role = b.role;
  if (b.enabled !== undefined) patchU.enabled = !!b.enabled;
  if (b.password) await auth.setPassword(u.id, b.password);
  if (Object.keys(patchU).length) await db.usersUpdate(u.id, patchU);
  auth.logAction(req, 'user.update', u.username, JSON.stringify({ ...b, password: b.password ? '******' : undefined }).slice(0, 300));
  res.json({ ok: true, user: auth.publicUser(u) });
}));
router.delete('/system/users/:id', auth.authRequired, R(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可删除用户' });
  if (req.params.id === req.user.id) return res.status(400).json({ ok: false, error: '不能删除自己' });
  const u = await db.usersFind(req.params.id);
  if (!u) return res.status(404).json({ ok: false, error: '用户不存在' });
  await db.usersRemove(req.params.id);
  auth.logAction(req, 'user.delete', u.username, '');
  res.json({ ok: true });
}));

/* ------------------------------- 凭据库 ------------------------------- */
function safeCred(c) {
  return { id: c.id, name: c.name, kind: c.kind, vendor: c.vendor, host: c.host, port: c.port, username: c.username, note: c.note, createdAt: c.createdAt, hasSecret: !!c.secretEnc, hasEnable: !!c.enableEnc };
}
router.get('/system/credentials', auth.requirePerm('view'), R(async (req, res) => {
  const rows = (await db.credentialsList()).map(c => {
    const o = safeCred(c);
    if (req.user.role === 'admin') o.secretMasked = c.secretEnc ? '******' : '';
    return o;
  });
  res.json({ ok: true, rows });
}));
router.post('/system/credentials', auth.authRequired, R(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可维护凭据库' });
  const b = req.body || {};
  if (!b.name || !b.host) return res.status(400).json({ ok: false, error: '名称与地址必填' });
  const c = {
    id: store.uid('c_'), name: b.name, kind: b.kind || 'ssh', vendor: b.vendor || '通用',
    host: b.host, port: Number(b.port || (b.kind === 'telnet' ? 23 : 22)), username: b.username || '',
    secretEnc: store.encrypt(b.secret || ''), enableEnc: b.enable ? store.encrypt(b.enable) : '',
    note: b.note || '', createdAt: new Date().toISOString(), creator: req.user.username
  };
  await db.credentialsCreate(c);
  auth.logAction(req, 'credential.create', c.name, `${c.kind} ${c.username}@${c.host}:${c.port}`);
  res.json({ ok: true, credential: safeCred(c) });
}));
router.put('/system/credentials/:id', auth.authRequired, R(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可维护凭据库' });
  const c = await db.credentialsFind(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: '凭据不存在' });
  const b = req.body || {};
  const patchC = {};
  for (const k of ['name', 'kind', 'vendor', 'host', 'note', 'username']) if (b[k] !== undefined) patchC[k] = b[k];
  if (b.port !== undefined) patchC.port = Number(b.port);
  if (b.secret) patchC.secretEnc = store.encrypt(b.secret);
  if (b.enable !== undefined) patchC.enableEnc = b.enable ? store.encrypt(b.enable) : '';
  await db.credentialsUpdate(req.params.id, patchC);
  auth.logAction(req, 'credential.update', c.name, `${c.kind} ${c.username}@${c.host}:${c.port}`);
  res.json({ ok: true, credential: safeCred(c) });
}));
router.delete('/system/credentials/:id', auth.authRequired, R(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可维护凭据库' });
  const c = await db.credentialsFind(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: '凭据不存在' });
  await db.credentialsRemove(req.params.id);
  auth.logAction(req, 'credential.delete', c.name, '');
  res.json({ ok: true });
}));
router.post('/system/credentials/:id/test', auth.authRequired, R(async (req, res) => {
  const c = await db.credentialsFind(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: '凭据不存在' });
  if (c.kind === 'snmp' || c.kind === 'zabbix') return res.json({ ok: true, note: '该类型不做连通测试' });
  const probe = await netutil.tcpConnect(c.host, c.port || 22, 3000);
  if (!probe.ok) return res.json({ ok: false, stage: 'tcp', error: `无法连接 ${c.host}:${c.port} - ${probe.error}`, ms: probe.ms });
  try {
    const conn = await netutil.sshConnect({ host: c.host, port: c.port, username: c.username, secret: store.decrypt(c.secretEnc), kind: c.kind });
    conn.end();
    auth.logAction(req, 'credential.test', c.name, 'ok');
    res.json({ ok: true, stage: 'ssh', ms: probe.ms });
  } catch (e) {
    auth.logAction(req, 'credential.test', c.name, e.message, 'fail');
    res.json({ ok: false, stage: 'ssh', error: e.message, ms: probe.ms });
  }
}));

router.get('/system/audit', auth.requirePerm('audit.read'), R(async (req, res) => {
  const rows = await db.auditRead({
    limit: Math.min(1000, Number(req.query.limit || 200)),
    user: req.query.user || '', action: req.query.action || '',
    from: req.query.from || '', to: req.query.to || ''
  });
  res.json({ ok: true, rows });
}));

router.post('/system/notify/test', auth.authRequired, R(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ ok: false, error: '仅管理员可测试推送' });
  const r = await notify.test((req.body || {}).channel);
  auth.logAction(req, 'notify.test', (req.body || {}).channel || 'all', JSON.stringify(r).slice(0, 300));
  res.json({ ok: true, ...r });
}));

router.get('/system/health', auth.authRequired, R(async (req, res) => {
  const st = await db.status();
  const dirs = { data: store.DATA_DIR, recordings: store.REC_DIR, captures: store.CAP_DIR };
  const sizes = {};
  for (const [k, d] of Object.entries(dirs)) {
    try { sizes[k] = fs.readdirSync(d).reduce((a, f) => { try { return a + fs.statSync(path.join(d, f)).size; } catch { return a; } }, 0); } catch { sizes[k] = 0; }
  }
  res.json({
    ok: true, node: process.version, platform: process.platform, uptimeSec: Math.round(process.uptime()),
    pid: process.pid, rssMB: +(process.memoryUsage().rss / 1048576).toFixed(1),
    datasource: {
      mode: ds.getProvider().name,
      lastOkAt: (db.settingsSync() || {}).datasource?.lastOkAt || null,
      lastError: (db.settingsSync() || {}).datasource?.lastError || ''
    },
    storage: st,
    counts: {
      users: (await db.usersList()).length,
      credentials: (await db.credentialsList()).length,
      templates: (await db.templatesList()).length,
      alarms: (await db.alarmsList()).length,
      flows: (await db.flowSearch({ limit: 0, offset: 0 })).total,
      tasks: (await db.taskList()).length,
      recordings: store.listRecordings({ limit: 9999 }).length
    },
    storageBytes: sizes,
    capture: { engine: netutil.findTshark() || '', ready: !!netutil.findTshark() },
    iperf: netutil.findIperf() || ''
  });
}));

/* ====================== TLS 证书管理（Web 上传） ====================== */
/* 仅管理员可操作（证书决定全站传输安全）。证书文件落在 data/ 下，
   服务启动时由 index.js 的 loadTls() 读取 —— 上传后需重启服务方能启用 HTTPS。 */
const crypto = require('crypto');

/** 读取 DER TLV 长度字段 */
function _derLen(buf, off) {
  let b = buf[off], len, start;
  if ((b & 0x80) === 0) { len = b; start = off + 1; }
  else {
    const n = b & 0x7f; len = 0; start = off + 1;
    for (let i = 0; i < n; i++) { len = (len << 8) | buf[start + i]; }
    start += n;
  }
  return { len, start };
}
/** 从证书 DER 中尽力提取 subjectAltName（DNS / IP），失败返回 [] */
function parseSan(certPem) {
  try {
    const X509Certificate = crypto.X509Certificate;
    if (!X509Certificate) return [];
    const x = new X509Certificate(certPem);
    const der = x.raw;
    const oid = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x11]); // 2.5.29.17
    const at = der.indexOf(oid);
    if (at < 0) return [];
    let p = at + oid.length;
    while (p < der.length) {
      const tag = der[p];
      if (tag === 0x04) { // OCTET STRING：包着 SAN 的 SEQUENCE
        const li = _derLen(der, p + 1);
        return _readNames(der.subarray(li.start, li.start + li.len));
      }
      const li = _derLen(der, p + 1);
      p = li.start + li.len;
    }
    return [];
  } catch { return []; }
}
function _readNames(buf) {
  const out = [];
  let p = 0;
  if (buf[0] === 0x30) { const li = _derLen(buf, 1); buf = buf.subarray(li.start, li.start + li.len); p = 0; }
  while (p < buf.length) {
    const tag = buf[p];
    const li = _derLen(buf, p + 1);
    const val = buf.subarray(li.start, li.start + li.len);
    if (tag === 0x82) out.push('DNS:' + val.toString('utf8'));
    else if (tag === 0x87) {
      if (val.length === 4) out.push('IP:' + [val[0], val[1], val[2], val[3]].join('.'));
      else if (val.length === 16) {
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(val.readUInt16BE(i).toString(16));
        out.push('IP:' + parts.join(':'));
      }
    }
    p = li.start + li.len;
  }
  return out;
}
/** 解析证书元信息（subject / SAN / 有效期），证书非法时返回 {error} */
function certInfo(certPem) {
  try {
    const X509Certificate = crypto.X509Certificate;
    const x = new X509Certificate(certPem);
    return {
      subject: x.subject,
      issuer: x.issuer,
      serial: x.serialNumber,
      fingerprint: x.fingerprint256,
      validFrom: new Date(x.validFrom).toISOString(),
      validTo: new Date(x.validTo).toISOString(),
      san: parseSan(certPem),
      daysLeft: Math.round((new Date(x.validTo) - Date.now()) / 86400000)
    };
  } catch (e) {
    return { error: '证书解析失败：' + e.message };
  }
}
/** 校验 cert/key 是否配对 */
function certKeyMatch(certPem, keyPem) {
  try {
    const X509Certificate = crypto.X509Certificate;
    const x = new X509Certificate(certPem);
    const k = crypto.createPrivateKey(keyPem);
    return x.checkPrivateKey(k);
  } catch { return false; }
}
function readPem(name) {
  const p = path.join(store.DATA_DIR, name);
  return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null;
}

router.get('/system/cert', auth.authRequired, R(async (req, res) => {
  const onDisk = fs.existsSync(path.join(store.DATA_DIR, 'cert.pem')) && fs.existsSync(path.join(store.DATA_DIR, 'key.pem'));
  const info = onDisk ? certInfo(readPem('cert.pem')) : null;
  res.json({
    ok: true,
    running: !!req.secure,            // 当前这一次的连接是否已是 HTTPS
    onDisk,                           // data/ 下是否已存在证书（重启后即生效）
    cert: onDisk ? info : null,
    chainOnDisk: fs.existsSync(path.join(store.DATA_DIR, 'chain.pem'))
  });
}));

router.post('/system/cert', auth.authRequired, auth.requirePerm('*'), multipart.rawBody(2 * 1024 * 1024), R(async (req, res) => {
  try {
    if (!req.rawBody) return res.status(400).json({ ok: false, error: '未接收到上传内容' });
    const parts = multipart.parse(req.rawBody, req.headers['content-type'] || '');
    const certPart = parts.find(p => p.name === 'cert' && p.filename) || parts.find(p => p.name === 'cert');
    const keyPart = parts.find(p => p.name === 'key' && p.filename) || parts.find(p => p.name === 'key');
    const chainPart = parts.find(p => p.name === 'chain' && p.filename) || parts.find(p => p.name === 'chain');
    if (!certPart || !keyPart) return res.status(400).json({ ok: false, error: '请同时上传「证书(cert)」与「私钥(key)」两个文件' });
    const certPem = certPart.data.toString('utf8');
    const keyPem = keyPart.data.toString('utf8');
    const info = certInfo(certPem);
    if (info.error) return res.status(400).json({ ok: false, error: info.error });
    if (!certKeyMatch(certPem, keyPem)) return res.status(400).json({ ok: false, error: '证书与私钥不匹配（不是同一对密钥）' });
    fs.writeFileSync(path.join(store.DATA_DIR, 'cert.pem'), certPem.replace(/\r\n/g, '\n'));
    fs.writeFileSync(path.join(store.DATA_DIR, 'key.pem'), keyPem.replace(/\r\n/g, '\n'));
    if (chainPart && chainPart.data && chainPart.data.length) {
      fs.writeFileSync(path.join(store.DATA_DIR, 'chain.pem'), chainPart.data.toString('utf8').replace(/\r\n/g, '\n'));
    }
    auth.logAction(req, 'system.cert', 'upload', `SAN=${info.san.join(',')} 有效期至 ${info.validTo}`);
    res.json({
      ok: true, applied: false, needRestart: true,
      cert: info,
      message: '证书已保存，请重启服务（关闭并重新运行程序）以启用 HTTPS。'
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
}));

router.delete('/system/cert', auth.authRequired, auth.requirePerm('*'), R(async (req, res) => {
  try {
    for (const f of ['cert.pem', 'key.pem', 'chain.pem']) {
      const p = path.join(store.DATA_DIR, f);
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
    auth.logAction(req, 'system.cert', 'delete', '移除证书，回退 HTTP');
    res.json({ ok: true, message: '已移除证书，重启服务后将回退为 HTTP。' });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
}));

/* ================================ AI 助手 ================================ */
async function buildContext(scope = {}) {
  const hosts = await allHosts();
  const lines = [];
  lines.push(`【纳管设备 ${hosts.length} 台】`);
  for (const h of hosts) {
    lines.push(`- ${h.name}(${h.host}) ${h.ip} ${h.vendor} ${h.model} 区域:${h.zone} 角色:${h.role} 状态:${h.status ? '在线' : '离线'} CPU:${h.cpu ?? '-'}% 内存:${h.mem ?? '-'}% 温度:${h.temp ?? '-'}℃ 健康度:${h.health}`);
  }
  try {
    const problems = await ds.getProvider().problems();
    const act = problems.filter(p => p.status !== 'resolved').slice(0, 20);
    lines.push(`\n【当前告警 ${act.length} 条】`);
    for (const p of act) lines.push(`- [${p.severity}] ${p.host} ${p.title}`);
  } catch { }
  if (scope.host) {
    try {
      const d = await ds.getProvider().ports((hosts.find(h => h.host === scope.host) || {}).hostid || scope.host);
      const ps = (d.ports || []);
      lines.push(`\n【${scope.host} 端口状态】共 ${ps.length} 口，UP ${ps.filter(p => p.operStatus === 1).length}，DOWN ${ps.filter(p => p.operStatus !== 1).length}`);
      for (const p of ps.slice(0, 60)) {
        lines.push(`- ${p.name} ${p.operStatus === 1 ? 'UP' : 'DOWN'} speed:${p.speedMbps}Mbps 入:${ds.fmtBps(p.inBps)} 出:${ds.fmtBps(p.outBps)} 错包:${(p.inErrors || 0) + (p.outErrors || 0) + (p.crcErrors || 0)}`);
      }
    } catch { }
  }
  return lines.join('\n');
}

/**
 * 流量上下文：把一份 pcap（文件/会话/最近抓包）解析为结构化文本摘要，供 AI 根因解读。
 * scopeFlow: { file } | { sessions, packets } | { recent:true }（取最新抓包文件）
 */
async function buildFlowContext(scopeFlow) {
  if (!scopeFlow) return '';
  let sessions = [], packets = 0;
  try {
    if (Array.isArray(scopeFlow.sessions)) {
      sessions = scopeFlow.sessions; packets = Number(scopeFlow.packets || 0);
    } else if (scopeFlow.file) {
      const name = String(scopeFlow.file).replace(/[^\w.\-]/g, '');
      if (!name) return '';
      const parsed = dpi.parsePcapFile(path.join(store.CAP_DIR, name), { customDefs: await customProto.asDefs() });
      if (parsed.error) return '';
      sessions = parsed.sessions; packets = parsed.packets;
    } else if (scopeFlow.recent) {
      try {
        const files = fs.readdirSync(store.CAP_DIR).filter(f => f.endsWith('.pcap')).map(f => ({ f, m: fs.statSync(path.join(store.CAP_DIR, f)).mtimeMs })).sort((a, b) => b.m - a.m);
        if (files.length) {
          const parsed = dpi.parsePcapFile(path.join(store.CAP_DIR, files[0].f), { customDefs: await customProto.asDefs() });
          if (!parsed.error) { sessions = parsed.sessions; packets = parsed.packets; }
        }
      } catch { }
    }
  } catch { return ''; }
  if (!sessions.length) return '';

  const m = dpiMetrics.computeFlowMetrics(sessions, packets);
  const totalBytes = m.totals.bytes || 1;
  const L = [];
  L.push(`【流量分析上下文（${sessions.length} 会话 / ${packets} 包）】`);
  L.push(`时间跨度：${m.span.ms} 毫秒；峰值速率：${fmtBps(m.kpi.peakBps)}`);
  L.push(`重传统计：重传率 ${m.kpi.retransRate}%（重传会话 ${m.kpi.retransSessions} 个），重传段 ${m.kpi.retransSegments} 个`);
  L.push(`握手时延（SYN→SYN/ACK）：平均 ${m.kpi.avgHandshakeMs}ms（${m.kpi.handshakeSamples} 样本）`);
  L.push(`应用响应：HTTP 平均 ${m.kpi.avgHttpRespMs}ms（${m.kpi.httpSamples} 事务）；DNS 平均 ${m.kpi.avgDnsRespMs}ms（${m.kpi.dnsSamples} 查询）`);
  L.push(`异常会话：RST ${m.kpi.rstSessions} 个、FIN 正常关闭 ${m.kpi.finSessions} 个`);
  L.push(`协议构成（Top）：` + m.byProto.slice(0, 8).map(p => `${p.proto}(${p.sessions}会话/${totalBytes ? Math.round(p.bytes / totalBytes * 100) : 0}%)`).join('、'));
  L.push(`Top Talker（按字节）：`);
  for (const t of m.topTalkers.slice(0, 6)) L.push(`- ${t.key} 流量 ${t.bytes} 字节（${t.sessions} 会话）`);
  const anomalies = [];
  for (const s of sessions) {
    const ap = s.customProto || s.appProto;
    if (s.perf.retrans > 0) anomalies.push(`${s.srcIp}:${s.srcPort}→${s.dstIp}:${s.dstPort}(${ap}) 重传 ${s.perf.retrans} 包`);
    else if (s.perf.handshakeMs >= 300) anomalies.push(`${s.srcIp}→${s.dstIp}(${ap}) 握手 ${s.perf.handshakeMs}ms 偏慢`);
    else if (s.perf.httpRespMs >= 1000) anomalies.push(`${s.srcIp}→${s.dstIp}(${ap}) HTTP 响应 ${s.perf.httpRespMs}ms 偏慢`);
    else if (s.perf.rst) anomalies.push(`${s.srcIp}:${s.srcPort}→${s.dstIp}:${s.dstPort}(${ap}) 异常重置(RST)`);
    if (anomalies.length >= 12) break;
  }
  if (anomalies.length) L.push(`异常明细（前 ${anomalies.length}）：\n  - ` + anomalies.join('\n  - '));
  else L.push('未发现明显异常会话');
  return L.join('\n');
}

function fmtBps(v) {
  v = Number(v) || 0;
  if (v >= 1e9) return (v / 1e9).toFixed(2) + ' Gbps';
  if (v >= 1e6) return (v / 1e6).toFixed(2) + ' Mbps';
  if (v >= 1e3) return (v / 1e3).toFixed(1) + ' Kbps';
  return v + ' bps';
}

/** 自动流量根因解读（不接模型时也能出结构化结论） */
function flowRootCause(m) {
  const issues = [];
  if (m.kpi.retransRate >= 2) issues.push(`整体重传率 ${m.kpi.retransRate}% 偏高，可能存在链路拥塞或丢包（重点关注重传会话）`);
  if (m.kpi.avgHandshakeMs >= 200) issues.push(`平均 TCP 握手 ${m.kpi.avgHandshakeMs}ms 偏慢，可能服务器繁忙或网络往返过大`);
  if (m.kpi.avgHttpRespMs >= 800) issues.push(`HTTP 平均响应 ${m.kpi.avgHttpRespMs}ms 偏慢，关注后端应用与数据库`);
  if (m.kpi.rstSessions > 0) issues.push(`有 ${m.kpi.rstSessions} 个会话被 RST 异常重置，可能为防火墙拦截或服务端主动断连`);
  if (m.kpi.avgDnsRespMs >= 200) issues.push(`DNS 平均响应 ${m.kpi.avgDnsRespMs}ms 偏慢，建议检查 DNS 服务器或缓存`);
  if (!issues.length) issues.push('本次流量各项指标均在正常区间，未见明显瓶颈');
  return issues.join('；');
}

router.post('/ai/chat', auth.authRequired, R(async (req, res) => {
  const { messages = [], host = '', useContext = true, flow = null } = req.body || {};
  const cfg = ((await db.settingsGet()).ai) || {};
  const q = messages.filter(m => m.role === 'user').slice(-1)[0]?.content || '';
  if (!cfg.enabled) return res.status(400).json({ ok: false, error: 'AI 助手未启用' });

  let ctx = '';
  if (useContext) {
    try { ctx = await buildContext({ host }); } catch { }
    if (flow) { try { const fc = await buildFlowContext(flow); if (fc) ctx += '\n\n' + fc; } catch { } }
  }

  if (cfg.provider === 'none' || (!cfg.baseUrl && cfg.provider !== 'ollama')) {
    // 规则引擎兜底：不接模型也能回答高频运维问题
    let answer;
    if (flow) {
      const r = await loadFlowSessions(flow);
      if (r.error) answer = '无法构建流量上下文：' + r.error;
      else {
        const m = dpiMetrics.computeFlowMetrics(r.sessions, r.packets);
        answer = '【流量根因自动解读】\n' + flowRootCause(m) + '\n\n' + (await buildFlowContext(flow) || '');
      }
    } else {
      answer = ruleEngine(q, ctx);
    }
    await db.aiAdd({ id: store.uid('ai_'), user: req.user.username, question: q, answer, at: new Date().toISOString(), provider: 'rule' });
    auth.logAction(req, 'ai.chat', flow ? 'flow-rule-engine' : 'rule-engine', q.slice(0, 200));
    return res.json({ ok: true, provider: 'rule', answer, contextUsed: !!ctx });
  }

  try {
    const base = cfg.provider === 'ollama'
      ? String(cfg.baseUrl || 'http://127.0.0.1:11434').replace(/\/+$/, '') + '/v1'
      : String(cfg.baseUrl).replace(/\/+$/, '');
    const url = base + '/chat/completions';
    const sys = cfg.systemPrompt + (ctx ? `\n\n以下是当前网络实时数据，请基于这些数据回答，不要编造设备信息：\n${ctx}` : '');
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 60000);
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(cfg.apiKey ? { Authorization: `Bearer ${store.decrypt(cfg.apiKey) || cfg.apiKey}` } : {}) },
      body: JSON.stringify({
        model: cfg.model || 'gpt-4o-mini', temperature: cfg.temperature ?? 0.2, max_tokens: cfg.maxTokens || 1024,
        messages: [{ role: 'system', content: sys }, ...messages.slice(-10)]
      }),
      signal: ctrl.signal
    });
    clearTimeout(t);
    if (!r.ok) throw new Error(`模型接口返回 ${r.status} ${(await r.text()).slice(0, 300)}`);
    const data = await r.json();
    const answer = data.choices?.[0]?.message?.content || '(空响应)';
    await db.aiAdd({ id: store.uid('ai_'), user: req.user.username, question: q, answer, at: new Date().toISOString(), provider: cfg.provider, model: cfg.model });
    auth.logAction(req, 'ai.chat', cfg.provider + '/' + cfg.model, q.slice(0, 200));
    res.json({ ok: true, provider: cfg.provider, model: cfg.model, answer, contextUsed: !!ctx, usage: data.usage });
  } catch (e) {
    res.status(502).json({ ok: false, provider: cfg.provider, error: e.message });
  }
}));

router.get('/ai/history', auth.authRequired, R(async (req, res) => {
  const rows = await db.aiList(50, req.user.role === 'admin' ? '' : req.user.username);
  res.json({ ok: true, rows });
}));

/** 规则引擎：不接大模型也能给出专家式判断，覆盖高频排障问答 */
function ruleEngine(q, ctx) {
  const s = String(q || '');
  const has = (...k) => k.some(x => s.includes(x));
  const parts = [];

  if (has('为什么', '不通', '不通了', '断了', 'down', 'DOWN', '离线', '连不上')) {
    parts.push('**端口/链路不通的排查顺序**（自下而上，逐层排除）：');
    parts.push('1. 看端口物理状态：`show interfaces status`（华为/H3C 用 `display interface brief`）——是 notconnect（对端没连/网线问题）还是 err-disabled（被保护性关闭）。');
    parts.push('2. 看错包：`show interfaces counters errors` —— FCS/CRC 错包增长说明网线、水晶头、光模块或端口硬件有问题，换线换口先试。');
    parts.push('3. 看 VLAN 与 Trunk：`show vlan brief`、`show interfaces trunk` —— 对端 trunk 是否放通该 VLAN，PVID 是否一致。');
    parts.push('4. 看生成树：`show spanning-tree interface Gi1/0/x` —— 是否被 STP 阻塞（BLK），或收到 BPDU 被 err-disable（接入了路由器/小交换机）。');
    parts.push('5. 看 MAC 学习：`show mac address-table interface Gi1/0/x` —— 学到了终端 MAC 说明二层已通，问题在三层。');
    parts.push('6. 看 ARP 与网关：`show ip arp`（设备侧）+ 本机 `arp -a` —— ARP 学不到就是二层或网关问题。');
    parts.push('7. 抓包定位：用本工具「抓包」在端口镜像口抓 15 秒，看有没有 ARP 请求但无应答。');
    parts.push('> 提示：本工具「会话与流量 → IP 定位」输入终端 IP，可一键查出该 IP 落在哪台交换机哪个端口，是最快的定位手段。');
  }
  if (has('cpu', 'CPU', '高负载', '卡')) {
    parts.push('**CPU 高的常见原因与处置**：');
    parts.push('- 广播/组播风暴：看 `show interfaces counters` 的广播速率，查环路（`show spanning-tree` 有无拓扑震荡）。');
    parts.push('- 大量 ARP 或 ICMP 泛洪：可能有环路或病毒主机。');
    parts.push('- 控制平面被刷：`show processes cpu sorted`（Cisco）/`display cpu-usage`（华为），看是哪个进程吃 CPU。');
    parts.push('- SNMP 轮询过密：把 Zabbix 的采集间隔从 30s 放宽到 60–120s。');
  }
  if (has('环路', '风暴', '震荡')) {
    parts.push('**环路判断**：端口指示灯狂闪 + CPU 高 + 多端口 MAC 表漂移（同一 MAC 在两个口来回学）。处置：启用 `spanning-tree portfast bpduguard default`，对终端口配 `bpduguard`，从根端口方向逐段拔线定位。');
  }
  if (has('告警', '怎么消', '确认')) {
    parts.push('**告警处置流程**：先在「告警管理」确认（ack）避免重复推送 → 定位根因（参考上面的排查步骤）→ 修复 → 让 Zabbix 触发项自动恢复 → 在告警里关闭。');
    parts.push('如果是误报，回 Zabbix 调整触发器表达式或阈值，本工具会在 60 秒内同步。');
  }
  if (has('测速', '带宽', '慢')) {
    parts.push('**内网慢/带宽问题**：');
    parts.push('- 先测链路吞吐：「内网测速」选 iperf3 模式，在链路两端各跑一次，看是否达到端口速率的 80% 以上。');
    parts.push('- 测质量：「延迟/丢包探测」对目标连续 ping 30 次，看抖动和丢包。抖动大但丢包少 = 链路拥塞或队列问题。');
    parts.push('- 看端口利用率：设备详情里单口利用率持续 > 70% 就是瓶颈，考虑做链路聚合（LACP）。');
  }
  if (has('配置', '怎么配', '命令', 'vlan', 'VLAN', 'trunk', 'TRUNK')) {
    parts.push('**常用配置片段**：');
    parts.push('```\n# Cisco 建 VLAN 并把端口划进去\nvlan 10\n name Office\ninterface GigabitEthernet1/0/5\n switchport mode access\n switchport access vlan 10\n spanning-tree portfast\n```');
    parts.push('```\n# 华为/H3C\nvlan 10\ninterface GigabitEthernet0/0/5\n port link-type access\n port default vlan 10          # H3C 用 port access vlan 10\n stp edged-port enable\n```');
    parts.push('> 在本工具「终端与配置下发」里可以批量下发，且全程录像，出问题能回放追溯。');
  }
  if (has('zabbix', 'Zabbix', '数据源', '接不上')) {
    parts.push('**对接 Zabbix 检查项**：① 先确认能访问 `http://10.252.28.99`（FortiClient 已连）；② 系统管理 → 数据源里账号需有 API 访问权限（超级管理员或用户角色勾选 API）；③ 点「测试连接」看返回版本号；④ 若报 `HTTP 403/401` 多为账号密码或前端地址不对（应为 Zabbix Web 地址，不含 /zabbix 之外的路径）。');
  }
  if (!parts.length) {
    parts.push('我可以基于当前纳管的设备和告警，帮你做这些事：');
    parts.push('- 判断某个端口/终端为什么不通');
    parts.push('- 分析 CPU 高、端口错包、环路风暴的原因');
    parts.push('- 生成 Cisco / 华为 / H3C 的配置命令片段');
    parts.push('- 解释某条告警该怎么处置、要不要处理');
    parts.push('- 排查 Zabbix 对接与数据为空的常见原因');
    parts.push('\n直接问，比如「SW-ACC-03 的 Gi1/0/17 为什么 down 了」「帮我写一个把 Gi1/0/5 划到 VLAN 10 的配置」。');
    parts.push('\n> 当前未接入大模型（规则引擎模式）。在「系统管理 → AI 助手」里填入 OpenAI 兼容接口或本地 Ollama 地址，即可获得自由问答能力。');
  }
  if (ctx) parts.push('\n---\n*以上判断已结合当前纳管设备的实时状态与告警。*');
  return parts.join('\n\n');
}

/* ============================== 拓扑 ============================== */
router.get('/topology', auth.authRequired, R(async (req, res) => {
  const hosts = await allHosts();
  const saved = await db.topologyGet();
  if (saved.nodes && saved.nodes.length) return res.json({ ok: true, ...saved, auto: false });
  // 自动生成：核心 - 汇聚 - 接入 三层
  const nodes = hosts.map(h => ({ id: h.host, label: h.name || h.host, type: h.role, ip: h.ip, vendor: h.vendor, model: h.model, status: h.status }));
  const links = [];
  const core = hosts.filter(h => h.role === '核心'), dist = hosts.filter(h => h.role === '汇聚'), acc = hosts.filter(h => h.role === '接入'), fw = hosts.filter(h => h.role === '防火墙');
  acc.forEach((a, i) => { const t = dist[i % Math.max(1, dist.length)] || core[0]; if (t) links.push({ source: t.host, target: a.host }); });
  dist.forEach((d, i) => { const t = core[i % Math.max(1, core.length)] || fw[0]; if (t) links.push({ source: t.host, target: d.host }); });
  core.forEach(c => { if (fw[0]) links.push({ source: fw[0].host, target: c.host }); });
  const groups = [...new Set(hosts.map(h => h.zone))];
  res.json({ ok: true, nodes, links, groups, auto: true });
}));
router.put('/topology', auth.authRequired, R(async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'ops') return res.status(403).json({ ok: false, error: '权限不足' });
  await db.topologySet(req.body || { nodes: [], links: [] });
  auth.logAction(req, 'topology.save', '', `${(req.body?.nodes || []).length} 节点`);
  res.json({ ok: true });
}));

/* ============================== 辅助 ============================== */
async function pickCred(h) {
  const c = (await db.credentialsList()).find(c => c.host === h.ip || c.host === h.host);
  return c || null;
}
function mapVendor(v, os) {
  const s = `${v} ${os}`;
  if (/华为|Huawei|VRP/i.test(s)) return 'huawei';
  if (/H3C|Comware/i.test(s)) return 'h3c';
  if (/Nexus|NX-OS/i.test(s)) return 'nxos';
  if (/Forti/i.test(s)) return 'fortinet';
  if (/Palo/i.test(s)) return 'paloalto';
  return 'cisco';
}
const _demoSeed = (h) => ds.rng(h.host + 'table');
function demoMac(h) {
  const r = _demoSeed(h);
  const out = [];
  const ep = h.host.includes('FW') ? 'ethernet1/' : h.host.includes('SW') ? 'GigabitEthernet1/0/' : 'port';
  for (let i = 1; i <= 24; i++) {
    const vip = (0x1000 + i * 7).toString(16).slice(-4), v2 = (0x2000 + i * 13).toString(16).slice(-4), v3 = (0x3000 + i * 31).toString(16).slice(-4);
    out.push({ vlan: String([10, 20, 30, 40][i % 4]), mac: `${vip}.${v2}.${v3}`, type: 'DYNAMIC', port: `${ep}${i % 48 + 1}`, ip: `10.252.28.${100 + i}` });
  }
  const known = { '10.252.28.11': '0000.0000.0001' };
  return out;
}
function demoArp(h) {
  const r = _demoSeed(h);
  const out = [];
  for (let i = 1; i <= 24; i++) {
    const vip = (0x1000 + i * 7).toString(16).slice(-4), v2 = (0x2000 + i * 13).toString(16).slice(-4), v3 = (0x3000 + i * 31).toString(16).slice(-4);
    out.push({ ip: `10.252.28.${100 + i}`, mac: `${vip}.${v2}.${v3}`, age: String((i * 3) % 240), iface: `GigabitEthernet1/0/${i % 48 + 1}` });
  }
  return out;
}
function demoSess(h) {
  const out = [];
  for (let i = 0; i < 40; i++) {
    out.push({
      src: `10.252.${20 + i % 5}.${10 + i}`, dst: `10.${(i % 3) * 40 + 10}.1.${5 + i % 20}`,
      sport: String(40000 + i * 17), dport: String([80, 443, 445, 22, 3389, 53][i % 6]),
      proto: i % 7 === 0 ? 'udp' : 'tcp', bytes: Math.round(1024 * (i + 1) * (i % 9 + 1))
    });
  }
  return out;
}
function demoFlow(h) { return demoSess(h); }
function buildDeviceCapture(h, iface, filter, seconds) {
  if (!h) return [];
  const v = mapVendor(h.vendor, h.os);
  const i = iface || 'GigabitEthernet1/0/1';
  const f = filter || 'host 10.252.28.100';
  if (v === 'huawei') return ['screen-length 0 temporary', `capture-packet interface ${i} destination file cap.pcap packet-num 2000`, `display capture-packet file cap.pcap`];
  if (v === 'h3c') return ['screen-length disable', `capture-packet interface ${i} destination file cap.pcap packet-len 96`, 'display capture-packet file cap.pcap'];
  if (v === 'fortinet') return [`diagnose sniffer packet any '${f}' 4 ${seconds} a`];
  if (v === 'paloalto') return [`debug dataplane packet-diag set filter match ip ${f}`, 'debug dataplane packet-diag set filter on', `debug dataplane packet-diag set filter off`];
  return [`monitor capture buffer CAP1 size 4096 max-size 1518`, `monitor capture point ip c1 ${i} both`, `monitor capture point associate c1 CAP1`, `monitor capture point start c1`, `monitor capture point stop c1`, `show monitor capture buffer CAP1 dump`];
}

/* ====================== 旁路持续采集任务（P1） ====================== */
router.get('/capture/tasks', auth.requirePerm('capture'), R(async (req, res) => {
  const rows = await db.taskList();
  const b = capture.capBin();
  res.json({
    ok: true,
    rows,
    env: {
      engine: b.tool || '',
      bin: b.bin || '',
      ready: !!b.bin,
      ifaces: netutil.localInterfaces().filter(i => !i.internal),
      hint: b.bin ? '' : '未检测到 tshark/dumpcap。可安装 Wireshark/Npcap 以启用本地旁路抓包；或把任务改成设备侧采集（device）。'
    }
  });
}));

router.post('/capture/tasks', auth.requirePerm('capture'), R(async (req, res) => {
  const b = req.body || {};
  if (!b.name) return res.status(400).json({ ok: false, error: '任务名称必填' });
  const row = await db.taskSave({
    name: b.name, kind: b.kind || 'pcap', iface: b.iface || '', bpf: b.bpf || '',
    pcapSize: Number(b.pcapSize || 100), retainHours: Number(b.retainHours || 72),
    intervalSec: Number(b.intervalSec || 300), seconds: Number(b.seconds || 30),
    hosts: b.hosts || '', credentialId: b.credentialId || '',
    enabled: !!b.enabled, status: 'idle', runs: 0
  });
  auth.logAction(req, 'capture.task.create', row.name, row.kind);
  res.json({ ok: true, task: row });
}));

router.put('/capture/tasks/:id', auth.requirePerm('capture'), R(async (req, res) => {
  const cur = await db.taskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  const b = req.body || {};
  const patch = {};
  for (const k of ['name', 'kind', 'iface', 'bpf', 'hosts', 'credentialId', 'status']) if (b[k] !== undefined) patch[k] = b[k];
  if (b.pcapSize !== undefined) patch.pcapSize = Number(b.pcapSize);
  if (b.retainHours !== undefined) patch.retainHours = Number(b.retainHours);
  if (b.intervalSec !== undefined) patch.intervalSec = Number(b.intervalSec);
  if (b.seconds !== undefined) patch.seconds = Number(b.seconds);
  if (b.enabled !== undefined) patch.enabled = !!b.enabled;
  const row = await db.taskSave({ ...patch, id: cur.id });
  auth.logAction(req, 'capture.task.update', cur.name, Object.keys(patch).join(','));
  res.json({ ok: true, task: row });
}));

router.delete('/capture/tasks/:id', auth.requirePerm('capture'), R(async (req, res) => {
  const cur = await db.taskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  await db.taskRemove(cur.id);
  auth.logAction(req, 'capture.task.delete', cur.name, '');
  res.json({ ok: true });
}));

router.post('/capture/tasks/:id/run', auth.requirePerm('capture'), R(async (req, res) => {
  const r = await capture.trigger(req.params.id, req.user.username);
  auth.logAction(req, 'capture.task.run', req.params.id, r.error || '');
  res.json(r);
}));

router.post('/capture/tasks/:id/toggle', auth.requirePerm('capture'), R(async (req, res) => {
  const cur = await db.taskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  const enabled = req.body?.enabled !== undefined ? !!req.body.enabled : !cur.enabled;
  const row = await db.taskSave({ id: cur.id, enabled, status: enabled ? 'idle' : 'disabled' });
  auth.logAction(req, 'capture.task.toggle', cur.name, enabled ? '启用' : '停用');
  res.json({ ok: true, task: row });
}));

/* ====================== 全流量回溯（P2 会话库） ====================== */
router.get('/flow/protocols', auth.requirePerm('view'), R(async (req, res) => {
  const byProto = new Map();
  for (const [port, [proto, tag]] of Object.entries(dpi.PORT_MAP)) {
    if (!byProto.has(proto)) byProto.set(proto, { proto, tag: tag || '', ports: [] });
    byProto.get(proto).ports.push(Number(port));
  }
  const rows = [...byProto.values()].map(x => ({ ...x, ports: x.ports.sort((a, b) => a - b) }));
  rows.sort((a, b) => a.ports[0] - b.ports[0]);
  res.json({ ok: true, rows, total: rows.length });
}));

router.get('/flow/stats', auth.requirePerm('view'), R(async (req, res) => {
  const q = req.query || {};
  const where = {};
  if (q.proto) where.proto = String(q.proto);
  if (q.ip) where.ip = String(q.ip);
  const agg = await db.flowAgg(where);
  const span = await db.flowSearch({ limit: 1, offset: 0, ...(q.ip ? { ip: String(q.ip) } : {}), ...(q.proto ? { proto: String(q.proto) } : {}) });
  const all = await db.flowSearch({ limit: 20000, ...(q.ip ? { ip: String(q.ip) } : {}), ...(q.proto ? { proto: String(q.proto) } : {}) });
  const map = new Map();
  for (const r of all.rows) {
    const p = r.appProto || r.proto || 'other';
    const e = map.get(p) || { proto: p, sessions: 0, bytes: 0, pkts: 0 };
    e.sessions++; e.bytes += Number(r.bytes || 0); e.pkts += Number(r.pkts || 0);
    map.set(p, e);
  }
  const byProto = [...map.values()].sort((a, b) => b.bytes - a.bytes);
  res.json({
    ok: true,
    total: all.total,
    span: { from: all.rows.length ? all.rows[all.rows.length - 1].startedAt : '', to: all.rows.length ? all.rows[0].startedAt : '' },
    byProto,
    topPairs: agg.slice(0, 12),
    filter: { ip: q.ip || '', proto: q.proto || '' }
  });
}));

router.get('/flow/sessions', auth.requirePerm('view'), R(async (req, res) => {
  const q = {
    from: String(req.query.from || ''), to: String(req.query.to || ''),
    ip: String(req.query.ip || ''), proto: String(req.query.proto || ''),
    taskId: String(req.query.taskId || ''), fileId: String(req.query.fileId || ''),
    limit: Number(req.query.limit || 100), offset: Number(req.query.offset || 0)
  };
  const r = await db.flowSearch(q);
  res.json({ ok: true, total: r.total, rows: r.rows, limit: q.limit, offset: q.offset });
}));

router.get('/flow/sessions/:id', auth.requirePerm('view'), R(async (req, res) => {
  const row = await db.flowById(req.params.id);
  if (!row) return res.status(404).json({ ok: false, error: '会话不存在' });
  const file = row.fileId || '';
  let fileRow = null;
  if (file) {
    try {
      const list = await db.capList({ limit: 999 });
      fileRow = list.find(x => x.fileId === file || x.path?.endsWith(file)) || null;
    } catch { }
  }
  res.json({ ok: true, session: row, file: fileRow });
}));

/** 解析一个 pcap 文件（用于回溯页直接查看，不入库存） */
router.post('/flow/parse', auth.requirePerm('capture'), R(async (req, res) => {
  const b = req.body || {};
  const name = String(b.file || '').replace(/[^\w.\-]/g, '');
  if (!name) return res.status(400).json({ ok: false, error: '请指定文件名' });
  const full = path.join(store.CAP_DIR, name);
  const parsed = dpi.parsePcapFile(full);
  if (parsed.error) return res.status(404).json({ ok: false, error: parsed.error });
  /* persist=1 时把解析出的会话直接入库（上传 pcap 归档 / 手工导入场景） */
  let inserted = 0;
  if (b.persist) {
    const rows = (parsed.sessions || []).map(s => ({
      id: store.uid('flw_'),
      startedAt: s.startedAt,
      srcIp: s.srcIp, dstIp: s.dstIp, srcPort: s.srcPort, dstPort: s.dstPort,
      proto: s.proto, appProto: s.appProto || '',
      taskId: b.taskId || '', fileId: name,
      bytes: s.bytes, pkts: s.pkts, durationMs: s.durationMs,
      hint: s.hint || {}, tags: s.tags || []
    }));
    inserted = rows.length ? await db.flowInsert(rows) : 0;
  }
  auth.logAction(req, 'flow.parse', name, `${parsed.packets} 包${inserted ? ` / 入库 ${inserted} 会话` : ''}`);
  res.json({
    ok: true, file: name, packets: parsed.packets, linkType: parsed.linkType,
    truncated: parsed.truncated, inserted,
    sessions: parsed.sessions.slice(0, Number(b.limit || 200))
  });
}));

/** 解析 pcap（文件或字节）并注入自定义协议定义后做性能钻取聚合 */
async function loadFlowSessions(b) {
  if (Array.isArray(b.sessions) && b.sessions.length) {
    return { sessions: b.sessions, packets: Number(b.packets || 0) };
  }
  if (b.file) {
    const name = String(b.file).replace(/[^\w.\-]/g, '');
    if (!name) return { error: '请指定文件名', status: 400 };
    const parsed = dpi.parsePcapFile(path.join(store.CAP_DIR, name), { customDefs: await customProto.asDefs() });
    if (parsed.error) return { error: parsed.error, status: 404 };
    return { sessions: parsed.sessions, packets: parsed.packets };
  }
  return { error: '请提供 sessions 或 file', status: 400 };
}

/** 流量性能钻取聚合：基于已解析会话（perf 字段）计算 KPI / 协议报表 / Top Talker / 时序 */
router.post('/flow/metrics', auth.requirePerm('view'), R(async (req, res) => {
  const b = req.body || {};
  const r = await loadFlowSessions(b);
  if (r.error) return res.status(r.status || 400).json({ ok: false, error: r.error });
  const m = dpiMetrics.computeFlowMetrics(r.sessions, r.packets);
  auth.logAction(req, 'flow.metrics', b.file ? String(b.file) : `${r.sessions.length}会话`, `重传率=${m.kpi.retransRate}% HTTP=${m.kpi.avgHttpRespMs}ms DNS=${m.kpi.avgDnsRespMs}ms`);
  res.json(m);
}));

/* ====================== 自定义协议（业务协议） ====================== */
router.get('/custom-protocols', auth.requirePerm('view'), R(async (req, res) => {
  res.json({ ok: true, list: await customProto.list() });
}));

router.post('/custom-protocols', auth.requirePerm('admin'), R(async (req, res) => {
  try {
    const created = await customProto.create(req.body || {});
    auth.logAction(req, 'custom-protocol.create', created.name, created.enabled ? '启用' : '停用');
    res.json({ ok: true, item: created });
  } catch (e) {
    res.status(e.status || 500).json({ ok: false, error: e.message });
  }
}));

router.put('/custom-protocols/:id', auth.requirePerm('admin'), R(async (req, res) => {
  try {
    const updated = await customProto.update(req.params.id, req.body || {});
    auth.logAction(req, 'custom-protocol.update', updated.name, updated.enabled ? '启用' : '停用');
    res.json({ ok: true, item: updated });
  } catch (e) {
    res.status(e.status || 500).json({ ok: false, error: e.message });
  }
}));

router.delete('/custom-protocols/:id', auth.requirePerm('admin'), R(async (req, res) => {
  try {
    const r = await customProto.remove(req.params.id);
    auth.logAction(req, 'custom-protocol.delete', req.params.id, '');
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(e.status || 500).json({ ok: false, error: e.message });
  }
}));

/* ====================== PCAP 上传回溯（multipart） ====================== */
router.post('/flow/upload', auth.requirePerm('view'), multipart.rawBody(), R(async (req, res) => {
  try {
    if (!req.rawBody) return res.status(400).json({ ok: false, error: '未接收到上传内容' });
    const parts = multipart.parse(req.rawBody, req.headers['content-type'] || '');
    const filePart = parts.find(p => p.filename);
    if (!filePart) return res.status(400).json({ ok: false, error: '请上传 PCAP 文件（字段名 file）' });
    // 校验是否为 libpcap magic（宽松：仅拦截明显非 pcap 的二进制）
    const b = filePart.data;
    const magic = b.length >= 4 ? b.readUInt32LE(0) : 0;
    const isPcap = [0xa1b2c3d4, 0xd4c3b2a1, 0xa1b2cd34, 0x34cdb2a1].includes(magic);
    if (!isPcap) return res.status(400).json({ ok: false, error: '文件不是标准 pcap 格式（libpcap magic 不匹配）' });
    const safeName = (filePart.filename || 'upload.pcap').replace(/[^\w.\-]/g, '').replace(/\.pcapng$/i, '.pcap');
    const fname = (store.uid('cap_') + '_' + safeName).slice(0, 120);
    const full = path.join(store.CAP_DIR, fname);
    fs.writeFileSync(full, b);
    const parsed = dpi.parsePcapFile(full, { customDefs: await customProto.asDefs() });
    if (parsed.error) { fs.unlinkSync(full); return res.status(400).json({ ok: false, error: parsed.error }); }
    const m = dpiMetrics.computeFlowMetrics(parsed.sessions, parsed.packets);
    auth.logAction(req, 'flow.upload', fname, `${parsed.sessions.length}会话/${parsed.packets}包`);
    res.json({ ok: true, file: fname, originalName: filePart.filename, sessions: parsed.sessions, packets: parsed.packets, metrics: m, truncated: !!parsed.truncated });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
}));

/* ====================== 通信关系图（相位化时序） ====================== */
router.post('/flow/graph', auth.requirePerm('view'), R(async (req, res) => {
  const r = await loadFlowSessions(req.body || {});
  if (r.error) return res.status(r.status || 400).json({ ok: false, error: r.error });
  const buckets = Number((req.body || {}).buckets) || 10;
  const g = flowGraph.buildGraph(r.sessions, { buckets });
  auth.logAction(req, 'flow.graph', `${(req.body || {}).file || r.sessions.length + '会话'}`, `${g.nodes.length}节点/${g.links.length}边/${g.buckets.length}帧`);
  res.json({ ok: true, ...g });
}));

/* ====================== 路径测量（两主机逐跳探测） ====================== */
router.post('/flow/path', auth.requirePerm('scan'), R(async (req, res) => {
  const b = req.body || {};
  const target = String(b.target || '').trim();
  if (!target) return res.status(400).json({ ok: false, error: '请提供 target（目标 IP/域名）' });
  const rounds = Math.min(5, Math.max(1, Number(b.rounds) || 3));
  const maxHops = Math.min(40, Math.max(4, Number(b.maxHops) || 30));
  try {
    const trace = require('./toolbox');
    const r = await trace.mtrTrace(target, { rounds, maxHops, timeout: 3000 });
    auth.logAction(req, 'flow.path', target, `hops=${r.hops ? r.hops.length : 0} loss=${r.summary ? r.summary.lossRate : '?'}%`);
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(502).json({ ok: false, error: '路径测量失败：' + e.message });
  }
}));

/* ====================== 网络扫描（P3） ====================== */
/** 端口参数既接受预设名（common/web/...）也接受端口串（22,80 或 1000-2000） */
function resolvePorts(v, fallback = '22,80,443,3389,445') {
  const s = String(v == null ? '' : v).trim();
  if (!s) return fallback;
  if (scanner.PORT_PRESETS[s]) return scanner.PORT_PRESETS[s].ports.join(',');
  return s;
}

router.get('/scan/presets', auth.authRequired, R(async (req, res) => {
  res.json({
    ok: true,
    presets: scanner.presets(),
    modes: [
      { key: 'tcp', label: 'TCP 握手（快）', desc: '扫常用端口判断是否可连，无需任何外部依赖，大网段首选' },
      { key: 'icmp', label: 'ICMP 探活（准而慢）', desc: '真实 ping，每个地址都要起一次探测进程，/24 网段约需 1～2 分钟' },
      { key: 'mixed', label: 'TCP + ICMP（先快后准）', desc: '先用 TCP 摸出存活，再对存活的补 ping 拿响应时延' },
      { key: 'auto', label: 'nmap（装了才可用）', desc: '本机检测到 nmap 时优先用 -sn 探测，没有则自动退回 tcp' }
    ],
    riskRules: scanner.RISK_RULES.map(r => ({ ports: r.ports, service: r.service, level: r.level, tag: r.tag, desc: r.desc })),
    levels: ['critical', 'high', 'medium', 'low', 'info'],
    maxHosts: scanner.MAX_HOSTS,
    discoverPorts: scanner.DISCOVER_PORTS
  });
}));

router.get('/scan/tasks', auth.requirePerm('scan'), R(async (req, res) => {
  const rows = await db.scanTaskList();
  res.json({ ok: true, rows, env: { maxHosts: scanner.MAX_HOSTS } });
}));

router.post('/scan/tasks', auth.requirePerm('scan'), R(async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim();
  const targets = String(b.targets || '').trim();
  if (!name) return res.status(400).json({ ok: false, error: '任务名称必填' });
  if (!targets) return res.status(400).json({ ok: false, error: '扫描目标必填，例如 10.252.28.0/24 或 192.168.1.1-50' });

  const portsText = resolvePorts(b.ports);
  if (!scanner.parsePorts(portsText).length) {
    return res.status(400).json({ ok: false, error: '端口范围不合法，示例：22,80,443 或 1000-2000' });
  }
  const row = await db.scanTaskSave({
    name, targets,
    ports: portsText,
    discoverMode: String(b.discoverMode || 'tcp'),
    concurrency: Number(b.concurrency || 60),
    timeoutMs: Number(b.timeoutMs || 1200),
    banner: b.banner !== false,
    intervalSec: Number(b.intervalSec || 3600),
    retainHours: Number(b.retainHours || 72),
    enabled: !!b.enabled,
    status: 'idle'
  });
  auth.logAction(req, 'scan.task.create', row.name, targets);
  res.json({ ok: true, task: row });
}));

router.put('/scan/tasks/:id', auth.requirePerm('scan'), R(async (req, res) => {
  const cur = await db.scanTaskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  const b = req.body || {};
  const patch = {};
  for (const k of ['name', 'targets', 'ports', 'discoverMode', 'concurrency', 'timeoutMs', 'banner', 'intervalSec', 'retainHours']) {
    if (b[k] !== undefined) patch[k] = b[k];
  }
  if (patch.ports !== undefined) {
    const portsText = resolvePorts(patch.ports, cur.ports);
    if (!scanner.parsePorts(portsText).length) {
      return res.status(400).json({ ok: false, error: '端口范围不合法，示例：22,80,443 或 1000-2000' });
    }
    patch.ports = portsText;
  }
  if (patch.banner !== undefined) patch.banner = !!patch.banner;
  const row = await db.scanTaskSave({ ...patch, id: cur.id });
  auth.logAction(req, 'scan.task.update', cur.name, Object.keys(patch).join(','));
  res.json({ ok: true, task: row });
}));

router.delete('/scan/tasks/:id', auth.requirePerm('scan'), R(async (req, res) => {
  const cur = await db.scanTaskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  await db.scanTaskRemove(cur.id);
  auth.logAction(req, 'scan.task.delete', cur.name, '');
  res.json({ ok: true });
}));

router.post('/scan/tasks/:id/run', auth.requirePerm('scan'), R(async (req, res) => {
  const task = await db.scanTaskFind(req.params.id);
  if (!task) return res.status(404).json({ ok: false, error: '任务不存在' });
  const r = await scanner.runScan(task, req.user.username);
  auth.logAction(req, 'scan.task.run', task.name, `存活 ${r.alive} / 开放端口 ${r.openPorts} / 耗时 ${r.ms}ms`);
  res.json(r);
}));

router.post('/scan/tasks/:id/toggle', auth.requirePerm('scan'), R(async (req, res) => {
  const cur = await db.scanTaskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  const enabled = req.body?.enabled !== undefined ? !!req.body.enabled : !cur.enabled;
  const row = await db.scanTaskSave({ id: cur.id, enabled, status: enabled ? 'idle' : 'disabled' });
  auth.logAction(req, 'scan.task.toggle', cur.name, enabled ? '启用' : '停用');
  res.json({ ok: true, task: row });
}));

/** 快速扫描：不建任务，扫一次即返 */
router.post('/scan/quick', auth.requirePerm('scan'), R(async (req, res) => {
  const b = req.body || {};
  const targets = String(b.targets || '').trim();
  if (!targets) return res.status(400).json({ ok: false, error: '扫描目标必填，例如 10.252.28.0/24 或 192.168.1.1-50' });
  const r = await scanner.quick(targets, {
    ports: resolvePorts(b.ports),
    discoverMode: String(b.discoverMode || 'tcp'),
    banner: b.banner !== false,
    concurrency: Number(b.concurrency || 60),
    timeoutMs: Number(b.timeoutMs || 1200)
  }, req.user.username);
  auth.logAction(req, 'scan.quick', targets, `存活 ${r.alive} / 开放端口 ${r.openPorts} / ${r.ms}ms`);
  res.json(r);
}));

router.get('/scan/runs', auth.requirePerm('view'), R(async (req, res) => {
  const limit = Math.max(1, Math.min(200, Number(req.query.limit || 30)));
  const rows = await db.scanRunList({ limit, taskId: String(req.query.taskId || '') });
  res.json({ ok: true, rows });
}));

router.get('/scan/hosts', auth.requirePerm('view'), R(async (req, res) => {
  const runId = String(req.query.runId || '');
  const limit = Math.max(1, Math.min(2000, Number(req.query.limit || 300)));
  const q = {
    runId,
    ip: String(req.query.ip || ''),
    risk: String(req.query.risk || ''),
    limit, offset: Math.max(0, Number(req.query.offset || 0))
  };
  const r = await db.scanHostSearch(q);
  res.json({ ok: true, ...r });
}));

router.get('/scan/ports', auth.requirePerm('view'), R(async (req, res) => {
  const runId = String(req.query.runId || '');
  const limit = Math.max(1, Math.min(5000, Number(req.query.limit || 500)));
  const r = await db.scanPortSearch({
    runId,
    ip: String(req.query.ip || ''),
    port: String(req.query.port || ''),
    state: String(req.query.state || ''),
    risk: String(req.query.risk || ''),
    service: String(req.query.service || ''),
    limit, offset: Math.max(0, Number(req.query.offset || 0))
  });
  res.json({ ok: true, ...r });
}));

router.get('/scan/stats', auth.requirePerm('view'), R(async (req, res) => {
  const runId = String(req.query.runId || '');
  const [stat, hosts] = await Promise.all([
    db.scanPortStats({ runId }),
    db.scanHostSearch({ runId, limit: 1 })
  ]);
  const needFix = stat.byRisk.filter(x => ['high', 'critical'].includes(x.level))
    .reduce((a, b) => a + b.count, 0);
  res.json({ ok: true, ...stat, riskPorts: needFix, hostCount: hosts.total });
}));

/** 扫描结果导出 CSV（带 BOM，Excel 直接打开不乱码） */
router.get('/scan/export', auth.requirePerm('scan'), R(async (req, res) => {
  const runId = String(req.query.runId || '');
  if (!runId) return res.status(400).json({ ok: false, error: '缺少 runId' });
  const [hosts, ports] = await Promise.all([
    db.scanHostSearch({ runId, limit: 5000 }),
    db.scanPortSearch({ runId, limit: 20000 })
  ]);
  const cell = (v) => {
    const s = String(v == null ? '' : v).replace(/"/g, '""');
    return /[",\n\r]/.test(s) ? `"${s}"` : s;
  };
  const lines = ['主机IP,主机名,开放端口数,风险等级,风险说明,开放端口'];
  for (const h of hosts.rows) {
    const ps = ports.rows.filter(p => p.ip === h.ip || p.hostIp === h.ip);
    lines.push([
      cell(h.ip), cell(h.hostname || ''), cell(h.openPorts || 0),
      cell(h.riskLevel || 'info'), cell((h.riskDescs || h.riskTags || []).join('；')),
      cell(ps.map(p => `${p.port}/${p.service || 'unknown'}`).join(' '))
    ].join(','));
  }
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="scan-${runId}.csv"`);
  res.send('\uFEFF' + lines.join('\r\n'));
}));

/* ====================== 网络诊断工具箱 /api/diag ======================
   权限口径与扫描保持一致：
     主动发包类（摄像头/IP冲突/环路/测速/DHCP）需要 scan，日志审计是只读检索 view 即可。
   这些工具会往网里发包、抓旁路包、读本机安全日志，所以一律不给 audit 角色。
   ---------------------------------------------------------------------- */

/** 诊断选项白名单：只透传工具元数据里声明过的键，避免前端随便塞东西进执行上下文 */
function diagOptions(meta, b) {
  const out = {};
  const declared = (meta.options || []);
  const keys = declared.map(o => o.key).concat('iface');
  for (const k of keys) {
    if (b[k] === undefined) continue;
    if (declared.find(d => d.key === k)?.type === 'number') out[k] = Number(b[k]);
    else out[k] = b[k];
  }
  return out;
}

router.get('/diag/tools', auth.authRequired, R(async (req, res) => {
  const cfg = (db.settingsSync() || {}).netdiag || {};
  const s = netdiag.syslogStatus();
  res.json({
    ok: true,
    tools: netdiag.TOOLS.map(t => ({
      key: t.key, name: t.name, icon: t.icon, desc: t.desc, risk: t.risk,
      needsTargets: !!t.needsTargets, options: t.options || []
    })),
    levels: netdiag.LEVEL_TEXT,
    levelOrder: netdiag.LEVEL_ORDER,
    rules: netdiag.LOG_RULES.map(r => ({ key: r.key, level: r.level, title: r.title, category: r.category, pattern: String(r.re.source) })),
    camPorts: cfg.camera?.ports || [],
    env: {
      maxHosts: netdiag.MAX_HOSTS,
      platform: process.platform,
      windows: process.platform === 'win32',
      tshark: !!netutil.findTshark(),
      syslog: { running: s.running, port: s.port, received: s.received, error: s.error || '' }
    }
  });
}));

/** 目标范围预览：只算网段不发包，让前端在跑之前先看到会扫哪些地址 */
router.get('/diag/scope', auth.authRequired, R(async (req, res) => {
  const mode = String(req.query.mode || 'local') === 'range' ? 'range' : 'local';
  const targets = String(req.query.targets || '');
  if (mode === 'range' && !targets) {
    return res.status(400).json({ ok: false, error: '指定网段模式下需要填写目标，例如 10.252.28.0/24' });
  }
  try {
    const nets = mode === 'local' ? netdiag.localNets() : [];
    const cap = Math.max(16, Math.min(netdiag.MAX_HOSTS, Number(req.query.maxHosts) || netdiag.MAX_HOSTS));
    let list = [], note = '';
    if (mode === 'local') {
      // 与 resolveScope 用同一套枚举：预览显示 0 个地址、真跑却有 254 个，界面上就对不上了
      for (const n of nets) list = list.concat(netdiag.enumerateCidr(n.cidr, cap));
      if (!nets.length) note = '未找到活动网卡（只有回环地址），请改用「指定网段」';
      else note = `将对本机所在网段进行扫描：${nets.map(n => `${n.cidr}（${n.address}，${n.prefix}位）`).join('、')}` +
        (nets.length && list.length > cap ? `，共 ${list.length} 个地址，单次上限 ${cap}` : '');
    } else {
      try {
        list = await scanner.expandTargets(targets, cap);
        note = `已展开 ${list.length} 个地址`;
      } catch (e) {
        return res.status(400).json({ ok: false, error: e.message || String(e) });
      }
    }
    res.json({ ok: true, mode, nets, targets: list, note, gateways: netdiag.defaultGateway() });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || String(e) });
  }
}));

/** 执行诊断：一次一个工具，返回问题清单与风险评分 */
router.post('/diag/run', auth.requirePerm('scan'), R(async (req, res) => {
  const b = req.body || {};
  const tool = String(b.tool || '');
  const meta = netdiag.toolMeta(tool);
  if (!meta) return res.status(400).json({ ok: false, error: `未知的诊断工具：${tool}` });
  const mode = String(b.mode || 'local') === 'range' ? 'range' : 'local';
  if (mode === 'range') {
    const targets = String(b.targets || '').trim();
    if (!targets) return res.status(400).json({ ok: false, error: '指定网段模式下需要填写目标，例如 10.252.28.0/24 或 192.168.1.1-50' });
  }
  const r = await netdiag.run(tool, {
    mode,
    targets: String(b.targets || ''),
    taskId: String(b.taskId || ''),
    maxHosts: b.maxHosts,
    ...diagOptions(meta, b)
  }, req.user.username);
  auth.logAction(req, `diag.${tool}`, String(b.targets || '本机'),
    `${r.targets || '-'} 目标 · ${r.findings.length} 条问题 · 等级 ${r.level} · ${r.ms}ms`);
  res.json(r);
}));

router.get('/diag/runs', auth.requirePerm('view'), R(async (req, res) => {
  const limit = Math.max(1, Math.min(200, Number(req.query.limit || 30)));
  const rows = await db.netdiagRunList({ limit, tool: String(req.query.tool || '') });
  res.json({ ok: true, rows });
}));

router.get('/diag/hosts', auth.requirePerm('view'), R(async (req, res) => {
  const r = await db.netdiagHostSearch({
    runId: String(req.query.runId || ''),
    tool: String(req.query.tool || ''),
    ip: String(req.query.ip || ''),
    risk: String(req.query.risk || ''),
    limit: Math.max(1, Math.min(2000, Number(req.query.limit || 300))),
    offset: Math.max(0, Number(req.query.offset || 0))
  });
  res.json({ ok: true, ...r });
}));

router.get('/diag/findings', auth.requirePerm('view'), R(async (req, res) => {
  const r = await db.netdiagFindingSearch({
    runId: String(req.query.runId || ''),
    tool: String(req.query.tool || ''),
    level: String(req.query.level || ''),
    category: String(req.query.category || ''),
    // keyword 里已包含 target 字段，传 keyword 即可按目标/标题模糊过滤
    keyword: String(req.query.target || ''),
    limit: Math.max(1, Math.min(2000, Number(req.query.limit || 300))),
    offset: Math.max(0, Number(req.query.offset || 0))
  });
  res.json({ ok: true, ...r });
}));

router.get('/diag/findings/stats', auth.requirePerm('view'), R(async (req, res) => {
  const runId = String(req.query.runId || '');
  const s = await db.netdiagFindingStats({ runId, tool: String(req.query.tool || '') });
  res.json({ ok: true, ...s });
}));

router.get('/diag/logs', auth.requirePerm('view'), R(async (req, res) => {
  const r = await db.netdiagLogSearch({
    runId: String(req.query.runId || ''),
    source: String(req.query.source || ''),
    host: String(req.query.host || ''),
    rule: String(req.query.rule || ''),
    level: String(req.query.level || ''),
    limit: Math.max(1, Math.min(2000, Number(req.query.limit || 200))),
    offset: Math.max(0, Number(req.query.offset || 0))
  });
  res.json({ ok: true, ...r });
}));

router.get('/diag/logs/stats', auth.requirePerm('view'), R(async (req, res) => {
  const days = Math.max(1, Math.min(365, Number(req.query.days || 7)));
  const s = await db.netdiagLogStats({
    runId: String(req.query.runId || ''),
    tool: String(req.query.tool || ''),
    from: new Date(Date.now() - days * 86400e3).toISOString()
  });
  res.json({ ok: true, ...s, days });
}));

/** 清空审计日志：破坏性操作，要 scan 权限；带 tool 时只清该来源 */
router.post('/diag/logs/clear', auth.requirePerm('scan'), R(async (req, res) => {
  const b = req.body || {};
  const n = await db.netdiagLogClear({ tool: String(b.tool || '') });
  auth.logAction(req, 'diag.log.clear', String(b.tool || '全部'), `清空 ${n} 条审计日志`);
  res.json({ ok: true, removed: n });
}));

/** 问题清单导出 CSV（带 BOM，Excel 直接打开不乱码） */
router.get('/diag/export', auth.requirePerm('scan'), R(async (req, res) => {
  const runId = String(req.query.runId || '');
  if (!runId) return res.status(400).json({ ok: false, error: '缺少 runId' });
  const q = {
    runId, tool: String(req.query.tool || ''), level: String(req.query.level || ''),
    limit: 5000, offset: 0
  };
  const [fs2, hs] = await Promise.all([db.netdiagFindingSearch(q), db.netdiagHostSearch({ runId, limit: 5000 })]);
  const cell = (v) => {
    const s = String(v == null ? '' : v).replace(/"/g, '""');
    return /[",\n\r]/.test(s) ? `"${s}"` : s;
  };
  const lines = ['等级,分类,目标,问题,详情,建议,发生时间'];
  for (const f of fs2.rows) {
    lines.push([
      cell(netdiag.LEVEL_TEXT[f.level] || f.level), cell(f.category), cell(f.target),
      cell(f.title), cell(f.detail), cell(f.advice), cell(f.createdAt)
    ].join(','));
  }
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="netdiag-${runId}.csv"`);
  res.send('\uFEFF' + lines.join('\r\n'));
}));

/** Syslog 接收开关：UDP 514 需管理员且常与系统 syslog 冲突，界面上要看到失败原因 */
router.get('/diag/syslog', auth.authRequired, R(async (req, res) => {
  const s = netdiag.syslogStatus();
  const cfg = (db.settingsSync() || {}).netdiag || {};
  const sc = cfg.syslog || {};
  res.json({
    ok: true,
    status: {
      running: s.running, port: s.port, received: s.received, dropped: s.dropped,
      lastAt: s.lastAt || '', error: s.error || ''
    },
    config: { enabled: !!sc.enabled, port: sc.port || 514, proto: sc.proto || 'udp', retainDays: sc.retainDays || 30 }
  });
}));

router.post('/diag/syslog', auth.requirePerm('admin'), R(async (req, res) => {
  const b = req.body || {};
  const cfg = (db.settingsSync() || {}).netdiag || {};
  const sc = Object.assign({}, cfg.syslog || {}, {
    enabled: !!b.enabled,
    port: Math.max(1, Math.min(65535, Number(b.port) || 5140)),
    proto: String(b.proto || 'udp') === 'tcp' ? 'tcp' : 'udp'
  });
  await db.settingsUpdate({ netdiag: Object.assign({}, cfg, { syslog: sc }) });
  if (sc.enabled) netdiag.startSyslog({ port: sc.port, proto: sc.proto });
  else netdiag.stopSyslog();
  auth.logAction(req, 'diag.syslog.toggle', `UDP ${sc.port}`, sc.enabled ? '启用' : '停用');
  res.json({ ok: true, status: netdiag.syslogStatus(), config: sc });
}));

/* ------------------------- 诊断任务（定时巡检） ------------------------- */

router.get('/diag/tasks', auth.requirePerm('scan'), R(async (req, res) => {
  const rows = await db.netdiagTaskList();
  res.json({ ok: true, rows, busy: Array.from(netdiag.running.keys()) });
}));

router.post('/diag/tasks', auth.requirePerm('scan'), R(async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim();
  const tool = String(b.tool || '');
  const meta = netdiag.toolMeta(tool);
  if (!name) return res.status(400).json({ ok: false, error: '任务名称必填' });
  if (!meta) return res.status(400).json({ ok: false, error: '请选择诊断工具' });
  const mode = String(b.mode || 'local') === 'range' ? 'range' : 'local';
  let targets = '';
  if (mode === 'range') {
    targets = String(b.targets || '').trim();
    if (!targets) return res.status(400).json({ ok: false, error: '指定网段模式下需要填写目标，例如 10.252.28.0/24' });
  }
  const row = await db.netdiagTaskSave({
    name, tool, mode, targets,
    options: diagOptions(meta, b),
    intervalSec: Number(b.intervalSec || 3600),
    retainHours: Number(b.retainHours || 168),
    enabled: !!b.enabled,
    status: 'idle'
  });
  auth.logAction(req, 'diag.task.create', row.name, `${meta.name} · ${targets || '本机网段'}`);
  res.json({ ok: true, task: row });
}));

router.put('/diag/tasks/:id', auth.requirePerm('scan'), R(async (req, res) => {
  const cur = await db.netdiagTaskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  const b = req.body || {};
  const patch = {};
  for (const k of ['name', 'mode', 'targets', 'intervalSec', 'retainHours', 'enabled']) {
    if (b[k] !== undefined) patch[k] = b[k];
  }
  if (patch.tool !== undefined && !netdiag.toolMeta(patch.tool)) {
    return res.status(400).json({ ok: false, error: '未知的诊断工具' });
  }
  if (patch.mode !== undefined && String(patch.mode) === 'range' && !String(patch.targets || '').trim()) {
    return res.status(400).json({ ok: false, error: '指定网段模式下需要填写目标' });
  }
  if (patch.options !== undefined && netdiag.toolMeta(cur.tool)) {
    patch.options = diagOptions(netdiag.toolMeta(cur.tool), { ...(cur.options || {}), ...patch.options });
  }
  const row = await db.netdiagTaskSave({ ...patch, id: cur.id });
  auth.logAction(req, 'diag.task.update', cur.name, Object.keys(patch).join(','));
  res.json({ ok: true, task: row });
}));

router.delete('/diag/tasks/:id', auth.requirePerm('scan'), R(async (req, res) => {
  const cur = await db.netdiagTaskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  await db.netdiagTaskRemove(cur.id);
  auth.logAction(req, 'diag.task.delete', cur.name, '');
  res.json({ ok: true });
}));

router.post('/diag/tasks/:id/run', auth.requirePerm('scan'), R(async (req, res) => {
  const task = await db.netdiagTaskFind(req.params.id);
  if (!task) return res.status(404).json({ ok: false, error: '任务不存在' });
  const r = await netdiag.runTask(task);
  auth.logAction(req, 'diag.task.run', task.name, `${r.findings?.length || 0} 条问题 · 等级 ${r.level || '-'} · ${r.ms}ms`);
  res.json({ ok: true, runId: r.runId, tool: task.tool, mode: task.mode, score: r.score, level: r.level, levelText: r.levelText, findings: r.findings, hosts: r.hosts, ms: r.ms });
}));

router.post('/diag/tasks/:id/toggle', auth.requirePerm('scan'), R(async (req, res) => {
  const cur = await db.netdiagTaskFind(req.params.id);
  if (!cur) return res.status(404).json({ ok: false, error: '任务不存在' });
  const enabled = req.body?.enabled !== undefined ? !!req.body.enabled : !cur.enabled;
  const row = await db.netdiagTaskSave({ id: cur.id, enabled, status: enabled ? 'idle' : 'disabled' });
  auth.logAction(req, 'diag.task.toggle', cur.name, enabled ? '启用' : '停用');
  res.json({ ok: true, task: row });
}));

/* ============================== 网络运维工具箱 (NetToolbox 移植) ==============================
 * 12 个跨平台工具：重定向链追踪 / HTTP 可用性 / SSL 证书 / Whois / 公网出口 /
 * Ping 详版 / MTR / DNS 诊断 / 服务与 OS 指纹 / 网卡流量 / NTP / 子网计算 / WoL。
 * 主动探测类（ping/mtr/fingerprint/wol）需要 scan 权限，其余登录即可用。
 * 所有工具函数自身已返回 { ok, ... }，路由原样下发并写入审计日志。
 */
const toolboxRoutes = [
  ['/toolbox/redirect',    'auth', 'redirect',    b => toolbox.redirectTrace(String(b.url || ''), b.opts || {}),            b => String(b.url || '')],
  ['/toolbox/httpcheck',   'auth', 'httpcheck',   b => toolbox.httpCheck(String(b.url || ''), b.opts || {}),                b => String(b.url || '')],
  ['/toolbox/sslcert',     'auth', 'sslcert',     b => toolbox.sslCert(String(b.host || ''), b.opts || {}),                b => String(b.host || '')],
  ['/toolbox/whois',       'auth', 'whois',       b => toolbox.whoisLookup(String(b.query || ''), b.opts || {}),           b => String(b.query || '')],
  ['/toolbox/publicip',    'auth', 'publicip',    () => toolbox.publicIp(),                                                  () => ''],
  ['/toolbox/ping',        'scan', 'ping',        b => toolbox.pingTest(String(b.host || ''), b.opts || {}),               b => String(b.host || '')],
  ['/toolbox/mtr',         'scan', 'mtr',         b => toolbox.mtrTrace(String(b.host || ''), b.opts || {}),              b => String(b.host || '')],
  ['/toolbox/dns',         'auth', 'dns',         b => toolbox.dnsDiag(String(b.domain || ''), b.opts || {}),             b => String(b.domain || '')],
  ['/toolbox/fingerprint', 'scan', 'fingerprint', b => toolbox.fingerprintHost(String(b.host || ''), b.opts || {}),       b => String(b.host || '')],
  ['/toolbox/ifstat',      'auth', 'ifstat',      b => toolbox.ifstat(b.opts || {}),                                       () => ''],
  ['/toolbox/ntp',         'auth', 'ntp',         b => toolbox.ntpQuery(b.opts || {}),                                     b => (Array.isArray(b.servers) ? b.servers.join(',') : (b.server || ''))],
  ['/toolbox/subnet',      'auth', 'subnet',      b => {
    if (b.mode === 'vlsm') return toolbox.subnetVlsm(String(b.cidr || ''), b.needs);
    if (b.mode === 'same') return toolbox.subnetSame(String(b.a || ''), String(b.b || ''), b.prefix);
    return toolbox.subnetAnalyze(String(b.spec || ''));
  }, b => String(b.spec || b.cidr || b.a || '')],
  ['/toolbox/wol',         'scan', 'wol',         b => toolbox.wolWake(b.macs, b.opts || {}),                              b => (Array.isArray(b.macs) ? b.macs.join(',') : String(b.macs || ''))],
];
for (const [routePath, perm, action, handler, targetFn] of toolboxRoutes) {
  const mw = perm === 'scan' ? auth.requirePerm('scan') : auth.authRequired;
  router.post(routePath, mw, R(async (req, res) => {
    const b = req.body || {};
    const r = await handler(b);
    auth.logAction(req, 'toolbox.' + action, String(targetFn(b) || ''), (r.ok ? 'OK' : '失败 ' + (r.error || '')).slice(0, 200));
    res.json(r);
  }));
}

/* 第二波工具箱能力（扫描发现 / 安全 / 无线 / 网络体检） */
const toolboxScanRoutes = [
  ['/toolbox/portscan',     'scan', 'portscan',     b => toolboxScan.portscan({ host: String(b.host || ''), ports: b.ports, timeout: b.timeout, banner: b.banner, threads: b.threads }), b => String(b.host || '')],
  ['/toolbox/discovery',    'scan', 'discovery',    b => toolboxScan.discovery({ target: String(b.target || 'auto'), methods: b.methods, timeout: b.timeout, threads: b.threads }), b => String(b.target || 'auto')],
  ['/toolbox/hostname',     'scan', 'hostname',     b => toolboxScan.hostname({ ip: String(b.ip || ''), timeout: b.timeout }), b => String(b.ip || '')],
  ['/toolbox/vendor',       'auth', 'vendor',       b => toolboxScan.vendor({ mac: String(b.mac || '') }), b => String(b.mac || '')],
  ['/toolbox/wifi',         'scan', 'wifi',         b => toolboxScan.wifi(), () => ''],
  ['/toolbox/ipconflict',   'scan', 'ipconflict',   b => toolboxScan.ipconflict({ target: String(b.target || 'auto'), timeout: b.timeout }), b => String(b.target || 'auto')],
  ['/toolbox/dhcp',         'auth', 'dhcp',         b => toolboxScan.dhcp(), () => ''],
  ['/toolbox/security',     'scan', 'security',     b => toolboxScan.security({ target: String(b.target || ''), timeout: b.timeout, ports: b.ports }), b => String(b.target || '')],
  ['/toolbox/netcheck',     'auth', 'netcheck',     b => toolboxScan.netcheck(), () => ''],
  ['/toolbox/topology',     'scan', 'topology',     b => toolboxScan.topology({ target: String(b.target || 'auto'), with_snmp: b.with_snmp }), b => String(b.target || 'auto')],
  ['/toolbox/session',      'scan', 'session',      b => toolboxScan.session({ host: String(b.host || ''), port: b.port, count: b.count, timeout: b.timeout, concurrency: b.concurrency }), b => (String(b.host || '') + ':' + (b.port || ''))],
  ['/toolbox/camera',       'scan', 'camera',       b => toolboxScan.camera({ target: String(b.target || ''), timeout: b.timeout }), b => String(b.target || '')],
];
for (const [routePath, perm, action, handler, targetFn] of toolboxScanRoutes) {
  const mw = perm === 'scan' ? auth.requirePerm('scan') : auth.authRequired;
  router.post(routePath, mw, R(async (req, res) => {
    const b = req.body || {};
    const r = await handler(b);
    auth.logAction(req, 'toolbox.' + action, String(targetFn(b) || ''), (r.ok ? 'OK' : '失败 ' + (r.error || '')).slice(0, 200));
    res.json(r);
  }));
}

/* ================================ 无线勘测 ================================ */
router.get('/wifi/interfaces', auth.authRequired, R(async (req, res) => {
  const ifaces = await wifi.getWirelessInterfaces();
  res.json({ ok: true, interfaces: ifaces });
}));

router.post('/wifi/scan', auth.authRequired, R(async (req, res) => {
  let { iface } = req.body || {};
  if (!iface) { try { const list = await wifi.getWirelessInterfaces(); iface = list[0]; } catch (e) {} }  // 未指定则用首个真实网卡
  const r = await wifi.scanWifi(iface);
  auth.logAction(req, 'wifi.scan', iface || 'auto', `${r.aps ? r.aps.length : 0} 个 BSSID`);
  res.json(r);
}));

router.post('/wifi/probe', auth.requirePerm('scan'), R(async (req, res) => {
  const { ssid, bssid, iface } = req.body || {};
  const r = await wifi.probeHidden({ ssid, bssid, iface });
  auth.logAction(req, 'wifi.probe', ssid || bssid || '', r.probed ? '已暴露' : '未发现');
  res.json(r);
}));

router.get('/wifi/samples', auth.authRequired, R(async (req, res) => {
  res.json({ ok: true, data: wifi.loadSamples() });
}));

router.post('/wifi/samples', auth.authRequired, R(async (req, res) => {
  const data = wifi.saveSamples(req.body || {});
  auth.logAction(req, 'wifi.samples.save', '', `${data.samples.length} 个测点`);
  res.json({ ok: true, data });
}));

router.delete('/wifi/samples', auth.authRequired, R(async (req, res) => {
  wifi.saveSamples({ floorImage: '', floorName: '', samples: [] });
  auth.logAction(req, 'wifi.samples.clear', '', '');
  res.json({ ok: true });
}));

router.post('/wifi/locate', auth.authRequired, R(async (req, res) => {
  const { samples } = req.body || {};
  const r = wifi.locateAp(samples);
  res.json({ ok: true, ...r });
}));

module.exports = { router, buildContext, ruleEngine };
