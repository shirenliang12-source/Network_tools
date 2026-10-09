/* =========================================================================
 * 可编辑大屏可视化引擎（后端）
 * - 多套大屏：settings.dashboards[]，settings.activeDashboard
 * - 组件模型：{ id, type, title, x, y, w, h, source, params, options }
 * - 数据源：getData(source, params) 复用 ds/db 聚合，demo 模式下模拟兜底
 * ========================================================================= */
const db = require('./db');
const ds = require('./datasource');
const store = require('./store');

/* db.settingsGet 仅在 db.init() 之后挂到 db 上；用兜底访问器避免调用顺序依赖 */
function dbx() { return (typeof db.settingsGet === 'function') ? db : db.get(); }
const settingsGet = () => dbx().settingsGet();
const settingsUpdate = (p) => dbx().settingsUpdate(p);

/* ----------------------------- 主机公开化（复用概要逻辑） ----------------------------- */
function inferRole(h) {
  const s = `${h.name} ${h.host} ${h.model}`;
  if (/FW|Firewall|防火墙|PA-\d|FortiGate|Firepower/.test(s)) return '防火墙';
  if (/CORE|核心|N9K|Nexus|95\d\d/.test(s)) return '核心';
  if (/DIST|汇聚|93\d\d/.test(s)) return '汇聚';
  if (/^SW|S\d{4}|29\d\d|92\d\d/.test(s)) return '接入';
  return '其他';
}
async function pubHost(h) {
  const inv = await db.inventoryGet(h.host).catch(() => ({}));
  return {
    hostid: h.hostid, host: h.host, name: h.name || h.host, ip: h.ip,
    status: h.status, available: h.available, error: h.error || '',
    maintenance: !!h.maintenance,
    vendor: h.vendor || inv.vendor || '', model: h.model || inv.model || '', os: h.os || '',
    serial: h.serial || '', location: h.location || inv.zone || '',
    zone: inv.zone || h.location || (h.tags && h.tags.zone) || '未分组',
    role: inv.role || (h.tags && h.tags.role) || inferRole(h),
    uptimeSec: h.uptimeSec, cpu: h.cpu, mem: h.mem, temp: h.temp,
    portCount: h.portCount || null, health: ds.healthScore(h),
    note: inv.note || '', owner: inv.owner || '', rack: inv.rack || ''
  };
}
async function allHosts() {
  return ds.cached('hosts', 25, async () => {
    const hs = await ds.getProvider().hosts();
    return Promise.all(hs.map(h => pubHost(h)));
  });
}

/* ----------------------------- 工具 ----------------------------- */
const rnd = (a, b) => a + Math.random() * (b - a);
const ri = (a, b) => Math.floor(rnd(a, b + 1));
const uid = (p) => (p || 'w_') + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

/* ----------------------------- 数据源 ----------------------------- */
async function kpiSource() {
  try {
    const hosts = await allHosts();
    const online = hosts.filter(h => h.status === 1).length;
    let pTotal = 0, pUp = 0, pDown = 0, pErr = 0;
    for (const h of hosts.slice(0, 14)) {
      try {
        const { ports } = await ds.cached('ports:' + h.host, 25, () => ds.getProvider().ports(h.host));
        pTotal += ports.length;
        pUp += ports.filter(p => p.operStatus === 1).length;
        pDown += ports.filter(p => p.operStatus !== 1).length;
        pErr += ports.reduce((a, p) => a + (p.inErrors || 0) + (p.outErrors || 0) + (p.crcErrors || 0), 0);
      } catch {}
    }
    const problems = await ds.cached('problems', 20, async () => {
      const p = await ds.getProvider().problems();
      const local = (await db.alarmsList()).filter(a => a.status !== 'closed');
      const map = new Map();
      for (const x of [...p, ...local]) if (!map.has(x.eventid || x.id)) map.set(x.eventid || x.id, x);
      return [...map.values()].sort((a, b) => (b.clock || 0) - (a.clock || 0));
    });
    const active = problems.filter(p => p.status !== 'resolved' && p.status !== 'closed');
    return {
      items: [
        { label: '纳管设备', value: hosts.length, color: '#dbe8ff' },
        { label: '在线设备', value: online, color: '#34d399' },
        { label: '离线设备', value: hosts.length - online, color: hosts.length - online ? '#f87171' : '#34d399' },
        { label: '活动告警', value: active.length, color: active.length ? '#fbbf24' : '#34d399' },
        { label: '端口总数', value: pTotal, color: '#60a5fa' },
        { label: 'UP 端口', value: pUp, color: '#34d399' },
        { label: 'DOWN 端口', value: pDown, color: pDown ? '#f87171' : '#34d399' },
        { label: '累计错包', value: pErr, color: pErr ? '#fbbf24' : '#34d399' }
      ]
    };
  } catch (e) { return simulate('kpi'); }
}

async function portKpi() {
  const r = await kpiSource().catch(() => simulate('kpi'));
  const items = (r.items || []).filter(i => ['端口总数', 'UP 端口', 'DOWN 端口', '累计错包'].includes(i.label));
  return { items, variant: 'bar' };
}

async function onlineDonut() {
  try {
    const hosts = await allHosts();
    const online = hosts.filter(h => h.status === 1).length;
    return { data: [
      { name: '在线', value: online, itemStyle: { color: '#34d399' } },
      { name: '离线', value: Math.max(0, hosts.length - online), itemStyle: { color: '#f87171' } }
    ], online, offline: hosts.length - online };
  } catch (e) { return simulate('onlineDonut'); }
}

async function resourceAvg() {
  try {
    const hosts = (await allHosts()).filter(h => h.status === 1);
    const mean = k => hosts.length ? hosts.reduce((a, h) => a + (Number(h[k]) || 0), 0) / hosts.length : 0;
    return { cpu: +mean('cpu').toFixed(1), mem: +mean('mem').toFixed(1), temp: +mean('temp').toFixed(1) };
  } catch (e) { return simulate('resourceAvg'); }
}

async function roleDist() {
  try {
    const hosts = await allHosts();
    const map = {};
    hosts.forEach(h => { map[h.role] = (map[h.role] || 0) + 1; });
    const colors = { '核心': '#22d3ee', '汇聚': '#3b82f6', '接入': '#34d399', '防火墙': '#fbbf24', '其他': '#8298bb' };
    return { items: Object.entries(map).map(([k, v]) => ({ label: k, value: v, color: colors[k] || '#8298bb' })) };
  } catch (e) { return simulate('roleDist'); }
}

async function trend(range) {
  try {
    const hosts = await allHosts();
    const mins = { '1h': 60, '6h': 360, '24h': 1440, '7d': 10080 }[range] || 1440;
    const to = store.nowSec(), from = to - mins * 60;
    const host = hosts[0] && (hosts[0].hostid || hosts[0].host);
    if (!host) return simulate('trend', { range });
    const data = await ds.getProvider().history(host, 'traffic', from, to, mins > 1000 ? 240 : 120).catch(() => []);
    if (!data || !data.length) return simulate('trend', { range });
    return { labels: data.map(p => store.fmtTime ? store.fmtTime(p.ts) : p.ts), values: data.map(p => p.value), unit: 'bps' };
  } catch (e) { return simulate('trend', { range }); }
}

async function portMatrix(host) {
  try {
    let hosts = await allHosts();
    if (host) hosts = hosts.filter(h => h.host === host || h.name === host);
    const target = hosts[0];
    if (!target) return simulate('portMatrix');
    const { ports } = await ds.cached('ports:' + target.host, 25, () => ds.getProvider().ports(target.host));
    return {
      host: target.name, hostIp: target.ip,
      ports: ports.slice(0, 96).map(p => ({
        name: p.name, operStatus: p.operStatus, inErrors: p.inErrors || 0, outErrors: p.outErrors || 0,
        crcErrors: p.crcErrors || 0, inBps: p.inBps || 0, outBps: p.outBps || 0
      }))
    };
  } catch (e) { return simulate('portMatrix'); }
}

async function alarms(params) {
  try {
    const problems = await ds.cached('problems', 20, async () => {
      const p = await ds.getProvider().problems();
      const local = (await db.alarmsList()).filter(a => a.status !== 'closed');
      const map = new Map();
      for (const x of [...p, ...local]) if (!map.has(x.eventid || x.id)) map.set(x.eventid || x.id, x);
      return [...map.values()].sort((a, b) => (b.clock || 0) - (a.clock || 0));
    });
    let list = problems.filter(p => p.status !== 'resolved' && p.status !== 'closed');
    if (params && params.severity) list = list.filter(p => p.severity === params.severity);
    const items = list.slice(0, 40).map(a => ({
      id: a.eventid || a.id, title: a.title || a.name || '告警',
      host: a.host || a.hostname || '', message: a.message || '', severity: a.severity || 'average',
      clock: a.clock || a.time || 0
    }));
    return { items, total: list.length };
  } catch (e) { return simulate('alarms'); }
}

async function topTraffic() {
  try {
    const hosts = await allHosts();
    const rows = [];
    for (const h of hosts.slice(0, 14)) {
      try {
        const { ports } = await ds.cached('ports:' + h.host, 25, () => ds.getProvider().ports(h.host));
        const total = ports.reduce((a, p) => a + (p.inBps || 0) + (p.outBps || 0), 0);
        rows.push({ name: h.name, host: h.host, total });
      } catch {}
    }
    rows.sort((a, b) => b.total - a.total);
    return { items: rows.slice(0, 10).map(r => ({ label: r.name, value: r.total, host: r.host })) };
  } catch (e) { return simulate('topTraffic'); }
}

async function deviceHealth() {
  try {
    const hosts = await allHosts();
    return { items: hosts.map(h => ({
      name: h.name, host: h.host, ip: h.ip, model: h.model,
      health: h.status ? h.health : 0, status: h.status, role: h.role
    })).sort((a, b) => a.health - b.health) };
  } catch (e) { return simulate('deviceHealth'); }
}

async function sevCountSrc() {
  try {
    const problems = await ds.cached('problems', 20, async () => {
      const p = await ds.getProvider().problems();
      const local = (await db.alarmsList()).filter(a => a.status !== 'closed');
      const map = new Map();
      for (const x of [...p, ...local]) if (!map.has(x.eventid || x.id)) map.set(x.eventid || x.id, x);
      return [...map.values()];
    });
    const c = problems.filter(p => p.status !== 'resolved' && p.status !== 'closed')
      .reduce((a, p) => (a[p.severity] = (a[p.severity] || 0) + 1, a), {});
    return { disaster: c.disaster || 0, high: c.high || 0, average: c.average || 0, info: c.information || c.info || 0 };
  } catch (e) { return simulate('sevCount'); }
}

async function topologySrc() {
  try {
    const hosts = await allHosts();
    const zones = new Set(hosts.map(h => h.zone).filter(Boolean));
    return { devices: hosts.length, zones: zones.size, online: hosts.filter(h => h.status === 1).length };
  } catch (e) { return simulate('topology'); }
}

async function trafficProto() {
  try {
    const hosts = await allHosts();
    const map = {};
    for (const h of hosts.slice(0, 8)) {
      try {
        const r = await ds.cached('traffic:' + h.host, 30, () => ds.getProvider().trafficTop(h.host, 5)).catch(() => null);
        if (r && r.length) r.forEach(t => { map[t.proto || t.app] = (map[t.proto || t.app] || 0) + (t.bytes || t.value || 0); });
      } catch {}
    }
    if (!Object.keys(map).length) return simulate('trafficProto');
    return { items: Object.entries(map).map(([k, v]) => ({ label: k, value: v })).sort((a, b) => b.value - a.value).slice(0, 8) };
  } catch (e) { return simulate('trafficProto'); }
}

/* ----------------------------- 模拟兜底（demo 模式也能出图） ----------------------------- */
function simulate(source, params) {
  switch (source) {
    case 'kpi': return { items: [
      { label: '纳管设备', value: ri(8, 40), color: '#dbe8ff' },
      { label: '在线设备', value: ri(8, 38), color: '#34d399' },
      { label: '离线设备', value: ri(0, 4), color: '#f87171' },
      { label: '活动告警', value: ri(0, 12), color: '#fbbf24' },
      { label: '端口总数', value: ri(200, 1200), color: '#60a5fa' },
      { label: 'UP 端口', value: ri(190, 1100), color: '#34d399' },
      { label: 'DOWN 端口', value: ri(0, 30), color: '#f87171' },
      { label: '累计错包', value: ri(0, 500), color: '#fbbf24' }
    ] };
    case 'onlineDonut': { const o = ri(8, 38), f = ri(0, 4); return { data: [{ name: '在线', value: o, itemStyle: { color: '#34d399' } }, { name: '离线', value: f, itemStyle: { color: '#f87171' } }], online: o, offline: f }; }
    case 'resourceAvg': return { cpu: +rnd(10, 70).toFixed(1), mem: +rnd(20, 80).toFixed(1), temp: +rnd(30, 60).toFixed(1) };
    case 'roleDist': return { items: [['核心', ri(1, 4)], ['汇聚', ri(2, 6)], ['接入', ri(4, 20)], ['防火墙', ri(1, 4)], ['其他', ri(1, 6)]].map(([label, value]) => ({ label, value, color: ({ '核心': '#22d3ee', '汇聚': '#3b82f6', '接入': '#34d399', '防火墙': '#fbbf24', '其他': '#8298bb' })[label] })) };
    case 'trend': { const n = 96; const labels = [], values = []; let t = Date.now() / 1000 - n * 900; for (let i = 0; i < n; i++) { labels.push(new Date(t * 1000).toLocaleTimeString('zh-CN', { hour12: false })); values.push(Math.round(rnd(2e8, 9e8) * (0.6 + 0.4 * Math.sin(i / 12)))); t += 900; } return { labels, values, unit: 'bps', simulated: true }; }
    case 'portMatrix': { const ports = []; for (let i = 1; i <= 48; i++) { const up = Math.random() > 0.08; ports.push({ name: 'Gi1/0/' + i, operStatus: up ? 1 : 0, inErrors: up ? ri(0, 3) : 0, outErrors: 0, crcErrors: up ? ri(0, 2) : 0, inBps: up ? ri(1e6, 8e8) : 0, outBps: up ? ri(1e6, 6e8) : 0 }); } return { host: '核心交换机-01', hostIp: '10.0.0.1', ports, simulated: true }; }
    case 'alarms': return { items: [['核心交换机 CPU 使用率过高', 'SW-CORE-01', 'high'], ['汇聚端口 Gi1/0/24 链路抖动', 'SW-DIST-03', 'average'], ['防火墙会话数接近上限', 'FW-EDGE-01', 'high'], ['接入交换机离线', 'SW-ACC-12', 'disaster']].map(([title, host, severity], i) => ({ id: 'sim' + i, title, host, message: '', severity, clock: Date.now() / 1000 - i * 600 })), total: 4, simulated: true };
    case 'topTraffic': return { items: ['SW-CORE-01', 'SW-DIST-03', 'FW-EDGE-01', 'SW-ACC-08', 'SW-ACC-12'].map(n => ({ label: n, value: ri(1e8, 9e8) })) };
    case 'deviceHealth': return { items: ['SW-CORE-01', 'SW-DIST-03', 'FW-EDGE-01', 'SW-ACC-08', 'SW-ACC-12'].map((n, i) => ({ name: n, host: '10.0.0.' + (i + 1), ip: '10.0.0.' + (i + 1), model: 'C9300', health: ri(45, 98), status: 1, role: ['核心', '汇聚', '防火墙', '接入', '接入'][i] })) };
    case 'sevCount': return { disaster: ri(0, 2), high: ri(0, 5), average: ri(0, 12), info: ri(0, 8) };
    case 'topology': return { devices: ri(8, 40), zones: ri(2, 6), online: ri(8, 38) };
    case 'trafficProto': return { items: [['TCP', ri(30, 60)], ['UDP', ri(10, 30)], ['HTTP', ri(5, 20)], ['DNS', ri(2, 10)], ['SSH', ri(1, 6)], ['ICMP', ri(1, 5)]].map(([label, value]) => ({ label, value })) };
    default: return { items: [] };
  }
}

/* ----------------------------- 数据源分发 ----------------------------- */
async function getData(source, params) {
  const p = params || {};
  switch (source) {
    case 'kpi': return kpiSource();
    case 'portKpi': return portKpi();
    case 'onlineDonut': return onlineDonut();
    case 'resourceAvg': return resourceAvg();
    case 'roleDist': return roleDist();
    case 'trend': return trend(p.range);
    case 'portMatrix': return portMatrix(p.host);
    case 'alarms': return alarms(p);
    case 'topTraffic': return topTraffic();
    case 'deviceHealth': return deviceHealth();
    case 'sevCount': return sevCountSrc();
    case 'topology': return topologySrc();
    case 'trafficProto': return trafficProto();
    default: return { error: 'unknown source: ' + source };
  }
}

/* 数据源目录（供前端组件面板挑选） */
function listSources() {
  return [
    { source: 'kpi', label: '设备与端口 KPI', types: ['kpi', 'statbar'], params: [] },
    { source: 'portKpi', label: '端口概况条', types: ['statbar'], params: [] },
    { source: 'onlineDonut', label: '设备在线率（环图）', types: ['donut'], params: [] },
    { source: 'resourceAvg', label: '平均资源占用（CPU/内存/温度）', types: ['gauges'], params: [] },
    { source: 'roleDist', label: '设备类型分布', types: ['bar', 'donut'], params: [] },
    { source: 'trend', label: '全网流量趋势（折线）', types: ['line'], params: [{ key: 'range', label: '时间范围', options: ['1h', '6h', '24h', '7d'], def: '24h' }] },
    { source: 'portMatrix', label: '端口状态矩阵', types: ['ports'], params: [{ key: 'host', label: '指定设备（留空取最忙）', def: '' }] },
    { source: 'alarms', label: '实时告警列表', types: ['list'], params: [{ key: 'severity', label: '按级别过滤', options: ['', 'disaster', 'high', 'average', 'information'], def: '' }] },
    { source: 'topTraffic', label: '设备流量排行（柱状）', types: ['bar'], params: [] },
    { source: 'deviceHealth', label: '设备健康度', types: ['list', 'table', 'progress'], params: [] },
    { source: 'sevCount', label: '告警级别计数', types: ['kpi'], params: [] },
    { source: 'topology', label: '拓扑规模统计', types: ['kpi'], params: [] },
    { source: 'trafficProto', label: '流量协议构成', types: ['bar', 'donut'], params: [] }
  ];
}

/* ----------------------------- 大屏存储 ----------------------------- */
function defaultWidgets() {
  return [
    { id: uid(), type: 'kpi', title: '设备概况', x: 0, y: 0, w: 4, h: 2, source: 'kpi', params: {}, options: {} },
    { id: uid(), type: 'donut', title: '设备运行状态', x: 0, y: 2, w: 4, h: 3, source: 'onlineDonut', params: {}, options: {} },
    { id: uid(), type: 'gauges', title: '平均资源占用', x: 0, y: 5, w: 4, h: 3, source: 'resourceAvg', params: {}, options: {} },
    { id: uid(), type: 'bar', title: '设备类型分布', x: 0, y: 8, w: 4, h: 3, source: 'roleDist', params: {}, options: {} },
    { id: uid(), type: 'statbar', title: '端口概况', x: 4, y: 0, w: 4, h: 1, source: 'portKpi', params: {}, options: {} },
    { id: uid(), type: 'line', title: '全网端口流量趋势', x: 4, y: 1, w: 4, h: 5, source: 'trend', params: { range: '24h' }, options: {} },
    { id: uid(), type: 'ports', title: '端口状态矩阵', x: 4, y: 6, w: 4, h: 5, source: 'portMatrix', params: {}, options: {} },
    { id: uid(), type: 'list', title: '实时告警', x: 8, y: 0, w: 4, h: 5, source: 'alarms', params: {}, options: {} },
    { id: uid(), type: 'bar', title: '设备流量排行', x: 8, y: 5, w: 4, h: 4, source: 'topTraffic', params: {}, options: {} },
    { id: uid(), type: 'table', title: '设备健康度', x: 8, y: 9, w: 4, h: 4, source: 'deviceHealth', params: {}, options: {} }
  ];
}

async function ensureSeed() {
  const s = await settingsGet();
  if (s.dashboards && Array.isArray(s.dashboards) && s.dashboards.length) return;
  const now = new Date().toISOString();
  const def = {
    id: 'builtin-default', name: '默认大屏', builtin: true, theme: 'default',
    refreshSec: 15, cols: 12, rowH: 76, widgets: defaultWidgets(),
    createdAt: now, updatedAt: now
  };
  await settingsUpdate({ dashboards: [def], activeDashboard: 'builtin-default' });
}

async function listDashboards() {
  await ensureSeed();
  const s = await settingsGet();
  return (s.dashboards || []).map(d => ({ id: d.id, name: d.name, builtin: !!d.builtin, theme: d.theme, updatedAt: d.updatedAt }));
}
async function getDashboard(id) {
  await ensureSeed();
  const s = await settingsGet();
  return (s.dashboards || []).find(d => d.id === id) || null;
}
async function activeDashboard() {
  await ensureSeed();
  const s = await settingsGet();
  return (s.dashboards || []).find(d => d.id === (s.activeDashboard || (s.dashboards[0] && s.dashboards[0].id))) || null;
}
async function createDashboard(name) {
  await ensureSeed();
  const s = await settingsGet();
  const now = new Date().toISOString();
  const d = {
    id: uid('db_'), name: name || ('大屏 ' + ((s.dashboards || []).length + 1)), builtin: false,
    theme: 'default', refreshSec: 15, cols: 12, rowH: 76, widgets: defaultWidgets(),
    createdAt: now, updatedAt: now
  };
  const arr = (s.dashboards || []).concat(d);
  await settingsUpdate({ dashboards: arr });
  return d;
}
async function updateDashboard(id, patch) {
  const s = await settingsGet();
  const arr = (s.dashboards || []).slice();
  const i = arr.findIndex(d => d.id === id);
  if (i < 0) return null;
  const cur = arr[i];
  const allow = ['name', 'theme', 'refreshSec', 'cols', 'rowH', 'widgets'];
  for (const k of allow) if (k in patch) cur[k] = patch[k];
  cur.updatedAt = new Date().toISOString();
  arr[i] = cur;
  await settingsUpdate({ dashboards: arr });
  return cur;
}
async function deleteDashboard(id) {
  const s = await settingsGet();
  const cur = (s.dashboards || []).find(d => d.id === id);
  if (!cur) return false;
  if (cur.builtin) return false;
  const arr = (s.dashboards || []).filter(d => d.id !== id);
  const patch = { dashboards: arr };
  if (s.activeDashboard === id) patch.activeDashboard = arr.length ? arr[0].id : null;
  await settingsUpdate(patch);
  return true;
}
async function activateDashboard(id) {
  const s = await settingsGet();
  if (!(s.dashboards || []).some(d => d.id === id)) return false;
  await settingsUpdate({ activeDashboard: id });
  return true;
}

module.exports = {
  listDashboards, getDashboard, activeDashboard, createDashboard, updateDashboard,
  deleteDashboard, activateDashboard, getData, listSources,
  SOURCES: listSources()
};
