'use strict';
/**
 * 数据源适配层
 *   DataProvider 统一接口，两种实现：
 *   - DemoProvider   内置多厂商模拟数据（设备/端口/指标/历史曲线/告警），无需 Zabbix 即可完整演示
 *   - ZabbixProvider 通过 JSON-RPC API 从 Zabbix 取主机、监控项、历史、告警
 * 切换方式：系统管理 -> 数据源配置。默认 demo，填好 Zabbix 地址账号后切 zabbix。
 */
const store = require('./store');
const db = require('./db');

/* ============================ 工具 ============================ */
// 稳定伪随机（同一 seed 结果一致，便于翻页/刷新时数据稳定）
function rng(seed) {
  let s = 0;
  for (let i = 0; i < String(seed).length; i++) s = (s * 31 + String(seed).charCodeAt(i)) >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
function human (s) {
  if (s == null) return '-';
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return `${d}d ${h}h ${m}m`;
}
const bps = n => Number(n) || 0;
function fmtBps(v) {
  v = bps(v);
  if (v >= 1e9) return (v / 1e9).toFixed(2) + ' Gbps';
  if (v >= 1e6) return (v / 1e6).toFixed(2) + ' Mbps';
  if (v >= 1e3) return (v / 1e3).toFixed(2) + ' Kbps';
  return v.toFixed(0) + ' bps';
}

/* ========================== 演示数据源 ========================== */
/** 与用户真实环境同构的设备清单（多厂商） */
const DEMO_DEVICES = [
  { host: 'SW-CORE-01', name: '核心交换机-01', vendor: 'Cisco', model: 'Nexus 93180YC-FX', ip: '10.252.28.11', zone: '核心机房A区', role: '核心', ports: 54, portPrefix: 'Ethernet1/', os: 'NX-OS 10.2(5)' },
  { host: 'SW-CORE-02', name: '核心交换机-02', vendor: 'Cisco', model: 'Nexus 93180YC-FX', ip: '10.252.28.12', zone: '核心机房A区', role: '核心', ports: 54, portPrefix: 'Ethernet1/', os: 'NX-OS 10.2(5)' },
  { host: 'SW-DIST-01', name: '汇聚交换机-01', vendor: 'Cisco', model: 'Catalyst 9500-48Y4C', ip: '10.252.28.21', zone: '核心机房B区', role: '汇聚', ports: 52, portPrefix: 'TenGigabitEthernet1/0/', os: 'IOS-XE 17.9.4' },
  { host: 'SW-DIST-02', name: '汇聚交换机-02', vendor: 'Cisco', model: 'Catalyst 9300-48P', ip: '10.252.28.22', zone: '研发楼3F弱电间', role: '汇聚', ports: 48, portPrefix: 'GigabitEthernet1/0/', os: 'IOS-XE 17.6.5' },
  { host: 'SW-ACC-01', name: '接入交换机-01', vendor: 'Cisco', model: 'Catalyst 9200L-48P-4G', ip: '10.252.28.31', zone: '研发楼1F弱电间', role: '接入', ports: 48, portPrefix: 'GigabitEthernet1/0/', os: 'IOS-XE 17.3.4' },
  { host: 'SW-ACC-02', name: '接入交换机-02', vendor: 'Cisco', model: 'Catalyst 9200L-48P-4G', ip: '10.252.28.32', zone: '研发楼2F弱电间', role: '接入', ports: 48, portPrefix: 'GigabitEthernet1/0/', os: 'IOS-XE 17.3.4' },
  { host: 'SW-ACC-03', name: '接入交换机-03', vendor: 'Cisco', model: 'Catalyst 2960X-48FPD-L', ip: '10.252.28.33', zone: '行政楼2F弱电间', role: '接入', ports: 48, portPrefix: 'GigabitEthernet1/0/', os: 'IOS 15.2(7)E3' },
  { host: 'SW-ACC-04', name: '接入交换机-04', vendor: '华为', model: 'S5735S-L24T4X-A1', ip: '10.252.28.34', zone: '车间1F弱电间', role: '接入', ports: 24, portPrefix: 'GigabitEthernet0/0/', os: 'VRP V200R021C00' },
  { host: 'SW-ACC-05', name: '接入交换机-05', vendor: 'H3C', model: 'S5560X-30C-EI', ip: '10.252.28.35', zone: '车间2F弱电间', role: '接入', ports: 28, portPrefix: 'GigabitEthernet1/0/', os: 'Comware 7.1.070' },
  { host: 'SW-ACC-06', name: '接入交换机-06', vendor: '华为', model: 'S1730S-L8T-A1', ip: '10.252.28.36', zone: '仓库1F弱电间', role: '接入', ports: 8, portPrefix: 'GigabitEthernet0/0/', os: 'VRP V200R019C10' },
  { host: 'FW-EDGE-01', name: '边界防火墙-主', vendor: 'Fortinet', model: 'FortiGate 400F', ip: '10.252.28.1', zone: '出口机房', role: '防火墙', ports: 16, portPrefix: 'port', os: 'FortiOS 7.2.8' },
  { host: 'FW-DC-01', name: '数据中心防火墙', vendor: 'Palo Alto', model: 'PA-820', ip: '10.252.28.2', zone: '核心机房A区', role: '防火墙', ports: 12, portPrefix: 'ethernet1/', os: 'PAN-OS 10.2.4' },
  { host: 'FW-INT-01', name: '内网防火墙', vendor: 'Cisco', model: 'Firepower 2110', ip: '10.252.28.3', zone: '核心机房A区', role: '防火墙', ports: 12, portPrefix: 'Ethernet1/', os: 'FPR 7.2.5' }
];

function buildPorts(dev) {
  const r = rng(dev.host);
  const ports = [];
  for (let i = 1; i <= dev.ports; i++) {
    const name = `${dev.portPrefix}${i}`;
    const uplink = i <= (dev.role === '核心' ? 8 : dev.role === '汇聚' ? 4 : 2);
    const active = uplink || r() > 0.38;
    const speed = uplink ? 10000 : (dev.vendor === 'H3C' || dev.vendor === '华为' ? 1000 : (dev.model.includes('2960X') ? 1000 : 1000));
    const util = active ? (uplink ? 0.25 + r() * 0.55 : 0.01 + r() * 0.35) : 0;
    const inBps = Math.round(speed * 1e6 * util * (0.8 + r() * 0.4));
    const outBps = Math.round(speed * 1e6 * util * (0.6 + r() * 0.5));
    ports.push({
      index: i,
      name,
      alias: uplink ? (dev.role === '接入' ? `Uplink-to-${dev.role === '接入' ? 'DIST' : 'CORE'}` : `Uplink-Trunk-${i}`) : (r() > 0.6 ? `AP-${Math.ceil(r() * 60)}` : `PC-${Math.ceil(r() * 300)}`),
      operStatus: active ? 1 : 2,
      adminStatus: 1,
      speedMbps: speed,
      duplex: 'full',
      mode: uplink ? 'Trunk' : pick(r, ['Access', 'Access', 'Access', 'Hybrid']),
      vlan: uplink ? '1,10,20,30' : String(pick(r, [10, 20, 30, 40, 99])),
      pvid: uplink ? 1 : pick(r, [10, 20, 30, 40, 99]),
      inBps, outBps,
      inPps: active ? Math.round(inBps / 8 / (600 + r() * 600)) : 0,
      outPps: active ? Math.round(outBps / 8 / (600 + r() * 600)) : 0,
      inErrors: active ? Math.round(r() * r() * 12) : 0,
      outErrors: active ? Math.round(r() * r() * 6) : 0,
      inDiscards: active ? Math.round(r() * r() * 20) : 0,
      outDiscards: active ? Math.round(r() * r() * 10) : 0,
      crcErrors: active ? Math.round(r() * r() * 4) : 0,
      poe: dev.model.match(/P|FPD/) || dev.role === '接入' ? (active ? 6500 + Math.round(r() * 9000) : 0) : null,
      util: +(util * 100).toFixed(1),
      lastChange: Math.floor(Date.now() / 1000) - Math.round(r() * 86400 * 30)
    });
  }
  return ports;
}

const _demoCache = {};
function demoDetail(host) {
  const dev = DEMO_DEVICES.find(d => d.host === host);
  if (!dev) return null;
  if (!_demoCache[host]) {
    const r = rng(host + 'meta');
    _demoCache[host] = {
      ports: buildPorts(dev),
      uptimeSec: Math.round(86400 * (20 + r() * 400) + r() * 86400),
      cpu: +(8 + r() * 40).toFixed(1),
      mem: +(35 + r() * 40).toFixed(1),
      temp: +(28 + r() * 22).toFixed(1),
      fans: Array.from({ length: dev.vendor === 'Fortinet' ? 2 : 3 }, (_, i) => ({
        name: `Fan${i + 1}`, rpm: 4200 + Math.round(rng(host + 'f' + i)() * 3000), status: rng(host + 'fs' + i)() > 0.05 ? 'normal' : 'warning'
      })),
      psus: Array.from({ length: 2 }, (_, i) => ({
        name: `PSU${i + 1}`, watts: Math.round(80 + rng(host + 'p' + i)() * 260),
        status: rng(host + 'ps' + i)() > 0.04 ? 'normal' : 'fault'
      })),
      serial: 'FOC' + Math.floor(rng(host + 'sn')() * 1e9).toString().padStart(9, '0'),
      firmware: dev.os
    };
  }
  // 每次读取注入轻微实时抖动，让页面"活"起来
  const base = _demoCache[host];
  const j = rng(host + Math.floor(Date.now() / 5000))();
  return {
    ...base,
    cpu: +(base.cpu + (j - 0.5) * 4).toFixed(1),
    mem: +(base.mem + (j - 0.5) * 2).toFixed(1),
    ports: base.ports.map(p => ({
      ...p,
      inBps: Math.round(p.inBps * (0.9 + j * 0.2)),
      outBps: Math.round(p.outBps * (0.9 + j * 0.2))
    }))
  };
}

function demoHistory(host, kind, from, to, points = 120) {
  const r = rng(host + kind);
  const base = kind === 'cpu' ? 25 : kind === 'mem' ? 55 : kind === 'temp' ? 42 : 1e9;
  const span = kind === 'traffic' ? 3e8 : kind === 'cpu' ? 22 : kind === 'mem' ? 12 : 8;
  const step = Math.max(60, Math.floor((to - from) / points));
  const out = [];
  const dayPhase = (t) => Math.sin((t % 86400) / 86400 * Math.PI * 2 - 1.2) * 0.5 + 0.5;
  for (let t = from; t <= to; t += step) {
    const wave = Math.sin(t / 3600 * 1.4 + r() * 2) * 0.35 + dayPhase(t) * 0.5 + r() * 0.3;
    const v = base + span * Math.max(0, wave) * (0.9 + r() * 0.2);
    out.push({ ts: t, value: +v.toFixed(kind === 'traffic' ? 0 : 1) });
  }
  return out;
}

function demoProblems() {
  const defs = [
    { sev: 'disaster', host: 'SW-ACC-03', title: 'GigabitEthernet1/0/17 端口 Down（非计划）', desc: '端口在 08:12:33 由 Up 变为 Down，持续 3 小时 12 分未恢复', code: 'PORT_DOWN' },
    { sev: 'high', host: 'FW-EDGE-01', title: '出口带宽利用率超过 85%', desc: 'WAN1 接口出方向连续 15 分钟利用率 > 85%', code: 'BW_HIGH' },
    { sev: 'high', host: 'SW-CORE-01', title: 'CPU 使用率超过 80%', desc: 'avgBusy5 = 83%（阈值 80%）', code: 'CPU_HIGH' },
    { sev: 'average', host: 'SW-ACC-05', title: '端口 CRC 错包增长', desc: 'GigabitEthernet1/0/9 CRC 错包 5 分钟内新增 128 个，疑似网线或水晶头接触不良', code: 'CRC' },
    { sev: 'average', host: 'FW-DC-01', title: '会话数接近上限', desc: '当前会话 51,240 / 上限 64,000', code: 'SESSION' },
    { sev: 'warning', host: 'SW-DIST-02', title: '风扇转速异常', desc: 'Fan2 转速 1280 RPM 低于正常区间', code: 'FAN' },
    { sev: 'warning', host: 'SW-ACC-04', title: '机箱温度偏高', desc: '进风温度 46℃，建议检查弱电间空调', code: 'TEMP' },
    { sev: 'information', host: 'SW-ACC-01', title: '配置文件发生变更', desc: '检测到 running-config 与上次基线不一致', code: 'CFG' }
  ];
  const now = store.nowSec();
  return defs.map((d, i) => ({
    id: 'p_' + (1000 + i),
    eventid: String(900000 + i * 137),
    source: 'zabbix',
    severity: d.sev,
    host: d.host,
    title: d.title,
    message: d.desc,
    code: d.code,
    clock: now - Math.round((i + 1) * 900 + Math.random() * 3600),
    acknowledged: i > 5,
    status: 'problem'
  }));
}


/* ========================== Zabbix 数据源 ========================== */
const ZBX_CLASS = {
  cpu: [/cpu.*util/i, /avgBusy/i, /hwEntityCpuUsage/i, /hh3cEntityExtCpuUsage/i, /system\.cpu\.util/i, /cpu_usage/i, /CPUUtil/i, /5min/i],
  mem: [/mem.*util/i, /hwEntityMemUsage/i, /hh3cEntityExtMemUsage/i, /memory.*used/i, /vm\.memory\.utilization/i, /MemUtil/i],
  temp: [/temp/i, /hwEntityTemperature/i, /entSensorValue/i, /temperature/i],
  uptime: [/uptime/i, /sysUpTime/i, /sysuptime/i],
  inOct: [/ifHCInOctets/i, /ifInOctets/i, /net\.if\.in/i, /ifInOctets/i, /InOctets/i],
  outOct: [/ifHCOutOctets/i, /ifOutOctets/i, /net\.if\.out/i, /OutOctets/i],
  inErr: [/ifInErrors/i, /ifInErrors/i],
  outErr: [/ifOutErrors/i],
  inDis: [/ifInDiscards/i],
  outDis: [/ifOutDiscards/i],
  oper: [/ifOperStatus/i, /net\.if\.status/i, /ifStatus/i],
  admin: [/ifAdminStatus/i],
  speed: [/ifHighSpeed/i, /ifSpeed/i],
  alias: [/ifAlias/i],
  ifDescr: [/ifDescr/i, /ifName/i],
  cpuModel: [/entPhysicalModelName/i],
};

class ZabbixProvider {
  constructor(cfg) { this.cfg = cfg; this.auth = null; this.authAt = 0; }
  get name() { return 'zabbix'; }

  async call(method, params = {}) {
    const cfg = ((await db.settingsGet()).datasource || {}).zabbix || {};
    const url = String(cfg.url || '').replace(/\/+$/, '') + '/api_jsonrpc.php';
    const body = {
      jsonrpc: '2.0', method, params, id: Math.floor(Math.random() * 1e6)
    };
    if (method !== 'apiinfo.version' && method !== 'user.login') body.auth = await this.token();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), cfg.timeoutMs || 15000);
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json-rpc' },
        body: JSON.stringify(body),
        signal: ctrl.signal
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      const data = await res.json();
      if (data.error) throw new Error(`Zabbix ${data.error.code}: ${data.error.data || data.error.message}`);
      return data.result;
    } finally { clearTimeout(timer); }
  }
  async token() {
    if (this.auth && Date.now() - this.authAt < 3600e3) return this.auth;
    const cfg = ((await db.settingsGet()).datasource || {}).zabbix || {};
    const t = await this.call('user.login', { user: cfg.username, password: store.decrypt(cfg.password) || cfg.password });
    this.auth = t; this.authAt = Date.now();
    return t;
  }
  async health() {
    return await this.call('apiinfo.version', {});
  }
  async hostGroups() {
    const gs = await this.call('hostgroup.get', { output: ['groupid', 'name'] });
    return gs.map(g => ({ id: g.groupid, name: g.name }));
  }
  async hosts(groupId) {
    const cfg = ((await db.settingsGet()).datasource || {}).zabbix || {};
    const selectedGroups = groupId ? [String(groupId)] : (Array.isArray(cfg.groupIds) ? cfg.groupIds.map(String).filter(Boolean) : []);
    const params = {
      output: ['hostid', 'host', 'name', 'status', 'available', 'maintenance_status'],
      selectInterfaces: ['interfaceid', 'ip', 'dns', 'port', 'type', 'available', 'error'],
      selectInventory: ['type', 'model', 'vendor', 'serialnum_a', 'location', 'os'],
      selectHostGroups: ['groupid', 'name'],
      selectTags: 'extend',
      monitored_hosts: true,
      sortfield: 'name'
    };
    if (selectedGroups.length) params.groupids = selectedGroups;
    const hosts = await this.call('host.get', params);
    if (!hosts.length) return [];
    const items = await this.call('item.get', {
      output: ['itemid', 'hostid', 'key_', 'name', 'lastvalue', 'units', 'value_type'],
      selectHosts: ['hostid'],
      hostids: hosts.map(h => h.hostid),
      filter: { status: 0 },
      monitored: true,
      webitems: false
    }).catch(() => []);
    const byHost = {};
    for (const it of items) {
      const hid = it.hosts?.[0]?.hostid;
      if (!hid) continue;
      (byHost[hid] = byHost[hid] || []).push(it);
    }
    return hosts.map(h => {
      const inv = h.inventory || {};
      const iface = (h.interfaces || []).find(i => i.type === '2') || (h.interfaces || [])[0] || {};
      const its = byHost[h.hostid] || [];
      const find = (reList) => its.find(x => reList.some(re => re.test(x.key_) || re.test(x.name)));
      const cpu = find(ZBX_CLASS.cpu), mem = find(ZBX_CLASS.mem), up = find(ZBX_CLASS.uptime),
        temp = find(ZBX_CLASS.temp), model = find(ZBX_CLASS.cpuModel);
      return {
        hostid: h.hostid,
        host: h.host,
        source: 'zabbix',
        name: h.name || h.host,
        ip: iface.ip || '-',
        status: h.status === '0' ? 1 : 0,       // 1=在线 0=离线
        available: Number(iface.available || 0),
        error: iface.error || '',
        maintenance: h.maintenance_status === '1',
        vendor: inv.vendor || '',
        model: inv.model || (model ? model.lastvalue : '') || inv.type || '',
        os: inv.os || '',
        serial: inv.serialnum_a || '',
        location: inv.location || '',
        groups: (h.hostgroups || []).map(g => ({ id: String(g.groupid), name: g.name })),
        uptimeSec: up ? Number(up.lastvalue) : null,
        cpu: cpu ? Number(cpu.lastvalue) : null,
        mem: mem ? Number(mem.lastvalue) : null,
        temp: temp ? Number(temp.lastvalue) : null,
        tags: (h.tags || []).reduce((a, t) => (a[t.tag] = t.value, a), {}),
        _items: its
      };
    });
  }
  async ports(hostid) {
    const host = (await this.hosts()).find(h => h.hostid === hostid);
    if (!host) return { host: null, ports: [] };
    const its = host._items || [];
    const find = (reList) => its.filter(x => reList.some(re => re.test(x.key_) || re.test(x.name)));
    const inO = find(ZBX_CLASS.inOct), outO = find(ZBX_CLASS.outOct), oper = find(ZBX_CLASS.oper),
      adm = find(ZBX_CLASS.admin), spd = find(ZBX_CLASS.speed), al = find(ZBX_CLASS.alias),
      desc = find(ZBX_CLASS.ifDescr), ie = find(ZBX_CLASS.inErr), oe = find(ZBX_CLASS.outErr),
      idc = find(ZBX_CLASS.inDis), odc = find(ZBX_CLASS.outDis);
    const idxOf = (it) => {
      const m = String(it.key_).match(/\[([^\]]*)\]/);
      if (m) { const p = m[1].split(',')[0].replace(/"/g, ''); if (/^\d+$/.test(p)) return Number(p); }
      const m2 = String(it.name).match(/(\d+)\s*$/); return m2 ? Number(m2[1]) : null;
    };
    const map = new Map();
    const put = (arr, key, conv) => arr.forEach(it => {
      const i = idxOf(it); if (i == null) return;
      const o = map.get(i) || { index: i };
      o[key] = conv ? conv(it) : it.lastvalue;
      if (it.units) o.units = it.units;
      map.set(i, o);
    });
    const n = v => v === undefined || v === '' ? null : Number(v);
    put(inO, 'inRaw', n); put(outO, 'outRaw', n); put(oper, 'operStatus', n); put(adm, 'adminStatus', n);
    put(spd, 'speedMbps', v => n(v.lastvalue) * (/HighSpeed/.test(v.key_) ? 1 : 1e-6));
    put(al, 'alias', v => v.lastvalue);
    put(desc, 'name', v => v.lastvalue);
    put(ie, 'inErrors', n); put(oe, 'outErrors', n); put(idc, 'inDiscards', n); put(odc, 'outDiscards', n);
    const ports = [...map.values()].filter(p => p.name || p.inRaw !== null).map(p => ({
      index: p.index, name: p.name || `if${p.index}`, alias: p.alias || '',
      operStatus: p.operStatus === null ? 0 : p.operStatus,
      adminStatus: p.adminStatus === null ? 1 : p.adminStatus,
      speedMbps: p.speedMbps || 1000, duplex: 'full', mode: '-', vlan: '-', pvid: '-',
      inBps: p.inRaw ? Math.round(p.inRaw * 8 / 60) : 0,     // 假定 60s 轮询差值
      outBps: p.outRaw ? Math.round(p.outRaw * 8 / 60) : 0,
      inPps: 0, outPps: 0,
      inErrors: p.inErrors || 0, outErrors: p.outErrors || 0,
      inDiscards: p.inDiscards || 0, outDiscards: p.outDiscards || 0, crcErrors: 0,
      poe: null, util: null, lastChange: null
    })).sort((a, b) => a.index - b.index);
    return { host: this.serialize(host), ports };
  }
  async history(hostid, kind, from, to, points = 120) {
    const host = (await this.hosts()).find(h => h.hostid === hostid);
    if (!host) return [];
    const its = host._items || [];
    const reList = kind === 'cpu' ? ZBX_CLASS.cpu : kind === 'mem' ? ZBX_CLASS.mem : kind === 'temp' ? ZBX_CLASS.temp : ZBX_CLASS.inOct;
    const item = its.find(x => reList.some(re => re.test(x.key_) || re.test(x.name)));
    if (!item) return [];
    const vt = Number(item.value_type);
    const rows = await this.call('history.get', {
      output: 'extend', history: vt, itemids: [item.itemid],
      time_from: from, time_till: to, sortfield: 'clock', sortorder: 'ASC', limit: 5000
    });
    const step = Math.max(1, Math.ceil(rows.length / points));
    const out = [];
    for (let i = 0; i < rows.length; i += step) {
      out.push({ ts: Number(rows[i].clock), value: Number(rows[i].value) });
    }
    if (kind === 'traffic') out.forEach(p => p.value = Math.round(p.value * 8 / 60));
    return out;
  }
  async problems() {
    const ps = await this.call('problem.get', {
      output: 'extend', selectAcknowledges: 'extend', selectHosts: ['hostid', 'host', 'name'],
      recent: true, sortfield: ['eventid'], sortorder: 'DESC', limit: 200
    }).catch(() => []);
    const SEV = { 0: 'information', 1: 'information', 2: 'warning', 3: 'average', 4: 'high', 5: 'disaster' };
    return ps.map(p => ({
      id: p.eventid, eventid: p.eventid, source: 'zabbix',
      severity: SEV[p.severity] || 'warning',
      host: p.hosts?.[0]?.host || p.hosts?.[0]?.name || '-',
      title: p.name, message: p.name,
      code: p.objectid, clock: Number(p.clock),
      acknowledged: p.acknowledged === '1',
      status: p.r_clock && p.r_clock !== '0' ? 'resolved' : 'problem'
    }));
  }
  async ack(eventid, message, user) {
    return await this.call('event.acknowledge', { eventids: [eventid], action: 6, message: message || `已由 ${user} 确认` });
  }
  serialize(h) { const { _items, ...rest } = h; return rest; }
}


/* ========================== Provider 工厂 ========================== */
class DemoProvider {
  constructor() { this.name = 'demo'; }
  async health() { return 'demo-mode'; }
  async hostGroups() { return [{ id: 'g1', name: '网络设备/交换机' }, { id: 'g2', name: '网络设备/防火墙' }]; }
  async hosts(groupId) {
    return DEMO_DEVICES.filter(d => !groupId || (groupId === 'g2' ? d.role === '防火墙' : d.role !== '防火墙'))
      .map(d => {
        const det = demoDetail(d.host);
        const down = d.host === 'SW-ACC-03';
        return {
          hostid: d.host, host: d.host, source: 'demo', name: d.name, ip: d.ip,
          status: down ? 0 : 1, available: down ? 0 : 1, error: down ? 'SNMP 超时 / 主机不可达' : '',
          maintenance: false, vendor: d.vendor, model: d.model, os: d.os,
          serial: det.serial, location: d.zone, role: d.role,
          uptimeSec: det.uptimeSec, cpu: det.cpu, mem: det.mem, temp: det.temp,
          portCount: d.ports,
          groups: [{ id: d.role === '防火墙' ? 'g2' : 'g1', name: d.role === '防火墙' ? '网络设备/防火墙' : '网络设备/交换机' }],
          tags: { zone: d.zone, role: d.role }
        };
      });
  }
  async ports(hostid) {
    const det = demoDetail(hostid);
    const dev = DEMO_DEVICES.find(d => d.host === hostid);
    if (!det || !dev) return { host: null, ports: [] };
    const h = (await this.hosts()).find(x => x.hostid === hostid);
    if (hostid === 'SW-ACC-03') det.ports[16] = { ...det.ports[16], operStatus: 2, inBps: 0, outBps: 0, util: 0, alias: 'PC-217' };
    return { host: h, ports: det.ports };
  }
  async history(hostid, kind, from, to, points) { return demoHistory(hostid, kind, from, to, points); }
  async problems() { return demoProblems(); }
  async ack(eventid) { return { ok: true }; }
}

let _provider = null, _providerKey = '';
function getProvider() {
  const cfg = (db.settingsSync() || {}).datasource || {};
  const key = cfg.mode + '|' + JSON.stringify(cfg.zabbix);
  if (_provider && _providerKey === key) return _provider;
  _providerKey = key;
  _provider = cfg.mode === 'zabbix' && cfg.zabbix.url && cfg.zabbix.username ? new ZabbixProvider(cfg.zabbix) : new DemoProvider();
  return _provider;
}
function resetProvider() { _provider = null; _providerKey = ''; }

/* 简易 TTL 缓存，避免高频刷新打爆 Zabbix */
const _cache = new Map();
async function cached(key, ttlSec, fn) {
  const hit = _cache.get(key);
  const now = Date.now();
  if (hit && now - hit.at < ttlSec * 1000) {
    if (hit.pending) return hit.pending;
    return hit.value;
  }
  const p = (async () => { try { const v = await fn(); _cache.set(key, { at: Date.now(), value: v }); return v; } catch (e) { _cache.set(key, { at: Date.now(), value: hit?.value, error: e.message }); throw e; } })();
  _cache.set(key, { at: now, pending: p });
  return p;
}
function cacheClear() { _cache.clear(); }

/* ==================== 上层统一取数（含健康度计算） ==================== */
function healthScore(h) {
  let s = 100;
  if (h.status === 0) return 0;
  if (h.cpu != null) s -= Math.max(0, (h.cpu - 60)) * 0.6;
  if (h.mem != null) s -= Math.max(0, (h.mem - 70)) * 0.5;
  if (h.temp != null) s -= Math.max(0, (h.temp - 50)) * 0.8;
  if (h.available === 2) s -= 15;
  return Math.max(0, Math.min(100, +s.toFixed(0)));
}

module.exports = {
  DEMO_DEVICES, getProvider, resetProvider, cached, cacheClear,
  healthScore, human, fmtBps, rng, pick
};
