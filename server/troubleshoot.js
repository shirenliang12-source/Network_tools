/* =========================================================================
 * 排障工作台 · 告警 → 根因闭环引擎
 * - 把一条告警映射到"诊断剧本"，自动采集证据（设备/端口/历史/可达性探测）
 * - 输出：结论摘要 + 分步证据 + 可能原因（带置信度）+ 处置建议
 * - 数据源：datasource（Zabbix / Demo）。探测复用 toolbox.pingTest。
 * ========================================================================= */
'use strict';
const ds = require('./datasource');
const toolbox = require('./toolbox');

/* ----------------------------- 工具 ----------------------------- */
const SEV_W = { disaster: 5, high: 4, average: 3, warning: 2, information: 1, critical: 5 };

function portNameFrom(text) {
  const m = String(text || '').match(/([A-Za-z]+[\d]*(?:\/\d+){1,3})/);
  return m ? m[1].toLowerCase() : null;
}
function nowSec() { return Math.floor(Date.now() / 1000); }

/* ----------------------------- 告警获取 ----------------------------- */
async function listAlarms(opts = {}) {
  const { severity = '', host = '', keyword = '', onlyActive = true } = opts;
  const problems = await ds.cached('problems', 20, async () => {
    const p = await ds.getProvider().problems();
    const local = (await _alarmsLocal()).filter(a => a.status !== 'closed');
    const map = new Map();
    for (const x of [...p, ...local]) if (!map.has(x.eventid || x.id)) map.set(x.eventid || x.id, x);
    return [...map.values()].sort((a, b) => (SEV_W[b.severity] || 0) - (SEV_W[a.severity] || 0) || (b.clock || 0) - (a.clock || 0));
  });
  let list = problems;
  if (onlyActive) list = list.filter(a => a.status !== 'resolved' && a.status !== 'closed');
  if (severity) list = list.filter(a => a.severity === severity);
  if (host) list = list.filter(a => a.host === host);
  if (keyword) list = list.filter(a => ((a.title || '') + (a.message || '') + (a.host || '')).toLowerCase().includes(String(keyword).toLowerCase()));
  return list;
}
// 避免直接依赖 db 模块导致的循环引用，按需 require
async function _alarmsLocal() {
  try { const db = require('./db'); return await db.alarmsList(); } catch (e) { return []; }
}

/* ----------------------------- 证据采集（带容错） ----------------------------- */
async function evHost(host) {
  try {
    const hs = await ds.getProvider().hosts();
    const h = hs.find(x => x.host === host || x.name === host);
    return h || null;
  } catch (e) { return null; }
}
async function evPorts(host) {
  try {
    const hs = await ds.getProvider().hosts();
    const h = hs.find(x => x.host === host || x.name === host);
    if (!h) return null;
    const r = await ds.getProvider().ports(h.hostid);
    return r && r.ports ? r.ports : null;
  } catch (e) { return null; }
}
async function evHistory(host, kind) {
  try {
    const hs = await ds.getProvider().hosts();
    const h = hs.find(x => x.host === host || x.name === host);
    if (!h) return null;
    const to = nowSec(), from = to - 3 * 3600;
    const rows = await ds.getProvider().history(h.hostid, kind, from, to, 36);
    if (!rows || !rows.length) return null;
    const vals = rows.map(p => Number(p.value) || 0);
    const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
    const last = vals[vals.length - 1];
    const max = Math.max(...vals);
    const rising = vals.length > 6 && last > vals[0] * 1.2;
    return { avg: +avg.toFixed(1), last: +last.toFixed(1), max: +max.toFixed(1), rising, points: rows.length };
  } catch (e) { return null; }
}
async function evReach(ip) {
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return { ok: null, note: '无可用 IP' };
  try {
    const r = await toolbox.pingTest(ip, { count: 3, timeoutMs: 2500 });
    return { ok: !!r.ok, loss: r.loss != null ? r.loss : (r.alive ? 0 : 100), avgMs: r.avgMs || r.rtt, raw: r };
  } catch (e) { return { ok: false, note: e.message }; }
}

/* ----------------------------- 分类 ----------------------------- */
function classify(a) {
  const t = ((a.title || '') + ' ' + (a.message || '') + ' ' + (a.code || '')).toLowerCase();
  if (/port_down|端口.*down|\bdown\b|link down|非计划/.test(t)) return 'PORT_DOWN';
  if (/crc|错包|error|discard/.test(t)) return 'CRC_ERR';
  if (/cpu/.test(t)) return 'CPU_HIGH';
  if (/带宽|bandwidth|bw_high|利用率.*85|出口/.test(t)) return 'BW_HIGH';
  if (/会话|session/.test(t)) return 'SESSION';
  if (/风扇|fan/.test(t)) return 'FAN';
  if (/温度|temp|高温|偏高/.test(t)) return 'TEMP';
  if (/配置文件|config|cfg|running-config/.test(t)) return 'CONFIG';
  return 'GENERIC';
}

/* ----------------------------- 剧本 ----------------------------- */
async function pbPortDown(a, ev) {
  const steps = [];
  const host = await evHost(a.host);
  steps.push({ name: '设备可达性与状态', evidence: host ? `设备 ${a.host}：${host.status ? '在线' : '离线'}${host.error ? '（' + host.error + '）' : ''}` : '未能获取设备状态', finding: host && !host.status ? '设备整体不可达，问题可能在更上游或设备断电' : '设备在线，聚焦端口本身' });
  const ports = await evPorts(a.host);
  const pn = portNameFrom(a.title + ' ' + a.message);
  let port = null;
  if (ports && pn) port = ports.find(p => p.name && p.name.toLowerCase().includes(pn));
  if (ports && port) {
    steps.push({ name: '端口状态', evidence: `端口 ${port.name}：operStatus=${port.operStatus === 1 ? 'Up' : 'Down'}，adminStatus=${port.adminStatus === 1 ? 'Up' : 'Down'}，速率 ${port.speedMbps || '-'}Mbps`, finding: port.adminStatus !== 1 ? '端口被管理员 shutdown（人为或脚本触发）' : '物理/协议层 Down，非人为 shutdown' });
  } else if (ports) {
    const downs = ports.filter(p => p.operStatus !== 1);
    steps.push({ name: '端口状态', evidence: `该设备共 ${ports.length} 个端口，其中 ${downs.length} 个 Down`, finding: downs.length ? '存在多个 Down 端口，疑似上行/级联或对端问题' : '未匹配到具体端口，请核对告警中的端口名' });
  } else {
    steps.push({ name: '端口状态', evidence: '未能获取端口表', finding: '设备 SNMP/接口采集异常，建议现场 console 查看' });
  }
  const reach = host && host.ip ? await evReach(host.ip) : { ok: null, note: '无 IP' };
  steps.push({ name: '对端/链路可达性', evidence: reach.ok === null ? (reach.note || '跳过') : (reach.ok ? `管理 IP ${host.ip} 可达（丢包 ${reach.loss}%，平均 ${reach.avgMs}ms）` : `管理 IP ${host.ip} 不可达`), finding: reach.ok ? '设备管理面正常，问题在业务端口/链路' : '连管理 IP 都不通，优先排查供电/上联/物理连接' });

  const causes = [];
  if (port && port.adminStatus !== 1) causes.push({ prob: '端口被人为 shutdown（维护后遗忘 no shutdown / 脚本误触发）', confidence: 'high' });
  if (host && !host.status) causes.push({ prob: '设备断电或上联中断导致整机离线', confidence: 'high' });
  if (port && port.operStatus !== 1 && (!port.adminStatus || port.adminStatus === 1)) causes.push({ prob: '物理层故障：网线/光纤松动、模块损坏或对端端口 Down', confidence: 'high' });
  if (!port) causes.push({ prob: '级联/上行端口 Down 或 STP 阻塞', confidence: 'medium' });
  if (!causes.length) causes.push({ prob: '端口振荡或间歇性 Down（需查看 logbuffer 确认）', confidence: 'medium' });

  const recs = [
    `登录 ${a.host} 执行 display interface ${pn || ''} / show interface ${pn || ''}，确认物理层与协议层状态与错包计数`,
    port && port.adminStatus !== 1 ? `进入接口视图执行 undo shutdown / no shutdown 恢复端口` : `检查 ${pn || '该'} 端口的线缆、光模块与对端设备供电`,
    `查看 logbuffer/日志，确认 Down 发生的精确时间与是否伴随 CRC/error 增长`,
    `必要时在现场 Web 终端操作，过程会被录像与审计`
  ];
  return { summary: `端口 Down 类告警：${a.host}${pn ? ' / ' + pn : ''}`, steps, causes, recommendations: recs };
}

async function pbCrc(a, ev) {
  const steps = [];
  const ports = await evPorts(a.host);
  const pn = portNameFrom(a.title + ' ' + a.message);
  let port = null;
  if (ports && pn) port = ports.find(p => p.name && p.name.toLowerCase().includes(pn));
  if (ports && port) {
    steps.push({ name: '端口错包计数', evidence: `端口 ${port.name}：inErrors=${port.inErrors || 0}，outErrors=${port.outErrors || 0}，crcErrors=${port.crcErrors || 0}，inDiscards=${port.inDiscards || 0}`, finding: (port.crcErrors || port.inErrors) ? '存在 CRC/Input 错包，典型为物理层问题' : '当前未检出错包（可能为瞬时已恢复）' });
  } else if (ports) {
    const bad = ports.filter(p => (p.crcErrors || 0) + (p.inErrors || 0) > 0).sort((x, y) => ((y.crcErrors || 0) + (y.inErrors || 0)) - ((x.crcErrors || 0) + (x.inErrors || 0)));
    steps.push({ name: '端口错包计数', evidence: bad.length ? `错包最高的端口：${bad.slice(0, 3).map(p => p.name + '(' + ((p.crcErrors || 0) + (p.inErrors || 0)) + ')').join('、')}` : '未检出明显错包端口', finding: bad.length ? '定位到具体问题端口' : '错包已恢复或未采集到' });
    port = bad[0];
  } else {
    steps.push({ name: '端口错包计数', evidence: '未能获取端口表', finding: 'SNMP 接口采集异常' });
  }
  if (port) steps.push({ name: '速率/双工', evidence: `端口 ${port.name}：速率 ${port.speedMbps || '-'}Mbps，双工 ${port.duplex || '-'}`, finding: '检查对端是否强制不同速率/双工（常见 CRC 诱因）' });

  const causes = [
    { prob: '网线/水晶头接触不良或劣化（最常见）', confidence: 'high' },
    { prob: '两端速率/双工不匹配（一端 auto、一端强制）', confidence: 'medium' },
    { prob: '光模块/端口硬件故障或光纤脏污', confidence: 'medium' },
    { prob: '强干扰环境或线缆超距', confidence: 'low' }
  ];
  const recs = [
    `登录 ${a.host} 查看 display interface ${port ? port.name : pn || ''} 的 CRC/input-error 是否持续增长`,
    `优先更换该端口网线或水晶头；若为光口则清洁/更换光模块与光纤`,
    `确认对端端口 speed/duplex 与本端一致，避免一端强制一端自适应`,
    `错包增长期间用端口镜像抓包，确认是否为特定流量触发`
  ];
  return { summary: `CRC / 错包类告警：${a.host}${port ? ' / ' + port.name : ''}`, steps, causes, recommendations: recs };
}

async function pbCpu(a, ev) {
  const steps = [];
  const cpu = await evHistory(a.host, 'cpu');
  if (cpu) steps.push({ name: 'CPU 历史趋势（近 3h）', evidence: `均值 ${cpu.avg}%，当前 ${cpu.last}%，峰值 ${cpu.max}%${cpu.rising ? '，呈上升趋势' : ''}`, finding: cpu.rising ? 'CPU 持续升高，非偶发抖动' : 'CPU 偏高但趋势平稳' });
  else steps.push({ name: 'CPU 历史趋势', evidence: '未能获取 CPU 历史', finding: 'Zabbix/Demo 未提供该指标' });
  const host = await evHost(a.host);
  if (host) steps.push({ name: '设备实时指标', evidence: `CPU=${host.cpu ?? '-'}%，MEM=${host.mem ?? '-'}%，TEMP=${host.temp ?? '-'}℃`, finding: host.mem > 80 ? '内存也偏高，注意是否存在表项膨胀' : '关注 CPU 进程分布' });

  const causes = [
    { prob: '流量突发 / 广播风暴 / 环路导致转发压力陡增', confidence: 'high' },
    { prob: '某控制平面进程异常（STP/BGP/SNMP 轮询风暴）', confidence: 'medium' },
    { prob: '设备表项（MAC/ARP/路由）膨胀', confidence: 'medium' },
    { prob: '设备性能达到瓶颈或版本 Bug', confidence: 'low' }
  ];
  const recs = [
    `登录执行 display cpu-usage / show processes cpu，按进程排序定位占用最高项`,
    `结合「会话与流量」「流量分析」查看 Top Talker，判断是否为特定主机/网段打满`,
    `检查近期是否有 STP 拓扑变化或新上线设备引发环路`,
    `若为 SNMP 轮询风暴，调整轮询间隔或采用采样（sFlow/NetStream）`
  ];
  return { summary: `CPU 高负载告警：${a.host}`, steps, causes, recommendations: recs };
}

async function pbBw(a, ev) {
  const steps = [];
  const traf = await evHistory(a.host, 'traffic');
  if (traf) steps.push({ name: '出口流量趋势（近 3h）', evidence: `均值 ${(traf.avg / 1e6).toFixed(1)} Mbps，当前 ${(traf.last / 1e6).toFixed(1)} Mbps，峰值 ${(traf.max / 1e6).toFixed(1)} Mbps${traf.rising ? '，呈上升趋势' : ''}`, finding: traf.rising ? '流量持续走高' : '流量偏高但平稳' });
  else steps.push({ name: '出口流量趋势', evidence: '未能获取流量历史', finding: '需结合会话分析定位来源' });
  steps.push({ name: '定位流量来源', evidence: '建议查看「会话与流量」Top 会话 / 「流量分析」Top Talker', finding: '先确定是高业务量还是异常流量' });

  const causes = [
    { prob: '业务高峰或批量同步/备份导致（正常但需扩容）', confidence: 'medium' },
    { prob: '异常大流量：病毒外联、P2P、扫描', confidence: 'medium' },
    { prob: '链路带宽规划不足', confidence: 'low' }
  ];
  const recs = [
    `在「会话与流量」按该设备/IP 过滤，定位 Top 会话与对端`,
    `若为异常流量，下发限速或 ACL 隔离来源主机`,
    `评估链路扩容或分流（链路聚合 / 负载均衡）`,
    `长期可在「流量分析」做 1s 粒度时序回溯确认突发时刻`
  ];
  return { summary: `带宽利用率高告警：${a.host}`, steps, causes, recommendations: recs };
}

async function pbSession(a, ev) {
  const steps = [];
  const host = await evHost(a.host);
  steps.push({ name: '设备与现状', evidence: host ? ('防火墙 ' + a.host + '（' + (host.model || '-') + '），CPU=' + (host.cpu != null ? host.cpu : '-') + '%') : '未能获取设备信息', finding: '会话表接近上限通常伴随新建连接被丢弃' });
  steps.push({ name: '定位会话来源', evidence: '查看「会话与流量」Top 会话，按源 IP / 目的 IP 排序', finding: '判断是正常业务峰值还是异常外联' });
  const causes = [
    { prob: '存在主机病毒/木马大量建连（外联扫描）', confidence: 'high' },
    { prob: 'NAT 会话超时配置过长导致表项堆积', confidence: 'medium' },
    { prob: '业务真实并发增长超过规格', confidence: 'low' }
  ];
  const recs = [
    `定位 Top 会话来源 IP，隔离异常主机并查杀`,
    `调优会话超时（如 TCP 超时由默认调到 1200s 以内）`,
    `检查策略是否存在放通过宽导致会话膨胀`
  ];
  return { summary: `会话数接近上限告警：${a.host}`, steps, causes, recommendations: recs };
}

async function pbFan(a, ev) {
  const host = await evHost(a.host);
  const steps = [{ name: '设备状态', evidence: host ? `温度=${host.temp ?? '-'}℃，CPU=${host.cpu ?? '-'}%` : '未能获取', finding: host && host.temp > 50 ? '温度偏高，需关注散热' : '温度正常' }];
  const causes = [
    { prob: '风扇模块故障或转速异常', confidence: 'high' },
    { prob: '机房空调/环境温度过高', confidence: 'medium' },
    { prob: '防尘网堵塞或设备积灰', confidence: 'medium' }
  ];
  return { summary: `风扇/散热告警：${a.host}`, steps, causes, recommendations: [
    `display environment / show environment 查看进风口/出风口温度与风扇转速`,
    `检查机房空调运行状态与进风温度`,
    `清理防尘网与机箱积灰，必要时更换风扇模块`
  ] };
}

async function pbTemp(a, ev) {
  const host = await evHost(a.host);
  const steps = [{ name: '温度现状', evidence: host ? `当前温度=${host.temp ?? '-'}℃` : '未能获取', finding: host && host.temp > 50 ? '超过建议阈值，存在降频/宕机风险' : '温度在合理区间' }];
  const causes = [
    { prob: '机房环境温度高 / 空调能力不足', confidence: 'high' },
    { prob: '设备散热风道受阻（防尘网/积灰）', confidence: 'medium' },
    { prob: '高负载下自然升温（关联 CPU 高）', confidence: 'low' }
  ];
  return { summary: `温度偏高告警：${a.host}`, steps, causes, recommendations: [
    `确认弱电间/机房空调与进风温度`,
    `清理防尘网与机箱积灰，保证前后风道畅通`,
    `若伴随 CPU 高，先按 CPU 高排查降负载`
  ] };
}

async function pbConfig(a, ev) {
  const steps = [{ name: '变更基线', evidence: `设备 ${a.host} 检测到 running-config 与基线不一致`, finding: '需确认是否为计划内变更' }];
  const causes = [
    { prob: '计划内变更但未 save（重启会丢失）', confidence: 'medium' },
    { prob: '非授权/误操作修改配置', confidence: 'medium' },
    { prob: '自动化脚本下发导致漂移', confidence: 'low' }
  ];
  return { summary: `配置变更告警：${a.host}`, steps, causes, recommendations: [
    `比对当前配置与最近一次基线/备份，确认差异项`,
    `若为计划内变更，执行 save / write memory 固化配置`,
    `若为非预期变更，回滚并排查操作来源（终端录像可溯源）`
  ] };
}

async function pbGeneric(a, ev) {
  const host = await evHost(a.host);
  const steps = [];
  steps.push({ name: '设备状态', evidence: host ? `${a.host}：${host.status ? '在线' : '离线'}${host.error ? '（' + host.error + '）' : ''}，CPU=${host.cpu ?? '-'}%，MEM=${host.mem ?? '-'}%` : '未能获取设备状态', finding: host && !host.status ? '设备不可达' : '设备在线' });
  const reach = host && host.ip ? await evReach(host.ip) : { ok: null, note: '无 IP' };
  steps.push({ name: '可达性', evidence: reach.ok === null ? (reach.note || '跳过') : (reach.ok ? `管理 IP 可达（丢包 ${reach.loss}%）` : '管理 IP 不可达'), finding: reach.ok ? '管理面正常' : '管理面不可达，优先排查供电/上联' });
  return {
    summary: `通用排障：${a.host}（${a.title || ''}）`,
    steps,
    causes: [{ prob: '需结合告警具体语义进一步定位（设备/IP/端口/指标）', confidence: 'low' }],
    recommendations: [
      `在「设备管理」查看 ${a.host} 的端口、CPU、内存、温度明细`,
      `必要时用「诊断工具箱」「网络运维工具箱」做 ping/traceroute/端口扫描`,
      `可直接把设备 show 输出粘贴给 AI 助手做深度分析`
    ]
  };
}

const PLAYBOOKS = {
  PORT_DOWN: pbPortDown, CRC_ERR: pbCrc, CPU_HIGH: pbCpu, BW_HIGH: pbBw,
  SESSION: pbSession, FAN: pbFan, TEMP: pbTemp, CONFIG: pbConfig, GENERIC: pbGeneric
};

/* ----------------------------- 主入口 ----------------------------- */
async function diagnose(alarm) {
  if (!alarm || !alarm.host) return { ok: false, error: '告警缺少 host 字段' };
  const category = classify(alarm);
  const playbook = PLAYBOOKS[category] || PLAYBOOKS.GENERIC;
  let result;
  try {
    result = await playbook(alarm, {});
  } catch (e) {
    result = { summary: `诊断执行异常：${a_title(alarm)}`, steps: [], causes: [], recommendations: ['诊断脚本异常：' + e.message], error: e.message };
  }
  return {
    ok: true,
    alarm: { id: alarm.eventid || alarm.id, host: alarm.host, title: alarm.title, severity: alarm.severity, clock: alarm.clock, code: alarm.code },
    category,
    summary: result.summary,
    steps: result.steps || [],
    causes: (result.causes || []).map(c => ({ prob: c.prob, confidence: c.confidence || 'low' })),
    recommendations: result.recommendations || [],
    generatedAt: nowSec()
  };
}
function a_title(a) { return a.title || a.host || '未知告警'; }

module.exports = { listAlarms, diagnose, classify, SEV_W };
