'use strict';
/**
 * 存储契约（PG 与 JSON 双实现共用）
 *
 * 这里只描述「数据长什么样」，不关心「存在哪」。
 * PG 侧按这张表建库建表；JSON 侧按 collection 名落在 data/db.json。
 * 上层业务代码只依赖本文件描述的语义，不直接触碰任何存储细节。
 */

/** 每张表：PG 表名 / JSON 集合或文件 / 主键 / 字段映射 */
const TABLES = {
  settings: {
    pg: 'app_settings',
    json: 'settings',
    pk: 'k',
    // k='settings' 单行存整个 settings 对象；扩展行以 k='settings.<path>' 存片段
    ddl: `CREATE TABLE IF NOT EXISTS app_settings (
      k TEXT PRIMARY KEY,
      v JSONB NOT NULL
    )`
  },
  users: {
    pg: 'users',
    json: 'users',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT,
      role TEXT NOT NULL DEFAULT 'ops',
      pass_hash TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT true,
      last_login_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: ['CREATE UNIQUE INDEX IF NOT EXISTS users_username_key ON users(username)']
  },
  credentials: {
    pg: 'credentials',
    json: 'credentials',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      name TEXT,
      vendor TEXT,
      kind TEXT,
      host TEXT,
      port INTEGER,
      username TEXT,
      secret_enc TEXT,
      enable_enc TEXT,
      note TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: ['CREATE INDEX IF NOT EXISTS credentials_host_idx ON credentials(host)']
  },
  templates: {
    pg: 'templates',
    json: 'templates',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS templates (
      id TEXT PRIMARY KEY,
      name TEXT,
      vendor TEXT,
      commands JSONB,
      category TEXT,
      danger BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`
  },
  alarms: {
    pg: 'alarms',
    json: 'alarms',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS alarms (
      id TEXT PRIMARY KEY,
      eventid TEXT,
      source TEXT,
      severity TEXT,
      host TEXT,
      title TEXT,
      message TEXT,
      status TEXT,
      clock BIGINT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      ack_by TEXT, ack_at TIMESTAMP,
      closed_by TEXT, closed_at TIMESTAMP,
      extra JSONB
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS alarms_status_idx ON alarms(status)',
      'CREATE INDEX IF NOT EXISTS alarms_severity_idx ON alarms(severity)',
      'CREATE INDEX IF NOT EXISTS alarms_created_idx ON alarms(created_at DESC)'
    ]
  },
  inventory: {
    pg: 'inventory',
    json: 'inventory',
    pk: 'host',
    ddl: `CREATE TABLE IF NOT EXISTS inventory (
      host TEXT PRIMARY KEY,
      data JSONB NOT NULL
    )`
  },
  topology: {
    pg: 'topology',
    json: 'topology',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS topology (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL
    )`
  },
  aiHistory: {
    pg: 'ai_history',
    json: 'aiHistory',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS ai_history (
      id TEXT PRIMARY KEY,
      user TEXT,
      question TEXT,
      answer TEXT,
      at TIMESTAMP NOT NULL DEFAULT now(),
      provider TEXT,
      model TEXT
    )`,
    indexes: ['CREATE INDEX IF NOT EXISTS ai_history_at_idx ON ai_history(at DESC)']
  },
  audit: {
    pg: 'audit_log',
    json: 'audit',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS audit_log (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMP NOT NULL DEFAULT now(),
      user TEXT, role TEXT, ip TEXT, action TEXT, target TEXT, result TEXT, detail TEXT
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit_log(ts DESC)',
      'CREATE INDEX IF NOT EXISTS audit_user_idx ON audit_log(user)'
    ]
  },
  speedResults: {
    pg: 'speed_results',
    json: 'speedResults',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS speed_results (
      id TEXT PRIMARY KEY,
      at TIMESTAMP NOT NULL DEFAULT now(),
      data JSONB NOT NULL
    )`,
    indexes: ['CREATE INDEX IF NOT EXISTS speed_at_idx ON speed_results(at DESC)']
  },
  recordingMeta: {
    pg: 'recording_meta',
    json: 'recordingMeta',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS recording_meta (
      id TEXT PRIMARY KEY,
      started_at TIMESTAMP NOT NULL DEFAULT now(),
      data JSONB NOT NULL
    )`,
    indexes: ['CREATE INDEX IF NOT EXISTS recmeta_started_idx ON recording_meta(started_at DESC)']
  },
  captureFiles: {
    pg: 'capture_files',
    json: 'captureFiles',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS capture_files (
      id TEXT PRIMARY KEY,
      name TEXT,
      path TEXT,
      size BIGINT,
      iface TEXT,
      mode TEXT,
      filter TEXT,
      source TEXT,
      started_at TIMESTAMP NOT NULL DEFAULT now(),
      ended_at TIMESTAMP,
      data JSONB
    )`,
    indexes: ['CREATE INDEX IF NOT EXISTS capfile_started_idx ON capture_files(started_at DESC)']
  },
  /* --- P1 旁路持续采集任务 --- */
  captureTasks: {
    pg: 'capture_tasks',
    json: 'captureTasks',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS capture_tasks (
      id TEXT PRIMARY KEY,
      name TEXT,
      iface TEXT,
      bpf TEXT,
      pcap_size INTEGER DEFAULT 100,
      retain_hours INTEGER DEFAULT 72,
      enabled BOOLEAN NOT NULL DEFAULT false,
      status TEXT NOT NULL DEFAULT 'idle',
      last_started_at TIMESTAMP,
      last_ended_at TIMESTAMP,
      runs INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      data JSONB
    )`,
    indexes: ['CREATE INDEX IF NOT EXISTS captask_status_idx ON capture_tasks(status)']
  },
  /* --- P3 网络扫描（本机执行，结果三张表） --- */
  scanRuns: {
    pg: 'scan_runs',
    json: 'scanRuns',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS scan_runs (
      id TEXT PRIMARY KEY,
      task_id TEXT,
      name TEXT,
      targets TEXT,
      mode TEXT,
      hosts_total INTEGER DEFAULT 0,
      hosts_alive INTEGER DEFAULT 0,
      ports_open INTEGER DEFAULT 0,
      risks INTEGER DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'running',
      started_at TIMESTAMP NOT NULL DEFAULT now(),
      ended_at TIMESTAMP,
      duration_ms INTEGER DEFAULT 0,
      data JSONB
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS scanrun_task_idx ON scan_runs(task_id)',
      'CREATE INDEX IF NOT EXISTS scanrun_started_idx ON scan_runs(started_at DESC)'
    ]
  },
  scanHosts: {
    pg: 'scan_hosts',
    json: 'scanHosts',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS scan_hosts (
      id TEXT PRIMARY KEY,
      run_id TEXT,
      task_id TEXT,
      ip TEXT,
      hostname TEXT,
      mac TEXT,
      alive BOOLEAN NOT NULL DEFAULT false,
      open_ports INTEGER DEFAULT 0,
      risk_level TEXT,
      risk_tags TEXT[],
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS scanhost_run_idx ON scan_hosts(run_id)',
      'CREATE INDEX IF NOT EXISTS scanhost_ip_idx ON scan_hosts(ip)',
      'CREATE INDEX IF NOT EXISTS scanhost_risk_idx ON scan_hosts(risk_level)'
    ]
  },
  scanPorts: {
    pg: 'scan_ports',
    json: 'scanPorts',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS scan_ports (
      id TEXT PRIMARY KEY,
      run_id TEXT,
      task_id TEXT,
      host_ip TEXT,
      ip TEXT,
      port INTEGER,
      proto TEXT,
      state TEXT,
      service TEXT,
      product TEXT,
      banner TEXT,
      risk_level TEXT,
      risk_desc TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS scanport_run_idx ON scan_ports(run_id)',
      'CREATE INDEX IF NOT EXISTS scanport_ip_idx ON scan_ports(ip)',
      'CREATE INDEX IF NOT EXISTS scanport_port_idx ON scan_ports(port)',
      'CREATE INDEX IF NOT EXISTS scanport_risk_idx ON scan_ports(risk_level)'
    ]
  },
  scanTasks: {
    pg: 'scan_tasks',
    json: 'scanTasks',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS scan_tasks (
      id TEXT PRIMARY KEY,
      name TEXT,
      targets TEXT,
      ports TEXT,
      discover_mode TEXT,
      concurrency INTEGER DEFAULT 60,
      timeout_ms INTEGER DEFAULT 1200,
      banner BOOLEAN NOT NULL DEFAULT true,
      enabled BOOLEAN NOT NULL DEFAULT false,
      status TEXT NOT NULL DEFAULT 'idle',
      interval_sec INTEGER DEFAULT 3600,
      retain_hours INTEGER DEFAULT 72,
      runs INTEGER NOT NULL DEFAULT 0,
      last_started_at TIMESTAMP,
      last_ended_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      data JSONB
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS scantask_status_idx ON scan_tasks(status)',
      'CREATE INDEX IF NOT EXISTS scantask_enabled_idx ON scan_tasks(enabled)'
    ]
  },
  /* --- P3 网络诊断工具箱（摄像头/IP冲突/环路/日志审计/外网测速/DHCP） --- */
  netdiagRuns: {
    pg: 'netdiag_runs',
    json: 'netdiagRuns',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS netdiag_runs (
      id TEXT PRIMARY KEY,
      task_id TEXT,
      tool TEXT NOT NULL,
      mode TEXT,
      targets TEXT,
      status TEXT NOT NULL DEFAULT 'running',
      score INTEGER DEFAULT 100,
      level TEXT,
      findings_count INTEGER DEFAULT 0,
      targets_total INTEGER DEFAULT 0,
      targets_done INTEGER DEFAULT 0,
      started_at TIMESTAMP NOT NULL DEFAULT now(),
      ended_at TIMESTAMP,
      duration_ms INTEGER DEFAULT 0,
      data JSONB
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS ndrun_tool_idx ON netdiag_runs(tool)',
      'CREATE INDEX IF NOT EXISTS ndrun_started_idx ON netdiag_runs(started_at DESC)',
      'CREATE INDEX IF NOT EXISTS ndrun_task_idx ON netdiag_runs(task_id)'
    ]
  },
  netdiagHosts: {
    pg: 'netdiag_hosts',
    json: 'netdiagHosts',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS netdiag_hosts (
      id TEXT PRIMARY KEY,
      run_id TEXT,
      tool TEXT NOT NULL,
      ip TEXT,
      mac TEXT,
      vendor TEXT,
      model TEXT,
      kind TEXT,
      risk_level TEXT,
      risk_desc TEXT,
      data JSONB,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS ndhost_run_idx ON netdiag_hosts(run_id)',
      'CREATE INDEX IF NOT EXISTS ndhost_tool_idx ON netdiag_hosts(tool)',
      'CREATE INDEX IF NOT EXISTS ndhost_ip_idx ON netdiag_hosts(ip)',
      'CREATE INDEX IF NOT EXISTS ndhost_risk_idx ON netdiag_hosts(risk_level)',
      // 与 JSON 驱动对齐：同一工具下同一 IP 只保留最新一条
      'CREATE UNIQUE INDEX IF NOT EXISTS ndhost_tool_ip_key ON netdiag_hosts(tool, ip)'
    ]
  },
  netdiagFindings: {
    pg: 'netdiag_findings',
    json: 'netdiagFindings',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS netdiag_findings (
      id TEXT PRIMARY KEY,
      run_id TEXT,
      tool TEXT NOT NULL,
      level TEXT NOT NULL DEFAULT 'info',
      category TEXT,
      target TEXT,
      title TEXT,
      detail TEXT,
      advice TEXT,
      evidence JSONB,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS ndfind_run_idx ON netdiag_findings(run_id)',
      'CREATE INDEX IF NOT EXISTS ndfind_tool_idx ON netdiag_findings(tool)',
      'CREATE INDEX IF NOT EXISTS ndfind_level_idx ON netdiag_findings(level)',
      'CREATE INDEX IF NOT EXISTS ndfind_created_idx ON netdiag_findings(created_at DESC)'
    ]
  },
  netdiagLogs: {
    pg: 'netdiag_logs',
    json: 'netdiagLogs',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS netdiag_logs (
      id TEXT PRIMARY KEY,
      run_id TEXT,
      source TEXT,
      host TEXT,
      src_ip TEXT,
      facility TEXT,
      severity INTEGER DEFAULT 6,
      tag TEXT,
      message TEXT,
      rule TEXT,
      level TEXT DEFAULT 'info',
      log_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS ndlog_at_idx ON netdiag_logs(log_at DESC)',
      'CREATE INDEX IF NOT EXISTS ndlog_host_idx ON netdiag_logs(host)',
      'CREATE INDEX IF NOT EXISTS ndlog_level_idx ON netdiag_logs(level)',
      'CREATE INDEX IF NOT EXISTS ndlog_source_idx ON netdiag_logs(source)'
    ]
  },
  netdiagTasks: {
    pg: 'netdiag_tasks',
    json: 'netdiagTasks',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS netdiag_tasks (
      id TEXT PRIMARY KEY,
      name TEXT,
      tool TEXT NOT NULL,
      mode TEXT DEFAULT 'local',
      targets TEXT,
      options JSONB,
      enabled BOOLEAN NOT NULL DEFAULT false,
      status TEXT NOT NULL DEFAULT 'idle',
      interval_sec INTEGER DEFAULT 3600,
      retain_hours INTEGER DEFAULT 168,
      runs INTEGER NOT NULL DEFAULT 0,
      last_started_at TIMESTAMP,
      last_ended_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS ndtask_tool_idx ON netdiag_tasks(tool)',
      'CREATE INDEX IF NOT EXISTS ndtask_status_idx ON netdiag_tasks(status)',
      'CREATE INDEX IF NOT EXISTS ndtask_enabled_idx ON netdiag_tasks(enabled)'
    ]
  },
  /* --- P2 会话库（全流量回溯的核心） --- */
  flowSessions: {
    pg: 'flow_sessions',
    json: 'flowSessions',
    pk: 'id',
    ddl: `CREATE TABLE IF NOT EXISTS flow_sessions (
      id TEXT PRIMARY KEY,
      started_at TIMESTAMP NOT NULL DEFAULT now(),
      src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
      proto TEXT, app_proto TEXT,
      task_id TEXT, file_id TEXT,
      bytes BIGINT DEFAULT 0, pkts INTEGER DEFAULT 0, duration_ms INTEGER DEFAULT 0,
      hint JSONB, tags TEXT[],
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS flow_started_idx ON flow_sessions(started_at DESC)',
      'CREATE INDEX IF NOT EXISTS flow_dstip_idx ON flow_sessions(dst_ip)',
      'CREATE INDEX IF NOT EXISTS flow_app_idx ON flow_sessions(app_proto)',
      'CREATE INDEX IF NOT EXISTS flow_task_idx ON flow_sessions(task_id)'
    ]
  }
};

/**
 * 从 DDL 解析列名——单一数据源就是 DDL，避免手写列清单与建表语句不一致。
 * 解析规则：CREATE TABLE 括号内每行第一段为列名，跳过 PRIMARY KEY / UNIQUE / DEFAULT 等约束行。
 */
function colsOf(t) {
  const body = String(t.ddl).replace(/^[\s\S]*?\(([\s\S]*)\)\s*;?\s*$/, '$1');
  const out = [];
  for (const raw of body.split(',')) {
    const line = raw.trim();
    if (!line || /^(PRIMARY|UNIQUE|FOREIGN|CONSTRAINT|CHECK)/i.test(line)) continue;
    const name = line.split(/\s+/)[0];
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) out.push(name);
  }
  return out;
}

/** camelCase ↔ snake_case */
const snake = (s) => String(s || '').replace(/([A-Z])/g, (m) => '_' + m.toLowerCase());
const camel = (s) => String(s || '').replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());

/** 全部 DDL（建表脚本与迁移共用） */
function allDDL() {
  const out = [];
  for (const t of Object.values(TABLES)) out.push(t.ddl);
  for (const t of Object.values(TABLES)) for (const ix of (t.indexes || [])) out.push(ix);
  return out;
}

/** 表说明（写进 README / 迁移脚本回显） */
const TABLE_COMMENTS = {
  settings: '系统设置（站点/数据源/通知/AI/终端/抓包/测速）',
  users: '用户账号与角色',
  credentials: '设备凭据（加密存储）',
  templates: '命令模板',
  alarms: '告警与事件',
  inventory: '设备补充信息',
  topology: '网络拓扑',
  aiHistory: 'AI 问答历史',
  audit: '审计日志（append-only）',
  speedResults: '测速结果历史',
  recordingMeta: '终端录像元数据（events 仍落盘）',
  captureFiles: '抓包文件索引（pcap 仍落盘）',
  captureTasks: '旁路持续采集任务',
  scanRuns: '扫描执行记录（每次扫描一条）',
  scanHosts: '扫描发现的主机',
  scanPorts: '扫描发现的开放端口',
  scanTasks: '网络扫描任务',
  netdiagRuns: '诊断执行记录（每次诊断一条）',
  netdiagHosts: '诊断命中的主机（摄像头等）',
  netdiagFindings: '诊断发现的问题清单（统一风险口径）',
  netdiagLogs: '日志审计原始日志（Syslog / 本机事件日志）',
  netdiagTasks: '诊断定时任务',
  flowSessions: '会话库（五元组 + 协议识别结果）'
};

/** 数值/布尔字段的序列化辅助：JSON 侧读全量对象，PG 侧按列存取 */
const nowIso = () => new Date().toISOString();
const toTs = (v) => {
  if (!v) return null;
  if (v instanceof Date) return v;
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) {
    // 10 位秒 / 13 位毫秒统一成 ISO
    const ms = n < 1e12 ? n * 1000 : n;
    return new Date(ms).toISOString();
  }
  const d = new Date(String(v).replace(' ', 'T') + (String(v).length === 19 ? 'Z' : ''));
  return isNaN(d.getTime()) ? null : d.toISOString();
};

module.exports = { TABLES, allDDL, TABLE_COMMENTS, colsOf, snake, camel, nowIso, toTs };
