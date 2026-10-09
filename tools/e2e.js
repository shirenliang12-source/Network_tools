/* =========================================================================
   端到端自检：模拟前端真实调用，逐项验证接口契约
   用法：node tools/e2e.js [baseUrl]   （默认 http://127.0.0.1:8787）
   ========================================================================= */
const BASE = (process.argv[2] || 'http://127.0.0.1:8787').replace(/\/+$/, '');
let pass = 0, fail = 0;
const fails = [];

function ok(name, cond, extra) {
  if (cond) { pass++; console.log(`  ✓ ${name}${extra ? ' — ' + extra : ''}`); }
  else { fail++; fails.push(name); console.log(`  ✗ ${name}${extra ? ' — ' + extra : ''}`); }
}

async function call(method, path, body, token) {
  const res = await fetch(BASE + '/api' + path, {
    method,
    headers: Object.assign({
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {})
    }, {}),
    body: (body === undefined || method === 'GET' || method === 'HEAD') ? undefined : JSON.stringify(body)
  });
  const ct = (res.headers.get('content-type') || '');
  const data = ct.includes('application/json') ? await res.json() : { raw: await res.text() };
  return { status: res.status, data };
}

(async () => {
  console.log(`\n=== 端到端接口自检 @ ${BASE} ===\n`);

  /* 1. 登录 */
  console.log('[认证]');
  const lg = await call('POST', '/auth/login', { username: 'admin', password: 'admin@123' });
  const token = lg.data && lg.data.token;
  ok('admin 登录', !!token, token ? 'token 长度 ' + token.length : JSON.stringify(lg.data).slice(0, 120));
  if (!token) { console.log('\n登录失败，后续检查跳过。'); process.exit(1); }
  const me = await call('GET', '/auth/me', null, token);
  ok('获取当前用户', me.data.user && me.data.user.role === 'admin', me.data.user ? me.data.user.username + '/' + me.data.user.roleName : '');

  /* 2. 总览与设备 */
  console.log('\n[总览 / 设备]');
  const ov = await call('GET', '/overview', null, token);
  ok('总览 overview', !!ov.data.overview || !!ov.data.kpi, Object.keys(ov.data).join(','));
  const tr = await call('GET', '/overview/trend?range=24h', null, token);
  ok('趋势 overview/trend', Array.isArray(tr.data.data) || !!tr.data.data, Object.keys(tr.data).join(','));
  const dv = await call('GET', '/devices?page=1&size=20', null, token);
  ok('设备列表', Array.isArray(dv.data.rows) && dv.data.rows.length > 0, `${(dv.data.rows || []).length} 台`);
  const host = (dv.data.rows || [])[0].host;
  const dd = await call('GET', '/devices/' + encodeURIComponent(host), null, token);
  ok('设备详情', !!dd.data.host, dd.data.host ? dd.data.host.name + ' / ' + (dd.data.host.ip || '') : '');
  const pt = await call('GET', '/devices/' + encodeURIComponent(host) + '/ports', null, token);
  ok('端口列表', Array.isArray(pt.data.ports) && pt.data.ports.length > 0, `${(pt.data.ports || []).length} 个端口`);
  const hs = await call('GET', '/devices/' + encodeURIComponent(host) + '/history?kind=traffic&range=24h', null, token);
  ok('历史曲线', !!hs.data.data || !!hs.data.series, Object.keys(hs.data).join(','));
  const inv = await call('POST', '/devices/' + encodeURIComponent(host) + '/inventory', { zone: '核心机房', owner: '自检脚本', rack: 'A01', role: '核心', note: 'e2e' }, token);
  ok('保存设备补充信息', inv.data.ok === true);

  /* 3. 告警 */
  console.log('\n[告警]');
  const al = await call('GET', '/alarms?limit=50', null, token);
  ok('告警列表', Array.isArray(al.data.rows), `${(al.data.rows || []).length} 条 · ${JSON.stringify(al.data.stats || {})}`);
  if ((al.data.rows || []).length) {
    const a0 = al.data.rows[0];
    const ac = await call('POST', '/alarms/' + encodeURIComponent(a0.eventid || a0.id) + '/ack', { message: 'e2e 自检' }, token);
    ok('告警确认', ac.data.ok === true);
    const cl = await call('POST', '/alarms/' + encodeURIComponent(a0.eventid || a0.id) + '/close', {}, token);
    ok('告警关闭', cl.data.ok === true);
  }
  const nw = await call('POST', '/alarms', { host: 'SW-ACC-01', title: 'e2e 自检告警', message: '由自检脚本创建', severity: 'warning' }, token);
  ok('手动创建告警', nw.data.ok === true && !!nw.data.alarm, nw.data.alarm ? nw.data.alarm.title : '');

  /* 4. 终端模板与下发 */
  console.log('\n[终端 / 配置下发]');
  const tp = await call('GET', '/terminal/templates', null, token);
  ok('命令模板列表', Array.isArray(tp.data.rows), `${(tp.data.rows || []).length} 个模板`);
  const ctp = await call('POST', '/terminal/templates', {
    name: 'e2e-自检模板', vendor: '通用', category: '配置', danger: false,
    commands: ['interface GigabitEthernet1/0/9', ' description e2e-test', ' no shutdown']
  }, token);
  ok('新建模板', ctp.data.ok === true && !!ctp.data.template, ctp.data.template ? ctp.data.template.name : '');
  const tplId = ctp.data.template && ctp.data.template.id;
  if (tplId) {
    const utp = await call('PUT', '/terminal/templates/' + tplId, { name: 'e2e-自检模板(改)', vendor: '通用', category: '配置', danger: false, commands: ['show version'] }, token);
    ok('更新模板', utp.data.ok === true);
    const dtp = await call('DELETE', '/terminal/templates/' + tplId, null, token);
    ok('删除模板', dtp.data.ok === true, JSON.stringify(dtp.data).slice(0,80) + ' HTTP' + dtp.status);
  }
  const rec = await call('GET', '/terminal/records?limit=10', null, token);
  ok('会话录像列表', Array.isArray(rec.data.rows), `${(rec.data.rows || []).length} 条`);
  const dep = await call('POST', '/terminal/deploy', { hosts: [host], commands: ['show version', 'show ip int brief'], credentialId: '', dryRun: true }, token);
  ok('下发预检 dryRun', dep.data.ok === true && !!dep.data.preview, `命中 ${(dep.data.preview || {}).dangerHits ? dep.data.preview.dangerHits.length : 0} 条危险规则`);
  const dep2 = await call('POST', '/terminal/deploy', { hosts: [host], commands: ['show version'], credentialId: '', confirmText: 'e2e', reason: '自检', dryRun: false }, token);
  ok('配置下发执行', dep2.data.ok === true && Array.isArray(dep2.data.results), `${((dep2.data.results || []).filter(x => x.ok).length)}/${(dep2.data.results || []).length} 成功`);
  const dpr = await call('GET', '/terminal/deploys?limit=5', null, token);
  ok('下发记录', Array.isArray(dpr.data.rows), `${(dpr.data.rows || []).length} 条`);
  const dz = await call('POST', '/terminal/deploy', { hosts: [host], commands: ['reload'], credentialId: '', dryRun: false }, token);
  ok('危险命令要求二次确认', dz.data.requiresConfirm === true, (dz.data.dangerHits || []).join('/'));

  /* 5. 会话与流量 */
  console.log('\n[会话 / 流量 / 抓包]');
  const loc = await call('GET', '/session/locate?q=10.252.28.101', null, token);
  ok('IP/MAC 定位', loc.data.ok === true && loc.data.hits, `命中 mac ${(loc.data.hits || {}).mac.length} / arp ${(loc.data.hits || {}).arp.length}`);
  const locm = await call('GET', '/session/locate?q=0011.2233.4455', null, token);
  ok('MAC 定位', locm.data.ok === true);
  for (const kind of ['mac', 'arp', 'session']) {
    const t = await call('GET', `/session/table?host=${encodeURIComponent(host)}&kind=${kind}`, null, token);
    ok(`表查询 ${kind}`, Array.isArray(t.data.rows), `${(t.data.rows || []).length} 行`);
  }
  const fl = await call('GET', '/session/flow?host=' + encodeURIComponent(host), null, token);
  ok('会话分析', Array.isArray(fl.data.top), `${(fl.data.top || []).length} 个汇聚对 / 共 ${fl.data.total} 会话`);
  const dg = await call('GET', '/capture/diagnose', null, token);
  ok('抓包诊断', dg.data.ok === true, `引擎 ${dg.data.engine || '未安装'} · ${(dg.data.interfaces || []).length} 个网卡`);
  const cp = await call('POST', '/capture/start', { host, engine: 'device', filter: 'host 10.252.28.40', seconds: 5 }, token);
  ok('设备侧抓包', cp.data.ok === true && Array.isArray(cp.data.commands), `${(cp.data.commands || []).length} 条命令`);
  const cl2 = await call('GET', '/capture/list', null, token);
  ok('抓包列表', Array.isArray(cl2.data.rows), `${(cl2.data.rows || []).length} 个文件`);

  /* 5b. 旁路采集任务（P1） */
  console.log('\n[旁路采集任务]');
  const tk0 = await call('GET', '/capture/tasks', null, token);
  ok('采集任务列表', tk0.data.ok === true && Array.isArray(tk0.data.rows), `引擎 ${tk0.data.env?.engine || '未安装'} · ${(tk0.data.rows || []).length} 个任务`);
  const tkn = await call('POST', '/capture/tasks', { name: 'e2e-旁路自检', kind: 'pcap', iface: '1', bpf: 'port 80', pcapSize: 50, retainHours: 24, intervalSec: 600, seconds: 10, enabled: false }, token);
  const taskId = tkn.data.task && tkn.data.task.id;
  ok('创建采集任务', !!taskId, taskId || (tkn.data.error || ''));
  if (taskId) {
    const tku = await call('PUT', '/capture/tasks/' + taskId, { name: 'e2e-旁路自检(改)', secured: true }, token);
    ok('更新采集任务', tku.data.ok === true && tku.data.task.name === 'e2e-旁路自检(改)', tku.data.task ? tku.data.task.name : '');
    const tkT = await call('POST', '/capture/tasks/' + taskId + '/toggle', { enabled: true }, token);
    ok('启用采集任务', tkT.data.ok === true && tkT.data.task.enabled === true);
    // 本机未装 tshark 时接口会返回明确错误，这属于环境限制而非接口缺陷
    const tkR = await call('POST', '/capture/tasks/' + taskId + '/run', {}, token);
    ok('执行采集任务', tkR.data.ok === true || /未检测到|tshark|dumpcap/.test(tkR.data.error || ''),
      tkR.data.error || `${tkR.data.packets || 0} 包 / ${tkR.data.sessions || 0} 会话`);
    const tkD = await call('DELETE', '/capture/tasks/' + taskId, null, token);
    ok('删除采集任务', tkD.data.ok === true);
  }

  /* 5c. 全流量回溯（P2） */
  console.log('\n[全流量回溯]');
  const fp = await call('GET', '/flow/protocols', null, token);
  ok('协议字典', fp.data.ok === true && fp.data.rows.length > 10, `${fp.data.rows.length} 类协议`);
  const fs1 = await call('GET', '/flow/stats', null, token);
  ok('协议统计', fs1.data.ok === true && Array.isArray(fs1.data.byProto), `总会话 ${fs1.data.total} · ${(fs1.data.byProto || []).length} 类`);
  const fs2 = await call('GET', '/flow/sessions?limit=20', null, token);
  ok('会话检索', fs2.data.ok === true && Array.isArray(fs2.data.rows), `命中 ${fs2.data.total} 条`);
  const fsd = (fs2.data.rows || [])[0];
  if (fsd) {
    const fs3 = await call('GET', '/flow/sessions/' + encodeURIComponent(fsd.id), null, token);
    ok('会话详情', fs3.data.ok === true && !!fs3.data.session, fs3.data.session ? `${fs3.data.session.srcIp}:${fs3.data.session.srcPort} → ${fs3.data.session.dstIp}:${fs3.data.session.dstPort}` : '');
    const fs4 = await call('GET', '/flow/stats?proto=' + encodeURIComponent(fsd.appProto || 'http'), null, token);
    ok('按协议过滤统计', fs4.data.ok === true && typeof fs4.data.total === 'number', `proto=${fsd.appProto} → ${fs4.data.total} 条`);
  }
  const parseCap = await call('GET', '/capture/list?limit=200', null, token);
  const capFile = (parseCap.data.rows || []).find(r => /\.pcap$/i.test(r.id || r.fileId || ''));
  if (capFile) {
    const fpr = await call('POST', '/flow/parse', { file: capFile.id, persist: 0 }, token);
    ok('解析 pcap', fpr.data.ok === true, `${fpr.data.packets || 0} 包 / ${(fpr.data.sessions || []).length} 会话`);
  } else {
    console.log('  · 跳过解析 pcap（抓包库里没有 pcap 文件，先用 tools/pcap-smoke.js 造一个）');
  }

  /* 6. 测速 */
  console.log('\n[内网测速]');
  const sv = await call('GET', '/speed/server', null, token);
  ok('测速服务端信息', sv.data.ok === true, `端口 ${sv.data.port} · iperf3 ${(sv.data.iperf || {}).available ? '可用' : '未安装'}`);
  const hl = await fetch(BASE + '/api/speed/http/download?bytes=2097152', { headers: { Authorization: 'Bearer ' + token } });
  ok('HTTP 下载接口', hl.status === 200 && Number(hl.headers.get('content-length') || 0) > 0, '长度 ' + hl.headers.get('content-length'));
  const hu = await call('POST', '/speed/http/upload', { size: 1024 }, token);
  ok('HTTP 上传接口', hu.status === 200, JSON.stringify(hu.data));
  const sb = await call('POST', '/speed/builtin', { host: '127.0.0.1', port: 5201, seconds: 2, mode: 'download', parallel: 1 }, token);
  ok('内置吞吐引擎', sb.data.ok === true, sb.data.ok ? fmtBps(sb.data.bps) + (sb.data.self ? '（回环自测）' : '') : (sb.data.error || '').slice(0, 80));
  const pr = await call('POST', '/speed/probe', { targets: ['127.0.0.1'], count: 2, intervalMs: 100, timeoutMs: 1200 }, token);
  ok('延迟丢包探测', Array.isArray(pr.data.rows) && pr.data.rows.length === 1, pr.data.rows && pr.data.rows[0] ? `丢包 ${pr.data.rows[0].loss}% avg ${pr.data.rows[0].avg}ms` : '');
  const rs = await call('GET', '/speed/results?limit=5', null, token);
  ok('测速历史', Array.isArray(rs.data.rows), `${(rs.data.rows || []).length} 条`);

  /* 7. 系统管理 */
  console.log('\n[系统管理]');
  const st = await call('GET', '/system/settings', null, token);
  ok('读取设置', st.data.ok === true, Object.keys(st.data.settings || {}).join(','));
  const dt = await call('GET', '/system/datasource/test', null, token);
  ok('数据源测试', dt.data.ok === true, `${dt.data.mode} · ${dt.data.hostCount} 台`);
  const us = await call('GET', '/system/users', null, token);
  ok('用户列表', Array.isArray(us.data.rows), `${(us.data.rows || []).length} 个用户 · 角色 ${(us.data.roles || []).map(r => r.key).join('/')}`);
  const cr = await call('GET', '/system/credentials', null, token);
  ok('凭据列表', Array.isArray(cr.data.rows), `${(cr.data.rows || []).length} 条`);
  const au = await call('GET', '/system/audit?limit=20', null, token);
  ok('审计日志', Array.isArray(au.data.rows), `${(au.data.rows || []).length} 条`);
  const hc = await call('GET', '/system/health', null, token);
  ok('运行状态', hc.data.ok === true, `${hc.data.datasource.mode} · 录像 ${(hc.data.counts || {}).recordings} · 内存 ${hc.data.rssMB}MB`);
  const nt = await call('POST', '/system/notify/test', { channel: '' }, token);
  ok('通知测试（未配置通道应正常返回）', nt.status === 200 || nt.status === 502, `HTTP ${nt.status}`);

  /* 8. AI 与拓扑 */
  console.log('\n[AI / 拓扑]');
  const ai = await call('POST', '/ai/chat', { message: 'SW-ACC-03 的 Gi1/0/17 为什么 down 了？', scope: {} }, token);
  ok('AI 问答', !!ai.data.answer, (ai.data.answer || '').slice(0, 60).replace(/\n/g, ' ') + '…');
  const ah = await call('GET', '/ai/history?limit=5', null, token);
  ok('AI 历史', !!ah.data.history || Array.isArray(ah.data.rows) || Array.isArray(ah.data), Object.keys(ah.data).join(','));
  const tp2 = await call('GET', '/topology', null, token);
  ok('拓扑读取', Array.isArray(tp2.data.nodes) && Array.isArray(tp2.data.links), `${(tp2.data.nodes || []).length} 节点 / ${(tp2.data.links || []).length} 链路${tp2.data.auto ? '（自动生成）' : ''}`);

  /* 8b. 网络扫描（P3） */
  console.log('\n[网络扫描]');
  const scp = await call('GET', '/scan/presets', null, token);
  ok('扫描预设与风险规则', scp.data.ok === true && scp.data.presets.length >= 6,
    `${scp.data.presets.length} 组预设 / ${(scp.data.riskRules || []).length} 条风险规则`);
  const skt = await call('POST', '/scan/tasks', {
    name: 'e2e-扫描自检', targets: '127.0.0.1', ports: '22,80,443,445',
    discoverMode: 'tcp', banner: false, enabled: false
  }, token);
  const skId = skt.data.task && skt.data.task.id;
  ok('创建扫描任务', !!skId, skId || (skt.data.error || ''));
  if (skId) {
    const skr = await call('POST', '/scan/tasks/' + skId + '/run', {}, token);
    ok('执行扫描', skr.data.ok === true, skr.data.error || `存活 ${skr.data.alive} / 端口 ${skr.data.openPorts} / ${skr.data.ms}ms`);
    const skh = await call('GET', '/scan/hosts?limit=5', null, token);
    ok('扫描主机查询', skh.data.ok === true && Array.isArray(skh.data.rows), `${(skh.data.rows || []).length} 台`);
    const skp = await call('GET', '/scan/ports?limit=20', null, token);
    ok('扫描端口查询', skp.data.ok === true && Array.isArray(skp.data.rows), `${(skp.data.rows || []).length} 条`);
    const sks = await call('GET', '/scan/stats', null, token);
    ok('扫描风险统计', sks.data.ok === true && Array.isArray(sks.data.byRisk),
      (sks.data.byRisk || []).map(x => `${x.level}:${x.count}`).join(' ') + ` · 风险端口 ${sks.data.riskPorts}`);
    const skd = await call('DELETE', '/scan/tasks/' + skId, null, token);
    ok('删除扫描任务', skd.data.ok === true, `HTTP ${skd.status}`);
  }

  /* 9. 权限校验 */
  /* 8c. 网络诊断工具箱（P4） */
  console.log('\n[诊断工具箱]');
  const dgT = await call('GET', '/diag/tools', null, token);
  const dgToolList = dgT.data.tools || [];
  ok('诊断工具清单', dgToolList.length === 6, dgToolList.map(t => t.name).join('/'));
  ok('风险等级字典', !!dgT.data.levels && !!dgT.data.levelOrder, `${Object.keys(dgT.data.levels || {}).length} 级`);
  ok('审计规则库下发', (dgT.data.rules || []).length >= 12, `${(dgT.data.rules || []).length} 条`);
  ok('环境探测标记', dgT.data.env && typeof dgT.data.env.tshark === 'boolean',
    `tshark ${dgT.data.env && dgT.data.env.tshark} · 平台 ${dgT.data.env && dgT.data.env.platform}`);

  const dgSc = await call('GET', '/diag/scope', null, token);
  ok('本机网段预览', (dgSc.data.targets || []).length > 0 && !!dgSc.data.note,
    `${(dgSc.data.nets || []).map(n => n.cidr).join('/')} · ${(dgSc.data.targets || []).length} 个地址`);
  const dgSc1 = await call('GET', '/diag/scope?mode=range&targets=10.252.28.0/30', null, token);
  ok('指定网段展开', (dgSc1.data.targets || []).length === 4, `${(dgSc1.data.targets || []).length} 个地址`);
  const dgSc2 = await call('GET', '/diag/scope?mode=range', null, token);
  ok('指定网段缺目标应报错', dgSc2.status === 400, 'HTTP ' + dgSc2.status);

  const dgSelfIp = ((dgSc.data.nets || [])[0] || {}).address || '';
  const dgSp = await call('POST', '/diag/run', { tool: 'speedtest', mode: 'local', seconds: 2, parallel: 2 }, token);
  ok('外网测速可跑完', dgSp.data.ok === true, `${dgSp.data.ms}ms · 评分 ${dgSp.data.score} · ${dgSp.data.levelText}`);
  ok('测速带回指标或问题', !!dgSp.data.summary || (dgSp.data.findings || []).length > 0,
    JSON.stringify(dgSp.data.summary || dgSp.data.findings).slice(0, 90));

  const dgLa = await call('POST', '/diag/run', { tool: 'logaudit', mode: 'local', source: 'local', limit: 100 }, token);
  ok('日志审计可跑完', dgLa.data.ok === true, `${dgLa.data.ms}ms · ${(dgLa.data.findings || []).length} 条问题`);

  const dgCam = await call('POST', '/diag/run', { tool: 'camera', mode: 'range', targets: dgSelfIp }, token);
  ok('摄像头扫描单目标可跑完', dgCam.data.ok === true,
    `${dgCam.data.targets} 目标 · ${(dgCam.data.hosts || []).length} 台 · ${(dgCam.data.findings || []).length} 条问题`);

  const dgBad = await call('POST', '/diag/run', { tool: 'nope' }, token);
  ok('未知工具被拒绝', dgBad.status === 400, 'HTTP ' + dgBad.status);

  ok('诊断记录入库', ((await call('GET', '/diag/runs?limit=5', null, token)).data.rows || []).length > 0);
  const dgH = await call('GET', '/diag/hosts?tool=camera&limit=50', null, token);
  ok('诊断主机可查', Array.isArray(dgH.data.rows), `${(dgH.data.rows || []).length} 台`);
  const dgF = await call('GET', '/diag/findings?limit=50', null, token);
  ok('问题清单可查', Array.isArray(dgF.data.rows), `${(dgF.data.rows || []).length} 条`);
  const dgFs = await call('GET', '/diag/findings/stats', null, token);
  ok('问题统计可算', typeof dgFs.data.total === 'number', `共 ${dgFs.data.total} 条 · 待修 ${dgFs.data.needFix}`);
  const dgL = await call('GET', '/diag/logs?limit=20', null, token);
  ok('审计日志可查', Array.isArray(dgL.data.rows), `${(dgL.data.rows || []).length} 条`);
  const dgLs = await call('GET', '/diag/logs/stats?days=1', null, token);
  ok('日志统计可算', typeof dgLs.data.total === 'number', `共 ${dgLs.data.total} 条`);

  // 注意：Response.text() 会按规范吞掉 BOM，校验 BOM 必须看原始字节
  const dgExp = await fetch(BASE + '/api/diag/export?runId=' + encodeURIComponent(dgSp.data.runId || ''), { headers: { Authorization: 'Bearer ' + token } });
  const dgExpBuf = Buffer.from(await dgExp.arrayBuffer());
  ok('问题清单可导出 CSV',
    dgExpBuf[0] === 0xEF && dgExpBuf[1] === 0xBB && dgExpBuf[2] === 0xBF && dgExpBuf.toString('utf8').includes('等级'),
    `${dgExpBuf.length} 字节 · 有 BOM ${dgExpBuf[0] === 0xEF}`);

  const dgSl = await call('GET', '/diag/syslog', null, token);
  ok('Syslog 状态可读', !!dgSl.data.status && !!dgSl.data.config, `端口 ${(dgSl.data.config || {}).port} · 已收 ${(dgSl.data.status || {}).received} 条`);

  const dgTk = await call('POST', '/diag/tasks', { name: 'e2e-诊断自检', tool: 'speedtest', mode: 'local', intervalSec: 600, enabled: false }, token);
  const dgTaskId = dgTk.data.task && dgTk.data.task.id;
  ok('创建诊断任务', !!dgTaskId, dgTaskId || JSON.stringify(dgTk.data).slice(0, 80));
  if (dgTaskId) {
    const dgTu = await call('PUT', '/diag/tasks/' + dgTaskId, { name: 'e2e-诊断自检(改)' }, token);
    ok('修改诊断任务', dgTu.status === 200, (dgTu.data.task || {}).name);
    const dgTt = await call('POST', '/diag/tasks/' + dgTaskId + '/toggle', { enabled: true }, token);
    ok('启用诊断任务', dgTt.data.task && dgTt.data.task.enabled === true);
    const dgTr = await call('POST', '/diag/tasks/' + dgTaskId + '/run', { seconds: 1, parallel: 1 }, token);
    ok('执行诊断任务', dgTr.data.ok === true && !!dgTr.data.runId, `${dgTr.data.ms}ms · ${dgTr.data.score} 分`);
    const dgTd = await call('DELETE', '/diag/tasks/' + dgTaskId, null, token);
    ok('删除诊断任务', dgTd.status === 200, 'HTTP ' + dgTd.status);
  }

  // 权限边界：只读角色（无 scan）不能发起主动探测，但可以读取结果
  const dgMk = await call('POST', '/system/users', { username: 'e2e-diag-ro', password: 'e2e@diag#2026', displayName: '自检只读账号', role: 'audit' }, token);
  const dgMkU = dgMk.data.user;
  if (dgMkU) {
    const dgRl = await call('POST', '/auth/login', { username: 'e2e-diag-ro', password: 'e2e@diag#2026' });
    const dgRo = dgRl.data && dgRl.data.token;
    ok('只读角色可登录', !!dgRo);
    if (dgRo) {
      const dgD1 = await call('POST', '/diag/run', { tool: 'speedtest', mode: 'local' }, dgRo);
      ok('只读角色不可执行诊断', dgD1.status === 403, 'HTTP ' + dgD1.status);
      const dgD2 = await call('GET', '/diag/hosts?limit=5', null, dgRo);
      ok('只读角色可读诊断结果', dgD2.status === 200, `${(dgD2.data.rows || []).length} 台`);
    }
    await call('DELETE', '/system/users/' + dgMkU.id, null, token);
  }

  console.log('\n[权限]');
  const lg2 = await call('POST', '/auth/login', { username: 'audit', password: 'audit@123' });
  const t2 = lg2.data && lg2.data.token;
  if (t2) {
    const p = await call('POST', '/terminal/deploy', { hosts: [host], commands: ['show version'] }, t2);
    ok('审计角色不可下发配置', p.status === 403, 'HTTP ' + p.status);
    const u = await call('POST', '/system/users', { username: 'a1', password: 'a123456', role: 'ops' }, t2);
    ok('审计角色不可建用户', u.status === 403, 'HTTP ' + u.status);
    const v = await call('GET', '/devices', null, t2);
    ok('审计角色可读设备', v.status === 200, `${(v.data.rows || []).length} 台`);
    const t = await call('GET', '/terminal/templates', null, t2);
    ok('审计角色可读模板', t.status === 200, `${(t.data.rows || []).length} 个模板`);
    const a = await call('GET', '/system/audit?limit=5', null, t2);
    ok('审计角色可读日志', a.status === 200, `${(a.data.rows || []).length} 条`);
  } else ok('audit 登录', false);

  console.log(`\n=== 自检完成：通过 ${pass} 项，失败 ${fail} 项 ===`);
  if (fails.length) console.log('失败项：\n  - ' + fails.join('\n  - '));
  process.exit(fail ? 1 : 0);
})();

function fmtBps(v) {
  v = Number(v) || 0;
  if (v >= 1e9) return (v / 1e9).toFixed(2) + ' Gbps';
  if (v >= 1e6) return (v / 1e6).toFixed(2) + ' Mbps';
  return Math.round(v) + ' bps';
}
