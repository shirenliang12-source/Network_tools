/** 后端自检脚本：node tools/smoke.js */
const netutil = require('../server/netutil');
const store = require('../server/store');
const db = require('../server/db');
const term = require('../server/term');
const auth = require('../server/auth');
const ds = require('../server/datasource');
const { ruleEngine, buildContext } = require('../server/api');

(async () => {
  const log = (...a) => console.log('  ', ...a);
  console.log('\n=== netops-console 后端自检 ===\n');

  /* 数据访问层：有 DATABASE_URL 走 PostgreSQL，否则走 data/db.json */
  await db.init();
  const st = await db.status();
  log('存储驱动:', st.driver, '|', st.url, `| 表 ${st.tables} 张`);
  await auth.ensureSeed();
  const users = await db.usersList();
  log('用户数:', users.length, '|', users.map(u => `${u.username}(${u.role})`).join(' '));

  const r = auth.login('admin', 'admin@123', '127.0.0.1');
  log('登录:', r ? 'OK' : 'FAIL', '| token 校验:', auth.verifyToken(r.token) ? 'OK' : 'FAIL');
  log('密码校验(错误密码应 FAIL):', auth.login('admin', 'wrong', '127.0.0.1') ? 'FAIL' : 'OK');

  const p = ds.getProvider();
  log('数据源:', p.name);

  const hosts = await p.hosts();
  log('设备数:', hosts.length);
  console.log(hosts.slice(0, 5).map(h => `      - ${h.host.padEnd(12)} ${h.ip.padEnd(14)} ${h.vendor}/${h.model} 健康度${ds.healthScore(h)}`).join('\n'));

  const ports = (await p.ports('SW-CORE-01')).ports;
  log('SW-CORE-01 端口数:', ports.length, '| 首个端口:', ports[0].name, ds.fmtBps(ports[0].inBps));

  const hist = await p.history('SW-CORE-01', 'traffic', store.nowSec() - 3600, store.nowSec(), 20);
  log('流量曲线点数:', hist.length, '| 示例:', JSON.stringify(hist[0]));

  const pb = await p.problems();
  log('告警数:', pb.length, '|', pb[0].severity, pb[0].title);

  const pg = await netutil.ping('127.0.0.1', { count: 2, intervalMs: 200 });
  log('ICMP 回环:', `${pg.recv}/${pg.sent}`, '丢包', pg.loss + '%', 'avg', pg.avg + 'ms');

  const tcpc = await netutil.tcpConnect('127.0.0.1', 8787, 1000);
  log('TCP 探测 127.0.0.1:8787:', tcpc.ok ? 'OK' : '未监听（服务未启动时正常）', tcpc.error || '');

  const sim = term.makeSimulator('SW-ACC-04');
  log('CLI 模拟器 display version 输出长度:', sim.exec('display version').length);
  log('CLI 模拟器 display mac-address 输出长度:', sim.exec('display mac-address').length);
  log('危险命令识别 reload:', term.checkDanger('reload') || '未识别');
  log('危险命令识别 show version（应为空）:', term.checkDanger('show version') || '(空) OK');

  log('MAC 表解析:', netutil.parseMacTable('  10    0011.2233.4455   DYNAMIC  Gi1/0/12').length, '条');
  log('ARP 表解析:', netutil.parseArp('Internet  10.252.28.40      3   0011.2233.4455   ARPA   Vlan10').length, '条');
  log('会话表解析:', netutil.parseSessions('proto=6 src=1.1.1.1 dst=2.2.2.2 sport=1234 dport=80 bytes=100').length, '条');

  const ctx = await buildContext({});
  log('AI 上下文长度:', ctx.length, '字符');
  const ans = ruleEngine('SW-ACC-03 的 Gi1/0/17 为什么 down 了', ctx);
  log('规则引擎回答长度:', ans.length, '字符');

  const dep = await term.deploy({ hosts: ['SW-ACC-04'], commands: ['display version'], user: 'admin', ip: '127.0.0.1' });
  log('演示配置下发:', dep.results[0].ok ? 'OK' : 'FAIL', '输出长度', dep.results[0].output.length);

  const danger = await term.deploy({ hosts: ['SW-ACC-04'], commands: ['reload'], user: 'admin', ip: '127.0.0.1' });
  log('危险命令下发拦截:', danger.requiresConfirm ? 'OK（要求二次确认）' : 'FAIL');

  console.log('\n=== 自检完成 ===\n');
  process.exit(0);
})().catch(e => { console.error('自检失败:', e); process.exit(1); });
