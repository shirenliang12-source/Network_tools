/* =========================================================================
 * 网络运维工具箱：NetToolbox 移植的 12 个跨平台工具前端页面
 * 重定向链追踪 / HTTP 可用性 / SSL 证书 / Whois / 公网出口 / Ping 详版 /
 * MTR / DNS 诊断 / 服务与 OS 指纹 / 网卡流量 / NTP / 子网计算 / 网络唤醒
 * ========================================================================= */
(function () {
  const { reactive, ref, computed } = Vue;
  const NC = window.NC;
  const { api, fmt, icon: ic0, toast, state: S } = NC;
  const ic = (n, s) => ic0(n, s);

  /* ----------------------------- 工具清单 ----------------------------- */
  const CATS = ['Web / HTTP', '域名 / DNS', '主机探测', '扫描发现', '安全检测', '主机信息', '无线分析', '网络体检', '会话测试', '主机与网络', '网络计算', '电源管理'];
  const TOOLS = [
    { key: 'redirect', name: '重定向链追踪', cat: 'Web / HTTP', icon: 'share', api: 'redirect', perm: 'auth',
      desc: '逐跳追踪 30x 跳转，识别 HTTPS 降级、跨域、跨端口、HSTS 与重定向环路', example: 'http://www.baidu.com' },
    { key: 'httpcheck', name: 'HTTP 可用性', cat: 'Web / HTTP', icon: 'activity', api: 'httpcheck', perm: 'auth',
      desc: '检测站点状态码、耗时、标题、关键字与 TLS 证书剩余天数', example: 'https://www.baidu.com' },
    { key: 'sslcert', name: 'SSL 证书检测', cat: 'Web / HTTP', icon: 'shield', api: 'sslcert', perm: 'auth',
      desc: '抓取对端 X.509 证书，检查有效期、自签名、链校验与加密套件', example: 'www.baidu.com' },
    { key: 'whois', name: 'Whois 归属查询', cat: '域名 / DNS', icon: 'search', api: 'whois', perm: 'auth',
      desc: '优先 RDAP、回落 whois 协议，查询域名/IP 的注册与归属信息', example: 'baidu.com' },
    { key: 'publicip', name: '公网出口 IP', cat: '域名 / DNS', icon: 'globe', api: 'publicip', perm: 'auth',
      desc: '查询本机经 NAT 后的公网出口地址与 ASN / 运营商', example: '' },
    { key: 'dns', name: 'DNS 诊断', cat: '域名 / DNS', icon: 'globe', api: 'dns', perm: 'auth',
      desc: '本机与多家公共 DNS 多类型对比，发现解析不一致与疑似劫持', example: 'baidu.com' },
    { key: 'ping', name: 'Ping 详版', cat: '主机探测', icon: 'wifi', api: 'ping', perm: 'scan',
      desc: 'ICMP 探测并补充 TTL，给出丢包、抖动与健康评分', example: '8.8.8.8' },
    { key: 'mtr', name: 'MTR 路由追踪', cat: '主机探测', icon: 'share', api: 'mtr', perm: 'scan',
      desc: '多轮 tracert/traceroute 采样，统计每跳延迟、抖动与丢包', example: '8.8.8.8' },
    { key: 'fingerprint', name: '服务 / OS 指纹', cat: '主机探测', icon: 'cpu', api: 'fingerprint', perm: 'scan',
      desc: '并发 TCP/Banner/TLS 探测，推断操作系统、设备类型与高危端口', example: '127.0.0.1' },
    { key: 'ifstat', name: '网卡实时流量', cat: '主机与网络', icon: 'activity', api: 'ifstat', perm: 'auth',
      desc: '差分网卡计数器，计算各适配器收/发速率与峰值', example: '' },
    { key: 'ntp', name: 'NTP 时间同步', cat: '主机与网络', icon: 'clock', api: 'ntp', perm: 'auth',
      desc: '向多个时间源发 UDP 123 报文，计算本机时钟偏差与延迟', example: '' },
    { key: 'subnet', name: '子网计算器', cat: '网络计算', icon: 'layers', api: 'subnet', perm: 'auth',
      desc: 'CIDR 解析、VLSM 划分与同网段判定（纯计算，零依赖）', example: '192.168.10.0/24' },
    { key: 'wol', name: '网络唤醒 WoL', cat: '电源管理', icon: 'power', api: 'wol', perm: 'scan',
      desc: '构造 Magic Packet 经 UDP 广播，远程唤醒指定 MAC', example: '00:11:22:33:44:55' },

    { key: 'portscan', name: '端口扫描', cat: '扫描发现', icon: 'server', api: 'portscan', perm: 'scan',
      desc: 'TCP 全连接扫描 + Banner/服务/产品识别，定位开放端口', example: '127.0.0.1' },
    { key: 'discovery', name: '主机发现', cat: '扫描发现', icon: 'search', api: 'discovery', perm: 'scan',
      desc: 'ARP 缓存 + ICMP Ping 扫 + TCP 探测，发现在线主机与 MAC/厂商', example: 'auto' },
    { key: 'topology', name: '拓扑发现', cat: '扫描发现', icon: 'share', api: 'topology', perm: 'scan',
      desc: '网段发现 + 厂商/主机名 enrichment，输出拓扑节点与边', example: 'auto' },
    { key: 'camera', name: '摄像头探测', cat: '扫描发现', icon: 'activity', api: 'camera', perm: 'scan',
      desc: '扫描监控/摄像头设备端口与品牌（海康/大华/Axis 等）', example: 'auto' },
    { key: 'security', name: '安全自检', cat: '安全检测', icon: 'shield', api: 'security', perm: 'scan',
      desc: '暴露面高危端口风险扫描与综合评分（仅体检，无入侵动作）', example: '192.168.1.0/24' },
    { key: 'ipconflict', name: 'IP 冲突检测', cat: '安全检测', icon: 'alert', api: 'ipconflict', perm: 'scan',
      desc: 'ARP 缓存比对 + 主动重探，发现同一 IP 对应多个 MAC 的冲突', example: 'auto' },
    { key: 'hostname', name: '主机名解析', cat: '主机信息', icon: 'globe', api: 'hostname', perm: 'scan',
      desc: '对 IP 做反向 DNS 解析，获取主机名', example: '8.8.8.8' },
    { key: 'vendor', name: 'MAC 厂商查询', cat: '主机信息', icon: 'cpu', api: 'vendor', perm: 'auth',
      desc: '根据 MAC 地址前 3 字节 OUI 查询网卡厂商（内置 1494 条）', example: '00:0c:29:ab:cd:ef' },
    { key: 'wifi', name: '无线扫描', cat: '无线分析', icon: 'wifi', api: 'wifi', perm: 'scan',
      desc: '通过 netsh wlan 扫描周边 Wi-Fi（SSID/BSSID/信号/信道/加密）', example: '' },
    { key: 'dhcp', name: 'DHCP 信息', cat: '网络体检', icon: 'layers', api: 'dhcp', perm: 'auth',
      desc: '解析本机各网卡 DHCP 服务器、租约与网关/DNS 配置', example: '' },
    { key: 'netcheck', name: '网络体检', cat: '网络体检', icon: 'activity', api: 'netcheck', perm: 'auth',
      desc: '7 维健康评分：网卡/网关/DNS/外网/延迟/速率/环路', example: '' },
    { key: 'session', name: '会话承压测试', cat: '会话测试', icon: 'clock', api: 'session', perm: 'scan',
      desc: '评估目标端口 TCP 连接时延、成功率与最大并发承压', example: '127.0.0.1' }
  ];
  const toolMap = {};
  TOOLS.forEach(t => toolMap[t.key] = t);
  const toolsByCat = (g) => TOOLS.filter(t => t.cat === g);

  /* ------------------------------ 表单状态 ------------------------------ */
  const form = reactive({
    url: 'http://www.baidu.com', hcMethod: 'GET', hcFollow: true, hcKeyword: '', hcCode: '', hcTimeout: 8000,
    host: '127.0.0.1', scPort: 443,
    query: 'baidu.com', domain: 'baidu.com',
    dnsTypes: 'A,AAAA,CNAME,MX,NS,TXT', dnsServers: '',
    pingCount: 4, pingTimeout: 1500,
    mtrMaxHops: 30, mtrRounds: 2, mtrProbeTimeout: 1000,
    fpFull: false, fpPorts: '', fpTimeout: 1200,
    ifInterval: 1000,
    ntpServers: '',
    subMode: 'analyze', subSpec: '192.168.10.0/24', subNeeds: '50,20,10',
    subA: '192.168.1.10', subB: '192.168.1.20', subPrefix: 24,
    wolMacs: '', wolPort: 9, wolBroadcast: '255.255.255.255',

    // 第二波能力
    psHost: '127.0.0.1', psPorts: '', psTimeout: 500, psBanner: true,
    discTarget: 'auto', discMethods: 'arp,ping,tcp', discTimeout: 500, discThreads: 64,
    topoTarget: 'auto',
    camTarget: 'auto', camTimeout: 800,
    secTarget: '', secTimeout: 800, secPorts: '',
    ipcTarget: 'auto', ipcTimeout: 600,
    hostIp: '8.8.8.8', hostTimeout: 600,
    vendMac: '00:0c:29:ab:cd:ef',
    sessHost: '127.0.0.1', sessPort: 80, sessCount: 20, sessTimeout: 2000
  });

  const current = ref('redirect');
  const result = ref(null);
  const err = ref('');
  const running = ref(false);
  const q = ref('');
  const totalTools = TOOLS.length;

  /* 按关键词过滤工具（匹配名称 / 用途 / 分类），并丢弃空分组 */
  const filteredGroups = computed(() => {
    const kw = q.value.trim().toLowerCase();
    return CATS.map(g => ({
      g,
      items: TOOLS.filter(t => t.cat === g && (!kw
        || t.name.toLowerCase().includes(kw)
        || t.desc.toLowerCase().includes(kw)
        || g.toLowerCase().includes(kw)))
    })).filter(x => x.items.length);
  });

  const cur = computed(() => toolMap[current.value]);
  const r = computed(() => result.value);
  const canScan = computed(() => {
    const p = S.user && S.user.perms;
    if (!Array.isArray(p)) return true;
    return p.includes('*') || p.includes('scan');
  });

  function num(v, def) { const n = Number(v); return Number.isFinite(n) ? n : def; }
  function select(t) { current.value = t.key; result.value = null; err.value = ''; }

  /* 按工具组装请求体（对齐 server/toolbox.js 的参数命名） */
  function buildBody(k) {
    switch (k) {
      case 'redirect': return { url: form.url, opts: { maxHops: num(form.mtrMaxHops, 10), timeoutMs: num(form.hcTimeout, 8000) } };
      case 'httpcheck': return { url: form.url, opts: { method: form.hcMethod, followRedirects: form.hcFollow, keyword: form.hcKeyword || undefined, expectedCode: form.hcCode ? num(form.hcCode) : null, timeoutMs: num(form.hcTimeout, 8000) } };
      case 'sslcert': return { host: form.host, opts: { port: num(form.scPort, 443), timeoutMs: num(form.hcTimeout, 8000) } };
      case 'whois': return { query: form.query, opts: { timeoutMs: num(form.hcTimeout, 8000) } };
      case 'publicip': return {};
      case 'ping': return { host: form.host, opts: { count: num(form.pingCount, 4), timeoutMs: num(form.pingTimeout, 1500) } };
      case 'mtr': return { host: form.host, opts: { maxHops: num(form.mtrMaxHops, 30), rounds: num(form.mtrRounds, 2), probeTimeoutMs: num(form.mtrProbeTimeout, 1000) } };
      case 'dns': return { domain: form.domain, opts: { types: form.dnsTypes.split(/[,\s]+/).map(s => s.toUpperCase()).filter(Boolean), servers: form.dnsServers.split(/[,\s]+/).filter(Boolean) } };
      case 'fingerprint': return { host: form.host, opts: { full: form.fpFull, ports: form.fpPorts ? form.fpPorts.split(/[,\s]+/).map(Number).filter(n => n > 0) : [], timeoutMs: num(form.fpTimeout, 1200) } };
      case 'ifstat': return { opts: { intervalMs: num(form.ifInterval, 1000) } };
      case 'ntp': return { opts: { servers: form.ntpServers.split(/[,\s]+/).filter(Boolean) } };
      case 'subnet':
        if (form.subMode === 'vlsm') return { mode: 'vlsm', cidr: form.subSpec, needs: form.subNeeds.split(/[,\s]+/).map(Number).filter(n => !isNaN(n)) };
        if (form.subMode === 'same') return { mode: 'same', a: form.subA, b: form.subB, prefix: form.subPrefix ? num(form.subPrefix) : undefined };
        return { mode: 'analyze', spec: form.subSpec };
      case 'wol': return { macs: form.wolMacs, opts: { port: num(form.wolPort, 9), broadcast: form.wolBroadcast || '255.255.255.255' } };

      case 'portscan': return { host: form.psHost, ports: form.psPorts ? form.psPorts.split(/[,\s]+/).map(Number).filter(n => n > 0) : [], timeout: num(form.psTimeout, 500), banner: form.psBanner };
      case 'discovery': return { target: form.discTarget, methods: form.discMethods, timeout: num(form.discTimeout, 500), threads: num(form.discThreads, 64) };
      case 'topology': return { target: form.topoTarget };
      case 'camera': return { target: form.camTarget, timeout: num(form.camTimeout, 800) };
      case 'security': return { target: form.secTarget, timeout: num(form.secTimeout, 800), ports: form.secPorts || undefined };
      case 'ipconflict': return { target: form.ipcTarget, timeout: num(form.ipcTimeout, 600) };
      case 'hostname': return { ip: form.hostIp, timeout: num(form.hostTimeout, 600) };
      case 'vendor': return { mac: form.vendMac };
      case 'wifi': return {};
      case 'dhcp': return {};
      case 'netcheck': return {};
      case 'session': return { host: form.sessHost, port: num(form.sessPort, 80), count: num(form.sessCount, 20), timeout: num(form.sessTimeout, 2000), concurrency: true };
    }
    return {};
  }

  async function run() {
    const k = current.value, t = toolMap[k];
    if (t.perm === 'scan' && !canScan.value) { toast('当前账号无 scan 权限', 'err'); return; }
    running.value = true; err.value = ''; result.value = null;
    try {
      const rj = await api.post('/toolbox/' + t.api, buildBody(k));
      result.value = rj;
      toast('执行完成', 'ok');
    } catch (e) {
      err.value = e.message || '执行失败';
      toast(err.value, 'err');
    } finally { running.value = false; }
  }

  /* 严重的颜色映射（warnings / risks / notes 的 level 字段） */
  function levelColor(l) {
    return ({ ok: '#16a34a', low: '#0ea5e9', medium: '#d97706', high: '#dc2626', critical: '#dc2626',
      warn: '#d97706', danger: '#dc2626', info: '#64748b' })[l] || '#64748b';
  }
  function badgeColor(l) {
    const c = levelColor(l);
    return { background: c + '22', color: c, border: '1px solid ' + c + '55' };
  }
  function dleft(t) { return (t || '').replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace('Z', ''); }

  /* ifstat 折线图 */
  const chartOpt = computed(() => {
    if (current.value !== 'ifstat' || !result.value || !result.value.adapters || !result.value.adapters.length) return null;
    const a = result.value.adapters[0];
    const labels = result.value.labels || a.history.map((_, i) => i + 1);
    return {
      textStyle: { fontFamily: 'var(--sans), sans-serif' },
      grid: { left: 8, right: 14, top: 30, bottom: 4, containLabel: true },
      tooltip: { trigger: 'axis' },
      legend: { data: ['RX', 'TX'], top: 0, textStyle: { color: 'var(--text-3)' } },
      xAxis: { type: 'category', data: labels, axisLabel: { color: 'var(--text-3)', fontSize: 11 } },
      yAxis: { type: 'value', axisLabel: { color: 'var(--text-3)', fontSize: 11, formatter: v => fmt.bps(v) }, splitLine: { lineStyle: { color: 'var(--border)' } } },
      series: [
        { name: 'RX', type: 'line', smooth: true, areaStyle: { opacity: 0.12 }, symbol: 'none', data: a.history.map(h => h.rx), itemStyle: { color: '#2563eb' } },
        { name: 'TX', type: 'line', smooth: true, areaStyle: { opacity: 0.12 }, symbol: 'none', data: a.history.map(h => h.tx), itemStyle: { color: '#22d3ee' } }
      ]
    };
  });

  const ToolboxPage = {
    components: { NcChart: NC.components.NcChart },
    template: `
<div class="tb">
  <aside class="tb-side">
    <div class="tb-side-h">
      <span class="tb-side-ic" v-html="ic('toolbox',18)"></span>
      <div>
        <div class="tb-side-t">网络运维工具箱</div>
        <div class="tb-side-s">{{ totalTools }} 个工具 · {{ cats.length }} 个分类</div>
      </div>
    </div>
    <div class="tb-search">
      <span v-html="ic('search',14)"></span>
      <input v-model.trim="q" placeholder="搜索工具名称 / 用途…">
    </div>
    <div class="tb-list">
      <div v-for="grp in filteredGroups" :key="grp.g" class="tb-group">
        <div class="tb-group-t"><span>{{ grp.g }}</span><span class="tb-group-n">{{ grp.items.length }}</span></div>
        <div v-for="t in grp.items" :key="t.key" class="tb-item" :class="{on: current===t.key}" @click="select(t)">
          <span class="tb-item-ic" v-html="ic(t.icon,15)"></span>
          <span class="tb-item-t">{{ t.name }}</span>
          <span v-if="t.perm==='scan'" class="tb-lock">scan</span>
        </div>
      </div>
      <div v-if="!filteredGroups.length" class="tb-none">未找到匹配的工具</div>
    </div>
  </aside>

  <section class="tb-main">
    <div class="tb-head">
      <span v-html="ic(cur.icon,22)" class="tb-head-ic"></span>
      <div>
        <div class="tb-head-t">{{ cur.name }}</div>
        <div class="tb-head-d">{{ cur.desc }}</div>
      </div>
      <div class="grow"></div>
      <span class="tb-perm" :style="cur.perm==='scan' ? {background:'rgba(217,119,6,.15)',color:'#d97706'} : {background:'rgba(37,99,235,.12)',color:'#2563eb'}">
        {{ cur.perm==='scan' ? '探测类 · 需 scan 权限' : '只读 · 登录即可用' }}
      </span>
    </div>

    <div class="card">
      <div class="card-body">
        <!-- ============ 重定向链追踪 ============ -->
        <div v-if="current==='redirect'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:320px"><label>起始 URL</label>
            <input class="inp" v-model.trim="form.url" placeholder="http://www.baidu.com"></div>
          <div class="field" style="width:130px"><label>最大跳数</label>
            <input class="inp" type="number" v-model.number="form.mtrMaxHops"></div>
          <div class="field" style="width:140px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.hcTimeout"></div>
        </div>

        <!-- ============ HTTP 可用性 ============ -->
        <div v-else-if="current==='httpcheck'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:300px"><label>目标 URL</label>
            <input class="inp" v-model.trim="form.url" placeholder="https://www.baidu.com"></div>
          <div class="field" style="width:120px"><label>方法</label>
            <select class="inp" v-model="form.hcMethod"><option>GET</option><option>HEAD</option></select></div>
          <div class="field" style="width:120px"><label>预期状态码</label>
            <input class="inp" v-model.trim="form.hcCode" placeholder="留空不限"></div>
          <div class="field" style="width:150px"><label>关键字(仅GET)</label>
            <input class="inp" v-model.trim="form.hcKeyword" placeholder="可选"></div>
          <div class="field" style="width:110px"><label>跟随跳转</label>
            <label class="checkbox"><input type="checkbox" v-model="form.hcFollow"> 是</label></div>
        </div>

        <!-- ============ SSL 证书 ============ -->
        <div v-else-if="current==='sslcert'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:280px"><label>主机名或 IP</label>
            <input class="inp" v-model.trim="form.host" placeholder="www.baidu.com"></div>
          <div class="field" style="width:120px"><label>端口</label>
            <input class="inp" type="number" v-model.number="form.scPort"></div>
        </div>

        <!-- ============ Whois ============ -->
        <div v-else-if="current==='whois'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:280px"><label>域名或 IP</label>
            <input class="inp" v-model.trim="form.query" placeholder="baidu.com"></div>
        </div>

        <!-- ============ 公网出口 ============ -->
        <div v-else-if="current==='publicip'" class="muted fs12">无需参数，直接执行即可查询本机公网出口地址。</div>

        <!-- ============ DNS 诊断 ============ -->
        <div v-else-if="current==='dns'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>域名</label>
            <input class="inp" v-model.trim="form.domain" placeholder="baidu.com"></div>
          <div class="field" style="flex:1;min-width:240px"><label>解析类型(逗号分隔)</label>
            <input class="inp" v-model.trim="form.dnsTypes"></div>
          <div class="field" style="flex:1;min-width:240px"><label>对比 DNS(留空=全部公共)</label>
            <input class="inp" v-model.trim="form.dnsServers" placeholder="223.5.5.5,8.8.8.8"></div>
        </div>

        <!-- ============ Ping ============ -->
        <div v-else-if="current==='ping'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标主机 / IP</label>
            <input class="inp" v-model.trim="form.host" placeholder="8.8.8.8"></div>
          <div class="field" style="width:110px"><label>次数</label>
            <input class="inp" type="number" v-model.number="form.pingCount"></div>
          <div class="field" style="width:120px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.pingTimeout"></div>
        </div>

        <!-- ============ MTR ============ -->
        <div v-else-if="current==='mtr'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标主机 / IP</label>
            <input class="inp" v-model.trim="form.host" placeholder="8.8.8.8"></div>
          <div class="field" style="width:110px"><label>最大跳数</label>
            <input class="inp" type="number" v-model.number="form.mtrMaxHops"></div>
          <div class="field" style="width:100px"><label>轮数</label>
            <input class="inp" type="number" v-model.number="form.mtrRounds"></div>
          <div class="field" style="width:130px"><label>每跳超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.mtrProbeTimeout"></div>
        </div>

        <!-- ============ 指纹 ============ -->
        <div v-else-if="current==='fingerprint'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标主机 / IP</label>
            <input class="inp" v-model.trim="form.host" placeholder="127.0.0.1"></div>
          <div class="field" style="flex:1;min-width:240px"><label>指定端口(逗号分隔)</label>
            <input class="inp" v-model.trim="form.fpPorts" placeholder="留空=常用端口"></div>
          <div class="field" style="width:110px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.fpTimeout"></div>
          <div class="field" style="width:120px"><label>全端口组</label>
            <label class="checkbox"><input type="checkbox" v-model="form.fpFull"> 增强</label></div>
        </div>

        <!-- ============ 网卡流量 ============ -->
        <div v-else-if="current==='ifstat'" class="row gap12 wrap">
          <div class="field" style="width:160px"><label>采样间隔(ms)</label>
            <input class="inp" type="number" v-model.number="form.ifInterval"></div>
          <div class="field" style="flex:1;min-width:240px"><label class="muted fs12">默认 6 轮采样，按网卡差分计算速率</label></div>
        </div>

        <!-- ============ NTP ============ -->
        <div v-else-if="current==='ntp'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:280px"><label>时间源(逗号分隔,留空=内置)</label>
            <input class="inp" v-model.trim="form.ntpServers" placeholder="ntp.aliyun.com,time.windows.com"></div>
        </div>

        <!-- ============ 子网计算 ============ -->
        <div v-else-if="current==='subnet'">
          <div class="row gap8" style="margin-bottom:10px">
            <button class="btn" :class="{primary: form.subMode==='analyze'}" @click="form.subMode='analyze'">CIDR 解析</button>
            <button class="btn" :class="{primary: form.subMode==='vlsm'}" @click="form.subMode='vlsm'">VLSM 划分</button>
            <button class="btn" :class="{primary: form.subMode==='same'}" @click="form.subMode='same'">同网段判定</button>
          </div>
          <div v-if="form.subMode!=='same'" class="row gap12 wrap">
            <div class="field" style="flex:1;min-width:260px"><label>{{ form.subMode==='vlsm' ? '基础网段 CIDR' : '网段 / 掩码 / 单 IP' }}</label>
              <input class="inp" v-model.trim="form.subSpec" placeholder="192.168.10.0/24"></div>
            <div v-if="form.subMode==='vlsm'" class="field" style="flex:1;min-width:260px"><label>各子网主机数(逗号分隔)</label>
              <input class="inp" v-model.trim="form.subNeeds" placeholder="50,20,10"></div>
          </div>
          <div v-else class="row gap12 wrap">
            <div class="field" style="flex:1;min-width:200px"><label>IP A</label>
              <input class="inp" v-model.trim="form.subA" placeholder="192.168.1.10"></div>
            <div class="field" style="flex:1;min-width:200px"><label>IP B</label>
              <input class="inp" v-model.trim="form.subB" placeholder="192.168.1.20"></div>
            <div class="field" style="width:120px"><label>前缀位</label>
              <input class="inp" type="number" v-model.number="form.subPrefix"></div>
          </div>
        </div>

        <!-- ============ WoL ============ -->
        <div v-else-if="current==='wol'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:280px"><label>MAC 地址(逗号/空格分隔多台)</label>
            <input class="inp" v-model.trim="form.wolMacs" placeholder="00:11:22:33:44:55"></div>
          <div class="field" style="width:110px"><label>端口</label>
            <input class="inp" type="number" v-model.number="form.wolPort"></div>
          <div class="field" style="width:200px"><label>广播地址</label>
            <input class="inp" v-model.trim="form.wolBroadcast"></div>
        </div>

        <!-- ============ 端口扫描 ============ -->
        <div v-else-if="current==='portscan'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标主机 / IP</label>
            <input class="inp" v-model.trim="form.psHost" placeholder="127.0.0.1"></div>
          <div class="field" style="flex:1;min-width:220px"><label>端口(逗号/范围,留空=常用51)</label>
            <input class="inp" v-model.trim="form.psPorts" placeholder="80,443,1-100"></div>
          <div class="field" style="width:120px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.psTimeout"></div>
          <div class="field" style="width:130px"><label>抓取 Banner</label>
            <label class="checkbox"><input type="checkbox" v-model="form.psBanner"> 是</label></div>
        </div>

        <!-- ============ 主机发现 ============ -->
        <div v-else-if="current==='discovery'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标网段/IP/范围(auto=本机)</label>
            <input class="inp" v-model.trim="form.discTarget" placeholder="auto 或 192.168.1.0/24"></div>
          <div class="field" style="flex:1;min-width:180px"><label>方法(arp,ping,tcp)</label>
            <input class="inp" v-model.trim="form.discMethods"></div>
          <div class="field" style="width:110px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.discTimeout"></div>
          <div class="field" style="width:110px"><label>并发数</label>
            <input class="inp" type="number" v-model.number="form.discThreads"></div>
        </div>

        <!-- ============ 拓扑发现 ============ -->
        <div v-else-if="current==='topology'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标网段(auto=本机)</label>
            <input class="inp" v-model.trim="form.topoTarget" placeholder="auto 或 192.168.1.0/24"></div>
          <div class="field" style="flex:1;min-width:240px"><label class="muted fs12">自动发现存活主机并 enrichment MAC/厂商/主机名</label></div>
        </div>

        <!-- ============ 摄像头探测 ============ -->
        <div v-else-if="current==='camera'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标网段(auto=本机)</label>
            <input class="inp" v-model.trim="form.camTarget" placeholder="auto 或 192.168.1.0/24"></div>
          <div class="field" style="width:120px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.camTimeout"></div>
        </div>

        <!-- ============ 安全自检 ============ -->
        <div v-else-if="current==='security'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标网段/IP</label>
            <input class="inp" v-model.trim="form.secTarget" placeholder="192.168.1.0/24"></div>
          <div class="field" style="flex:1;min-width:200px"><label>指定端口(留空=风险端口表)</label>
            <input class="inp" v-model.trim="form.secPorts" placeholder="22,3389 等"></div>
          <div class="field" style="width:120px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.secTimeout"></div>
        </div>

        <!-- ============ IP 冲突检测 ============ -->
        <div v-else-if="current==='ipconflict'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标网段(auto=本机)</label>
            <input class="inp" v-model.trim="form.ipcTarget" placeholder="auto 或 192.168.1.0/24"></div>
          <div class="field" style="width:120px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.ipcTimeout"></div>
        </div>

        <!-- ============ 主机名解析 ============ -->
        <div v-else-if="current==='hostname'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标 IP</label>
            <input class="inp" v-model.trim="form.hostIp" placeholder="8.8.8.8"></div>
          <div class="field" style="width:120px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.hostTimeout"></div>
        </div>

        <!-- ============ MAC 厂商查询 ============ -->
        <div v-else-if="current==='vendor'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>MAC 地址</label>
            <input class="inp" v-model.trim="form.vendMac" placeholder="00:0c:29:ab:cd:ef"></div>
        </div>

        <!-- ============ 无线扫描 ============ -->
        <div v-else-if="current==='wifi'" class="muted fs12">无需参数，直接执行即可扫描周边 Wi-Fi（需无线网卡与管理员权限）。</div>

        <!-- ============ DHCP 信息 ============ -->
        <div v-else-if="current==='dhcp'" class="muted fs12">无需参数，直接执行即可解析本机各网卡 DHCP 配置。</div>

        <!-- ============ 网络体检 ============ -->
        <div v-else-if="current==='netcheck'" class="muted fs12">无需参数，直接执行即可对本机做 7 维网络健康评分。</div>

        <!-- ============ 会话承压测试 ============ -->
        <div v-else-if="current==='session'" class="row gap12 wrap">
          <div class="field" style="flex:1;min-width:240px"><label>目标主机 / IP</label>
            <input class="inp" v-model.trim="form.sessHost" placeholder="127.0.0.1"></div>
          <div class="field" style="width:110px"><label>端口</label>
            <input class="inp" type="number" v-model.number="form.sessPort"></div>
          <div class="field" style="width:110px"><label>连接次数</label>
            <input class="inp" type="number" v-model.number="form.sessCount"></div>
          <div class="field" style="width:130px"><label>超时(ms)</label>
            <input class="inp" type="number" v-model.number="form.sessTimeout"></div>
        </div>

        <div class="row mt12">
          <button class="btn primary" :disabled="running || (cur.perm==='scan' && !canScan)" @click="run">
            <span v-if="running" class="typing"><span></span><span></span><span></span></span>
            <span v-else><span v-html="ic('play',14)"></span> 执行</span>
          </button>
          <span v-if="cur.perm==='scan' && !canScan" class="muted fs12" style="align-self:center">当前账号无 scan 权限</span>
          <div class="grow"></div>
          <span class="muted fs12" v-if="cur.example">示例：{{ cur.example }}</span>
        </div>
      </div>
    </div>

    <div v-if="err && !running" class="card" style="border-color:#dc2626">
      <div class="card-body" style="color:#dc2626"><span v-html="ic('alert',15)"></span> {{ err }}</div>
    </div>

    <div v-if="r && !running" class="card">
      <div class="card-body">
        <!-- ===== 重定向链追踪 ===== -->
        <template v-if="current==='redirect'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('info')">共 {{ r.hopCount }} 跳</span>
            <span class="tag" :style="badgeColor('info')">重定向 {{ r.redirectCount }} 次</span>
            <span class="tag" :style="badgeColor('info')">总耗时 {{ r.totalMs }}ms</span>
            <span v-if="r.downgrade" class="tag" :style="badgeColor('high')">⚠ HTTPS 降级</span>
            <span v-if="r.upgrade" class="tag" :style="badgeColor('ok')">HTTPS 升级</span>
            <span v-if="r.crossDomain" class="tag" :style="badgeColor('medium')">跨域名</span>
            <span v-if="r.crossPort" class="tag" :style="badgeColor('medium')">跨端口</span>
            <span v-if="r.loop" class="tag" :style="badgeColor('critical')">⚠ 重定向环路</span>
          </div>
          <div class="tb-notes">
            <div v-for="(n,i) in r.notes" :key="i" class="tb-note">{{ n }}</div>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>#</th><th>URL</th><th>协议</th><th>状态码</th><th>耗时</th><th>解析 IP</th><th>主机</th><th>Server</th><th>HSTS</th><th>跳转</th></tr></thead>
            <tbody>
              <tr v-for="h in r.hops" :key="h.n">
                <td>{{ h.n }}</td><td style="word-break:break-all">{{ h.url }}</td><td>{{ h.protocol }}</td>
                <td>{{ h.status || (h.error ? '—' : '') }}<span v-if="h.error" class="c-red"> ⚠ {{ h.error }}</span></td>
                <td>{{ h.ms }}ms</td><td>{{ h.ip || '—' }}</td><td>{{ h.host || '—' }}</td><td>{{ h.server || '—' }}</td>
                <td>{{ h.hsts ? '✓' : '—' }}</td><td>{{ h.redirect ? '↪' : '■' }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== HTTP 可用性 ===== -->
        <template v-else-if="current==='httpcheck'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor(r.okStatus ? 'ok' : 'high')">HTTP {{ r.status }} {{ r.statusText }}</span>
            <span class="tag" :style="badgeColor('info')">{{ r.method }}</span>
            <span class="tag" :style="badgeColor('info')">首包 {{ r.ms }}ms / 总 {{ r.totalMs }}ms</span>
            <span v-if="r.tls" class="tag" :style="badgeColor('ok')">{{ r.tls.protocol }}</span>
            <span v-if="r.codeMatched===true" class="tag" :style="badgeColor('ok')">状态码匹配</span>
            <span v-if="r.codeMatched===false" class="tag" :style="badgeColor('high')">状态码不符</span>
            <span v-if="r.keywordFound===true" class="tag" :style="badgeColor('ok')">关键字命中</span>
            <span v-if="r.keywordFound===false" class="tag" :style="badgeColor('high')">关键字未命中</span>
          </div>
          <div class="kv"><div><span>最终地址</span><b>{{ r.finalUrl || r.url }}</b></div>
            <div><span>Server</span><b>{{ r.server || '—' }}</b></div>
            <div><span>Content-Type</span><b>{{ r.contentType || '—' }}</b></div>
            <div><span>标题</span><b>{{ r.title || '—' }}</b></div>
            <div v-if="r.tls"><span>证书到期</span><b>{{ r.tls.validTo }}</b></div></div>
          <div v-if="r.warnings && r.warnings.length" class="tb-notes mt8">
            <div v-for="(w,i) in r.warnings" :key="i" class="tb-note" :style="{color: levelColor('medium')}">⚠ {{ w }}</div>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>响应头</th><th>值</th></tr></thead>
            <tbody>
              <tr v-for="(v,k) in r.headers" :key="k"><td>{{ k }}</td><td style="word-break:break-all">{{ v }}</td></tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== SSL 证书 ===== -->
        <template v-else-if="current==='sslcert'">
          <div class="kv">
            <div><span>主体 CN</span><b>{{ r.subject.cn }}</b></div>
            <div><span>颁发者 CN</span><b>{{ r.issuer.cn }}</b></div>
            <div><span>有效期起</span><b>{{ dleft(r.validFrom) }}</b></div>
            <div><span>有效期止</span><b>{{ dleft(r.validTo) }}</b></div>
            <div><span>剩余天数</span><b :style="{color: levelColor(r.expired ? 'critical' : (r.expiringSoon ? 'high' : 'ok'))}">{{ r.daysLeft }} 天</b></div>
            <div><span>自签名</span><b>{{ r.selfSigned ? '是' : '否' }}</b></div>
            <div><span>协议</span><b>{{ r.protocol }}</b></div>
            <div><span>加密套件</span><b>{{ r.cipher }}</b></div>
            <div><span>公钥位数</span><b>{{ r.keyBits || '—' }}</b></div>
            <div><span>链校验</span><b :style="{color: levelColor(r.authorized ? 'ok' : 'high')}">{{ r.authorized ? '通过' : ('未通过: '+r.authorizationError) }}</b></div>
          </div>
          <div class="row gap8 wrap mt8" v-if="r.san && r.san.length">
            <span class="muted fs12">SAN:</span>
            <span v-for="s in r.san" :key="s" class="tag" :style="badgeColor('info')">{{ s }}</span>
          </div>
          <div class="tb-notes mt8">
            <div v-for="(w,i) in r.warnings" :key="i" class="tb-note" :style="{color: levelColor(w.level)}">⚠ {{ w.text }}</div>
          </div>
          <div v-if="r.chain && r.chain.length" class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>链层级</th><th>主体</th><th>颁发者</th><th>到期</th><th>剩余</th></tr></thead>
            <tbody>
              <tr v-for="(c,i) in r.chain" :key="i"><td>{{ i+1 }}</td><td>{{ c.subject }}</td><td>{{ c.issuer }}</td><td>{{ dleft(c.validTo) }}</td><td>{{ c.daysLeft }} 天</td></tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== Whois ===== -->
        <template v-else-if="current==='whois'">
          <div class="kv">
            <div><span>来源</span><b>{{ r.source }}</b></div>
            <div><span>类型</span><b>{{ r.kind }}</b></div>
            <div v-if="r.query"><span>查询</span><b>{{ r.query }}</b></div>
            <div v-if="r.registrar"><span>注册商</span><b>{{ r.registrar }}</b></div>
            <div v-if="r.registrant"><span>注册人</span><b>{{ r.registrant }}</b></div>
            <div v-if="r.registration"><span>注册时间</span><b>{{ r.registration }}</b></div>
            <div v-if="r.expiration"><span>到期时间</span><b>{{ r.expiration }}</b></div>
            <div v-if="r.dnssec!==undefined"><span>DNSSEC</span><b>{{ r.dnssec ? '启用' : '未启用' }}</b></div>
          </div>
          <div v-if="r.nameservers && r.nameservers.length" class="row gap8 wrap mt8">
            <span class="muted fs12">Nameservers:</span>
            <span v-for="n in r.nameservers" :key="n" class="tag" :style="badgeColor('info')">{{ n }}</span>
          </div>
          <div v-if="r.status && r.status.length" class="row gap8 wrap mt8">
            <span class="muted fs12">状态:</span>
            <span v-for="s in r.status" :key="s" class="tag" :style="badgeColor('info')">{{ s }}</span>
          </div>
          <div v-if="r.fields" class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>字段</th><th>值</th></tr></thead>
            <tbody><tr v-for="(v,k) in r.fields" :key="k"><td>{{ k }}</td><td style="word-break:break-all;white-space:pre-wrap">{{ v }}</td></tr></tbody>
          </table></div>
          <div class="muted fs12 mt8" v-if="r.raw">原始响应 {{ r.raw.length }} 字符</div>
        </template>

        <!-- ===== 公网出口 ===== -->
        <template v-else-if="current==='publicip'">
          <div class="kv">
            <div><span>公网 IP</span><b>{{ r.ip }}</b></div>
            <div><span>来源</span><b>{{ r.source }}</b></div>
            <div v-if="r.asn"><span>ASN</span><b>{{ r.asn }}</b></div>
            <div v-if="r.organization"><span>运营商</span><b>{{ r.organization }}</b></div>
            <div v-if="r.country"><span>国家/地区</span><b>{{ r.country }}</b></div>
            <div v-if="r.city"><span>城市</span><b>{{ r.city }}</b></div>
          </div>
        </template>

        <!-- ===== DNS 诊断 ===== -->
        <template v-else-if="current==='dns'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor(r.consistent ? 'ok' : 'high')">{{ r.consistent ? '各 DNS 一致' : '结果不一致' }}</span>
            <span v-if="r.hijack" class="tag" :style="badgeColor('critical')">⚠ 疑似劫持</span>
          </div>
          <div class="tb-notes">
            <div v-for="(n,i) in r.notes" :key="i" class="tb-note">{{ n }}</div>
          </div>
          <div class="mt8"><div class="muted fs12 mb4">本机系统解析</div>
            <div v-for="t in r.types" :key="t" class="row gap8 wrap" style="margin-bottom:4px">
              <span class="tag" :style="badgeColor('info')">{{ t }}</span>
              <span v-if="r.system[t] && r.system[t].records.length" class="mono-num">{{ r.system[t].records.join(', ') }}</span>
              <span v-else class="muted fs12">{{ r.system[t] && r.system[t].error ? ('失败: '+r.system[t].error) : '无记录' }}</span>
            </div>
          </div>
          <div class="mt12"><div class="muted fs12 mb4">公共 DNS 对比</div>
            <div class="table-wrap"><table class="ntable compact">
              <thead><tr><th>DNS</th><th>IP</th><th>耗时</th><th>A 记录</th><th>状态</th></tr></thead>
              <tbody>
                <tr v-for="s in r.servers" :key="s.ip">
                  <td>{{ s.name }}</td><td>{{ s.ip }}</td><td>{{ s.ms }}ms</td>
                  <td style="word-break:break-all">{{ (s.a && s.a.length) ? s.a.join(', ') : '—' }}</td>
                  <td :style="{color: levelColor(s.ok ? 'ok' : 'high')}">{{ s.ok ? '正常' : '失败' }}</td>
                </tr>
              </tbody>
            </table></div>
          </div>
        </template>

        <!-- ===== Ping ===== -->
        <template v-else-if="current==='ping'">
          <div class="kv">
            <div><span>目标</span><b>{{ r.target }}</b></div>
            <div><span>IP</span><b>{{ r.ip }}</b></div>
            <div><span>TTL</span><b>{{ r.ttl || '—' }}</b></div>
            <div><span>发送 / 接收</span><b>{{ r.sent }} / {{ r.recv }}</b></div>
            <div><span>丢包</span><b :style="{color: levelColor(r.loss>=20?'high':(r.loss>0?'medium':'ok'))}">{{ r.loss }}%</b></div>
            <div><span>最小</span><b>{{ r.min==null?'—':r.min+'ms' }}</b></div>
            <div><span>平均</span><b>{{ r.avg==null?'—':r.avg+'ms' }}</b></div>
            <div><span>最大</span><b>{{ r.max==null?'—':r.max+'ms' }}</b></div>
            <div><span>抖动</span><b>{{ r.jitter==null?'—':r.jitter+'ms' }}</b></div>
          </div>
          <div class="mt8"><span class="tag" :style="badgeColor(r.grade.level)">健康评分：{{ r.grade.text }}</span></div>
        </template>

        <!-- ===== MTR ===== -->
        <template v-else-if="current==='mtr'">
          <div class="tb-notes">
            <div v-for="(n,i) in r.notes" :key="i" class="tb-note">{{ n }}</div>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>跳</th><th>IP</th><th>平均</th><th>最小</th><th>最大</th><th>抖动</th><th>丢包</th></tr></thead>
            <tbody>
              <tr v-for="h in r.hops" :key="h.ttl">
                <td>{{ h.ttl }}</td><td>{{ h.ip || '*' }}</td>
                <td>{{ h.avg==null?'—':h.avg+'ms' }}</td><td>{{ h.min==null?'—':h.min+'ms' }}</td>
                <td>{{ h.max==null?'—':h.max+'ms' }}</td><td>{{ h.jitter==null?'—':h.jitter+'ms' }}</td>
                <td :style="{color: levelColor(h.loss>20?'high':(h.loss>0?'medium':'ok'))}">{{ h.loss }}%</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== 指纹 ===== -->
        <template v-else-if="current==='fingerprint'">
          <div class="kv">
            <div><span>目标</span><b>{{ r.host }}</b></div>
            <div><span>IP</span><b>{{ r.ip }}</b></div>
            <div><span>操作系统</span><b>{{ r.osGuess.name }} <span class="muted fs12">({{ r.osGuess.hint }})</span></b></div>
            <div><span>设备类型</span><b>{{ r.deviceType }}</b></div>
            <div v-if="r.vendorHint"><span>厂商线索</span><b>{{ r.vendorHint }}</b></div>
            <div><span>开放端口</span><b>{{ r.openCount }} / 扫描 {{ r.scanned }}</b></div>
          </div>
          <div class="mt8"><div class="muted fs12 mb4">端口探测</div>
            <div class="table-wrap"><table class="ntable compact">
              <thead><tr><th>端口</th><th>服务</th><th>状态</th><th>耗时</th><th>Banner / Server</th></tr></thead>
              <tbody>
                <tr v-for="p in r.ports" :key="p.port">
                  <td>{{ p.port }}</td><td>{{ p.service || '—' }}</td>
                  <td :style="{color: levelColor(p.open?'ok':'info')}">{{ p.open ? '开放' : '关闭' }}</td>
                  <td>{{ p.ms==null?'—':p.ms+'ms' }}</td>
                  <td style="word-break:break-all">{{ p.server || p.banner || (p.error ? ('错误: '+p.error) : '—') }}</td>
                </tr>
              </tbody>
            </table></div>
          </div>
          <div class="mt8"><div class="muted fs12 mb4">风险判定</div>
            <div class="tb-notes">
              <div v-for="(x,i) in r.risks" :key="i" class="tb-note" :style="{color: levelColor(x.level)}">
                <b>[{{ x.port || '—' }}] {{ x.service }}</b> — {{ x.text }}
              </div>
            </div>
          </div>
        </template>

        <!-- ===== 网卡流量 ===== -->
        <template v-else-if="current==='ifstat'">
          <div class="row gap8 wrap mb8">
            <span class="tag" :style="badgeColor('info')">采样 {{ r.rounds }} 轮 / {{ r.intervalMs }}ms</span>
            <span class="tag" :style="badgeColor('info')">总入 {{ fmt.bps(r.totalRxBps) }}</span>
            <span class="tag" :style="badgeColor('info')">总出 {{ fmt.bps(r.totalTxBps) }}</span>
          </div>
          <div class="table-wrap"><table class="ntable compact">
            <thead><tr><th>网卡</th><th>入速率</th><th>出速率</th><th>入峰值</th><th>出峰值</th><th>累计入</th><th>累计出</th></tr></thead>
            <tbody>
              <tr v-for="a in r.adapters" :key="a.name">
                <td>{{ a.name }}</td><td>{{ a.rxHuman }}</td><td>{{ a.txHuman }}</td>
                <td>{{ fmt.bps(a.peakRx) }}</td><td>{{ fmt.bps(a.peakTx) }}</td>
                <td>{{ fmt.bytes(a.rxBytes) }}</td><td>{{ fmt.bytes(a.txBytes) }}</td>
              </tr>
            </tbody>
          </table></div>
          <div v-if="chartOpt" class="mt12"><div class="muted fs12 mb4">首张网卡速率走势（RX/TX）</div>
            <NcChart :option="chartOpt" height="220px"></NcChart></div>
        </template>

        <!-- ===== NTP ===== -->
        <template v-else-if="current==='ntp'">
          <div class="tb-notes">
            <div v-for="(n,i) in r.notes" :key="i" class="tb-note">{{ n }}</div>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>时间源</th><th>状态</th><th>偏差</th><th>延迟</th><th>Stratum</th></tr></thead>
            <tbody>
              <tr v-for="s in r.results" :key="s.server" :style="r.best && r.best.server===s.server ? {background:'var(--primary-weak)'} : ''">
                <td>{{ s.server }}</td>
                <td :style="{color: levelColor(s.ok?'ok':'high')}">{{ s.ok ? '正常' : ('失败 '+(s.error||'')) }}</td>
                <td>{{ s.ok ? s.offsetMs+'ms' : '—' }}</td><td>{{ s.ok ? s.delayMs+'ms' : '—' }}</td><td>{{ s.ok ? s.stratum : '—' }}</td>
              </tr>
            </tbody>
          </table></div>
          <div class="muted fs12 mt8">本地时间：{{ r.now }}</div>
        </template>

        <!-- ===== 子网计算 ===== -->
        <template v-else-if="current==='subnet' && form.subMode==='analyze'">
          <div class="kv">
            <div><span>输入</span><b>{{ r.input }}</b></div>
            <div><span>地址类别</span><b>{{ r.addressClass }}</b></div>
            <div><span>网络地址</span><b>{{ r.network }} /{{ r.prefix }}</b></div>
            <div><span>子网掩码</span><b>{{ r.mask }}</b></div>
            <div><span>通配符</span><b>{{ r.wildcard }}</b></div>
            <div><span>广播地址</span><b>{{ r.broadcast }}</b></div>
            <div><span>可用主机范围</span><b>{{ r.firstHost }} ~ {{ r.lastHost }}</b></div>
            <div><span>地址总数</span><b>{{ r.total }}</b></div>
            <div><span>可用主机数</span><b>{{ r.usable }}</b></div>
            <div><span>作用域</span><b>{{ r.scope }}</b></div>
          </div>
          <div class="tb-notes mt8"><div v-for="(n,i) in r.notes" :key="i" class="tb-note">{{ n }}</div></div>
        </template>
        <template v-else-if="current==='subnet' && form.subMode==='vlsm'">
          <div class="kv">
            <div><span>基础网段</span><b>{{ r.base }}</b></div>
            <div><span>地址池</span><b>{{ r.poolSize }}</b></div>
            <div><span>已用</span><b>{{ r.used }}</b></div>
            <div><span>剩余</span><b>{{ r.free }}</b></div>
            <div v-if="r.freeRange"><span>剩余区间</span><b>{{ r.freeRange }}</b></div>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>名称</th><th>需求</th><th>前缀</th><th>网络地址</th><th>广播</th><th>可用范围</th><th>可用数</th></tr></thead>
            <tbody>
              <tr v-for="(a,i) in r.allocations" :key="i">
                <td>{{ a.name }}</td><td>{{ a.size }}</td><td>{{ a.prefix }}</td>
                <td>{{ a.network }}</td><td>{{ a.broadcast }}</td>
                <td>{{ a.firstHost }} ~ {{ a.lastHost }}</td>
                <td>{{ a.usable }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>
        <template v-else-if="current==='subnet' && form.subMode==='same'">
          <div class="kv">
            <div><span>IP A</span><b>{{ r.a }}</b></div>
            <div><span>IP B</span><b>{{ r.b }}</b></div>
            <div><span>前缀</span><b>/{{ r.prefix }}</b></div>
            <div><span>网段 A</span><b>{{ r.networkA }}</b></div>
            <div><span>网段 B</span><b>{{ r.networkB }}</b></div>
            <div><span>判定</span><b :style="{color: levelColor(r.same?'ok':'high')}">{{ r.same ? '同一网段' : '不同网段' }}</b></div>
          </div>
          <div class="tb-notes mt8"><div class="tb-note" :style="{color: levelColor(r.same?'ok':'high')}">{{ r.note }}</div></div>
        </template>

        <!-- ===== WoL ===== -->
        <template v-else-if="current==='wol'">
          <div class="tb-notes"><div class="tb-note" :style="{color: levelColor(r.ok?'ok':'high')}">{{ r.note }}</div></div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>MAC</th><th>发送结果</th></tr></thead>
            <tbody>
              <tr v-for="d in r.devices" :key="d.mac">
                <td class="mono-num">{{ d.mac }}</td>
                <td :style="{color: levelColor(d.ok?'ok':'high')}">{{ d.ok ? '已发送' : ('失败 '+(d.error||'')) }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== 端口扫描 ===== -->
        <template v-else-if="current==='portscan'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('info')">目标 {{ r.host }}</span>
            <span class="tag" :style="badgeColor('info')">扫描 {{ r.scanned }} 端口</span>
            <span class="tag" :style="badgeColor('ok')">开放 {{ r.open }}</span>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>端口</th><th>协议</th><th>状态</th><th>服务</th><th>产品</th><th>Banner</th></tr></thead>
            <tbody>
              <tr v-for="p in r.ports" :key="p.port">
                <td>{{ p.port }}</td><td>{{ p.protocol }}</td>
                <td :style="{color: levelColor('ok')}">开放</td>
                <td>{{ p.service || '—' }}</td><td>{{ p.product || '—' }}</td>
                <td style="word-break:break-all">{{ (p.banner||'').slice(0,120) || '—' }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== 主机发现 ===== -->
        <template v-else-if="current==='discovery'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('info')">目标 {{ r.target }}</span>
            <span class="tag" :style="badgeColor('info')">共 {{ r.total }} 地址</span>
            <span class="tag" :style="badgeColor('ok')">发现 {{ r.count }} 台</span>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>IP</th><th>MAC</th><th>厂商</th><th>发现方式</th><th>延迟(ms)</th></tr></thead>
            <tbody>
              <tr v-for="h in r.found" :key="h.ip">
                <td>{{ h.ip }}</td><td class="mono-num">{{ h.mac || '—' }}</td><td>{{ h.vendor || '—' }}</td>
                <td>{{ h.method }}</td><td>{{ h.latency_ms<0 ? '—' : h.latency_ms }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== 拓扑发现 ===== -->
        <template v-else-if="current==='topology'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('info')">网段 {{ r.network }}</span>
            <span class="tag" :style="badgeColor('info')">网关 {{ r.gateway }}</span>
            <span class="tag" :style="badgeColor('ok')">节点 {{ r.count }}</span>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>IP</th><th>MAC</th><th>厂商</th><th>主机名</th><th>角色</th></tr></thead>
            <tbody>
              <tr v-for="n in r.nodes" :key="n.ip">
                <td>{{ n.ip }}</td><td class="mono-num">{{ n.mac || '—' }}</td><td>{{ n.vendor || '—' }}</td>
                <td>{{ n.hostname || '—' }}</td><td :style="{color: levelColor(n.role==='gateway'?'ok':'info')}">{{ n.role }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== 摄像头探测 ===== -->
        <template v-else-if="current==='camera'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('info')">目标 {{ r.target }}</span>
            <span class="tag" :style="badgeColor('ok')">发现 {{ r.devices.length }} 个设备</span>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>IP</th><th>开放端口</th><th>品牌</th><th>疑似摄像头</th><th>特征</th></tr></thead>
            <tbody>
              <tr v-for="d in r.devices" :key="d.ip">
                <td>{{ d.ip }}</td><td class="mono-num">{{ (d.open_ports||[]).join(', ') }}</td>
                <td>{{ d.brand || '—' }}</td>
                <td :style="{color: levelColor(d.is_camera?'high':'info')}">{{ d.is_camera ? '是' : '否' }}</td>
                <td style="word-break:break-all">{{ (d.note||'').slice(0,120) || '—' }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== 安全自检 ===== -->
        <template v-else-if="current==='security'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('info')">目标 {{ r.target }}</span>
            <span class="tag" :style="badgeColor('info')">主机 {{ r.hosts }}</span>
            <span class="tag" :style="badgeColor(r.risk_score>=70?'critical':(r.risk_score>=40?'high':(r.risk_score>=15?'medium':'ok')))">风险分 {{ r.risk_score }} · {{ r.level }}</span>
            <span class="tag" :style="badgeColor('high')">高危 {{ r.severity_count['高危'] }}</span>
            <span class="tag" :style="badgeColor('medium')">中危 {{ r.severity_count['中危'] }}</span>
            <span class="tag" :style="badgeColor('low')">低危 {{ r.severity_count['低危'] }}</span>
          </div>
          <div class="table-wrap mt8" v-if="r.findings.length"><table class="ntable compact">
            <thead><tr><th>IP</th><th>端口</th><th>服务</th><th>严重度</th><th>风险说明</th></tr></thead>
            <tbody>
              <tr v-for="(f,i) in r.findings" :key="i">
                <td>{{ f.ip }}</td><td>{{ f.port }}</td><td>{{ f.service }}</td>
                <td :style="{color: levelColor(f.severity==='高危'?'high':(f.severity==='中危'?'medium':'low'))}">{{ f.severity }}</td>
                <td>{{ f.detail }}</td>
              </tr>
            </tbody>
          </table></div>
          <div v-else class="muted fs12 mt8">未发现暴露面风险端口。</div>
        </template>

        <!-- ===== IP 冲突检测 ===== -->
        <template v-else-if="current==='ipconflict'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('info')">目标 {{ r.target }}</span>
            <span class="tag" :style="badgeColor('info')">映射 {{ r.count }}</span>
            <span class="tag" :style="badgeColor(r.conflicts.length?'critical':'ok')">冲突 {{ r.conflicts.length }}</span>
          </div>
          <div v-if="r.conflicts.length" class="tb-notes mt8">
            <div v-for="c in r.conflicts" :key="c.ip" class="tb-note" :style="{color: levelColor('critical')}">⚠ {{ c.ip }} 对应多个 MAC：{{ c.macs.join(', ') }}</div>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>IP</th><th>MAC</th><th>映射数</th></tr></thead>
            <tbody>
              <tr v-for="m in r.mappings" :key="m.ip">
                <td>{{ m.ip }}</td><td class="mono-num">{{ m.mac }}</td><td>{{ m.mac_count }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== 主机名解析 ===== -->
        <template v-else-if="current==='hostname'">
          <div class="kv">
            <div><span>IP</span><b>{{ r.ip }}</b></div>
            <div><span>主机名</span><b>{{ r.hostname || '—(无反向记录)' }}</b></div>
          </div>
        </template>

        <!-- ===== MAC 厂商查询 ===== -->
        <template v-else-if="current==='vendor'">
          <div class="kv">
            <div><span>MAC</span><b class="mono-num">{{ r.mac }}</b></div>
            <div><span>OUI</span><b>{{ r.oui }}</b></div>
            <div><span>厂商</span><b>{{ r.vendor || '未知(无匹配)' }}</b></div>
          </div>
        </template>

        <!-- ===== 无线扫描 ===== -->
        <template v-else-if="current==='wifi'">
          <div v-if="r.note" class="muted fs12 mb8">{{ r.note }}</div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>SSID</th><th>BSSID</th><th>信号(%)</th><th>信道</th><th>加密</th></tr></thead>
            <tbody>
              <tr v-for="n in r.networks" :key="n.bssid">
                <td>{{ n.ssid }}</td><td class="mono-num">{{ n.bssid }}</td>
                <td>{{ n.signal!=null ? n.signal+'%' : '—' }}</td>
                <td>{{ n.channel || '—' }}</td><td>{{ n.security || '—' }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== DHCP 信息 ===== -->
        <template v-else-if="current==='dhcp'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('ok')">DHCP 服务器 {{ r.dhcp_servers.length }}</span>
          </div>
          <div class="table-wrap mt8"><table class="ntable compact">
            <thead><tr><th>网卡</th><th>IPv4</th><th>掩码</th><th>网关</th><th>DHCP</th><th>DHCP服务器</th><th>租约起</th><th>租约止</th></tr></thead>
            <tbody>
              <tr v-for="i in r.interfaces" :key="i.name">
                <td>{{ i.name }}</td><td>{{ i.ip }}</td><td>{{ i.mask }}</td><td>{{ i.gateway||'—' }}</td>
                <td>{{ i.dhcp_enabled?'是':'否' }}</td><td>{{ i.dhcp_server||'—' }}</td>
                <td>{{ i.lease_obtained||'—' }}</td><td>{{ i.lease_expires||'—' }}</td>
              </tr>
            </tbody>
          </table></div>
        </template>

        <!-- ===== 网络体检 ===== -->
        <template v-else-if="current==='netcheck'">
          <div class="row gap8 wrap" style="margin-bottom:8px">
            <span class="tag" :style="badgeColor('info')">综合分 {{ r.score }}/100</span>
            <span class="tag" :style="badgeColor(r.level==='优秀'||r.level==='良好'?'ok':(r.level==='一般'?'medium':'high'))">等级 {{ r.level }}</span>
            <span class="tag" :style="badgeColor('info')">网关 {{ r.gateway }}</span>
          </div>
          <div class="tb-notes mt8">
            <div v-for="it in r.items" :key="it.key" class="tb-note">
              <b>{{ it.name }}</b>：{{ it.score }}/{{ it.max }} — <span :style="{color: levelColor(it.status==='ok'?'ok':(it.status==='warn'?'medium':'high'))}">{{ it.detail }}</span>
            </div>
          </div>
        </template>

        <!-- ===== 会话承压测试 ===== -->
        <template v-else-if="current==='session'">
          <div class="kv">
            <div><span>目标</span><b>{{ r.host }}:{{ r.port }}</b></div>
            <div><span>尝试 / 成功</span><b>{{ r.attempts }} / {{ r.success }}</b></div>
            <div><span>成功率</span><b :style="{color: levelColor(r.success_rate>=90?'ok':(r.success_rate>=60?'medium':'high'))}">{{ r.success_rate }}%</b></div>
            <div><span>平均连接时延</span><b>{{ r.avg_connect_ms!=null ? r.avg_connect_ms+'ms' : '—' }}</b></div>
            <div><span>最大并发承载</span><b>{{ r.max_concurrent!=null ? r.max_concurrent : '—' }}</b></div>
          </div>
        </template>
      </div>
    </div>
  </section>
</div>`,
    setup() {
      return {
        cats: CATS, tools: TOOLS, toolsByCat, cur, r, form, current, running, err, canScan, chartOpt,
        q, totalTools, filteredGroups,
        ic, fmt, select, run, levelColor, badgeColor, dleft
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.ToolboxPage = ToolboxPage;
  NC.route('/toolbox', { title: '网络运维工具箱', comp: 'ToolboxPage' });
})();
