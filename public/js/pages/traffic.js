/* =========================================================================
   会话与流量：IP/MAC 定位 · 设备表查询 · 会话分析 · 抓包诊断
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, nextTick, watch } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const TABS = [
    { k: 'locate', n: 'IP / MAC 定位', i: 'search' },
    { k: 'table', n: '设备表查询', i: 'list' },
    { k: 'flow', n: '流量会话分析', i: 'activity' },
    { k: 'capture', n: '抓包诊断', i: 'camera' }
  ];

  const TrafficPage = {
    name: 'TrafficPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
        <div class="grow"></div>
        <span class="fs12 muted">{{ demoTag }}</span>
      </div>

      <!-- ============ IP / MAC 定位 ============ -->
      <div v-show="tab==='locate'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('search',15)"></span><span>跨设备定位</span></div>
          <div class="filter-bar">
            <div class="search-box" style="flex:1;min-width:280px">
              <span v-html="ic('search',15)"></span>
              <input class="inp" v-model.trim="locQ" placeholder="输入 IP 或 MAC 地址，如 10.252.28.40 / 0011.2233.4455，回车查询"
                     @keydown.enter="doLocate">
            </div>
            <button class="btn primary" :disabled="locating" @click="doLocate" v-html="locating?'执行中…':ic('search',15)+'<span>定位</span>'"></button>
            <button class="btn" @click="locQ=''">清空</button>
          </div>
          <div class="hint-line" v-html="ic('shield',13) + '<span>该动作会同时在所有纳管设备上查 MAC 地址表与 ARP 表，用于判断「某台电脑/服务器接在哪个交换机的哪个口上」——这是内网排障最高频的动作。'"></div>

          <div v-if="locRes" class="col gap12 mt12">
            <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr))">
              <div class="result-box"><div class="l fs12 muted">查询目标</div><div class="big" style="font-size:16px">{{ locRes.query }}</div><div class="fs11 muted">{{ locRes.type==='ip'?'IP 地址':'MAC 地址' }}</div></div>
              <div class="result-box"><div class="l fs12 muted">MAC 表命中</div><div class="big up">{{ locRes.hits.mac.length }}</div><div class="fs11 muted">Learning 记录</div></div>
              <div class="result-box"><div class="l fs12 muted">ARP 表命中</div><div class="big lat">{{ locRes.hits.arp.length }}</div><div class="fs11 muted">IP↔MAC 解析</div></div>
              <div class="result-box"><div class="l fs12 muted">已扫描设备</div><div class="big" style="color:var(--text-2)">{{ locRes.scanned.length }}</div><div class="fs11 muted">{{ locRes.scanned.filter(x=>x.demo).length }} 台为演示数据</div></div>
            </div>

            <div v-if="!locRes.hits.mac.length && !locRes.hits.arp.length" class="card tight">
              <div class="row" style="color:var(--warn)"><span v-html="ic('alert',15)"></span>
                <span>未命中。可能原因：该终端已关机/下电（ARP 表项过期）、跨三层网段未在网关设备上、或设备未配置真实凭据导致仅返回演示数据。</span></div>
            </div>

            <div class="card" v-for="g in locGroups" :key="g.key">
              <div class="card-head"><span>{{ g.key }}</span><span class="fs12 muted fw4">{{ g.rows.length }} 条</span></div>
              <div class="table-wrap">
                <table class="ntable">
                  <thead><tr>
                    <th v-for="h in g.cols" :key="h">{{ h }}</th>
                    <th style="width:150px">操作</th>
                  </tr></thead>
                  <tbody>
                    <tr v-for="(r,i) in g.rows" :key="i">
                      <td v-for="c in g.keys" :key="c" :class="c==='ip'||c==='mac'||c==='port'||c==='iface'?'mono':'ellipsis'">{{ r[c] ?? '-' }}</td>
                      <td>
                        <button class="btn sm" @click="openHost(r.host)">终端</button>
                        <button class="btn sm" @click="go('/devices')">设备详情</button>
                      </td>
                    </tr>
                    <tr v-if="!g.rows.length"><td :colspan="g.keys.length+1" class="tbl-empty">无命中</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="card tight">
              <div class="card-head"><span class="fs12 fw5">扫描明细</span></div>
              <div class="table-wrap">
                <table class="ntable">
                  <thead><tr><th style="width:160px">设备</th><th style="width:130px">地址</th><th style="width:90px">数据来源</th><th>说明</th></tr></thead>
                  <tbody>
                    <tr v-for="s in locRes.scanned" :key="s.host">
                      <td class="fw5">{{ s.name }}<div class="fs11 muted mono">{{ s.host }}</div></td>
                      <td class="mono">{{ s.ip }}</td>
                      <td><span class="src-badge" :class="s.demo?'demo':'zabbix'">{{ s.demo?'演示数据':'设备实测' }}</span></td>
                      <td class="fs11 muted">{{ s.error || '正常' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ============ 设备表查询 ============ -->
      <div v-show="tab==='table'" class="col gap16">
        <div class="card">
          <div class="filter-bar">
            <select class="inp" v-model="tblHost" style="max-width:250px">
              <option v-for="d in devices" :key="d.host" :value="d.host">{{ d.name }} · {{ d.ip }}</option>
            </select>
            <div class="tabs" style="border:none">
              <div class="tab" :class="{on:kind==='mac'}" @click="kind='mac'">MAC 地址表</div>
              <div class="tab" :class="{on:kind==='arp'}" @click="kind='arp'">ARP 表</div>
              <div class="tab" :class="{on:kind==='session'}" @click="kind='session'">会话表</div>
            </div>
            <div class="search-box"><span v-html="ic('search',15)"></span>
              <input class="inp" v-model.trim="tblKw" placeholder="关键词过滤" @keydown.enter="loadTable" style="min-width:200px"></div>
            <button class="btn primary" @click="loadTable" v-html="ic('search',15)"></button>
            <div class="grow"></div>
            <span class="fs12 muted">{{ tblRows.length }} 条</span>
            <button class="btn" @click="exportTable" v-html="ic('download',15)+'<span>导出</span>'"></button>
            <button class="btn" @click="loadTable" v-html="ic('refresh',15)"></button>
          </div>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>命令随厂商自动切换（Cisco / 华为 VRP / H3C / Fortinet / Palo Alto），未配置真机凭据时返回演示数据。</span></div>

          <div class="table-wrap">
            <table class="ntable">
              <thead><tr>
                <th v-for="h in tblCols" :key="h">{{ h }}</th>
                <th style="width:120px">跳转</th>
              </tr></thead>
              <tbody>
                <tr v-for="(r,i) in tblRows" :key="i">
                  <td v-for="c in tblKeys" :key="c" :class="['mono','ellipsis']" :title="String(r[c]??'')">{{ r[c] ?? '-' }}</td>
                  <td><button class="btn sm" @click="openHost(tblHost)">终端</button></td>
                </tr>
                <tr v-if="!tblRows.length"><td :colspan="tblKeys.length+1" class="tbl-empty">暂无数据，点击刷新或调整关键词</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ============ 会话分析 ============ -->
      <div v-show="tab==='flow'" class="col gap16">
        <div class="card">
          <div class="filter-bar">
            <select class="inp" v-model="flowHost" style="max-width:250px">
              <option v-for="d in devices" :key="d.host" :value="d.host">{{ d.name }} · {{ d.ip }}</option>
            </select>
            <div class="grow"></div>
            <button class="btn" @click="loadFlow" v-html="ic('refresh',15)"></button>
          </div>
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr))">
            <div class="result-box"><div class="l fs12 muted">会话总数</div><div class="big">{{ flowStat.total }}</div><div class="fs11 muted">当前设备连接</div></div>
            <div class="result-box"><div class="l fs12 muted">Top 汇聚对</div><div class="big up">{{ flowStat.pairs }}</div><div class="fs11 muted">src→dst 聚合</div></div>
            <div class="result-box"><div class="l fs12 muted">总字节</div><div class="big" style="color:var(--primary)">{{ fmt.bytes(flowStat.bytes) }}</div><div class="fs11 muted">Top 汇总</div></div>
          </div>
          <div class="mt12" v-if="flowTop.length">
            <div class="fs13 fw5 mb8">流量 Top 汇聚（按会话数）</div>
            <NcChart :option="optFlow" height="300px"></NcChart>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('list',15)"></span><span>端口流量排行（入向 / 出向）</span></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:60px">#</th><th style="width:170px">源 → 目的</th><th style="width:70px">协议</th><th style="width:70px">目的端口</th><th style="width:110px">会话数</th><th style="width:130px">流量</th></tr></thead>
              <tbody>
                <tr v-for="(r,i) in flowTop" :key="i">
                  <td class="mono muted">{{ i+1 }}</td>
                  <td class="mono ellipsis" style="max-width:250px">{{ r.src }} → {{ r.dst }}</td>
                  <td><span class="tag">{{ r.proto }}</span></td>
                  <td class="mono">{{ r.ports || '-' }}</td>
                  <td class="mono-num">{{ r.flows }}</td>
                  <td><NcBar :value="r.bytes" :max="flowMax" show-text></NcBar></td>
                </tr>
                <tr v-if="!flowTop.length"><td colspan="6" class="tbl-empty">暂无会话数据</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ============ 抓包诊断 ============ -->
      <div v-show="tab==='capture'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('camera',15)"></span><span>抓包环境</span>
            <div class="grow"></div><button class="btn sm" @click="loadDiag" v-html="ic('refresh',13)"></button></div>
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
            <div class="result-box">
              <div class="l fs12 muted">抓包引擎</div>
              <div class="big" :style="{fontSize:17, color: diag.ready ? 'var(--success)' : 'var(--warn)'}">{{ diag.engine || '未安装' }}</div>
              <div class="fs11 muted ellipsis" :title="diag.path">{{ diag.hint || diag.path }}</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">可用网卡</div>
              <div class="big" style="color:var(--primary)">{{ ifaces.length }}</div>
              <div class="fs11 muted">{{ diag.localInterfaces ? diag.localInterfaces.length : 0 }} 个非回环地址</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">已抓文件</div>
              <div class="big">{{ caps.length }}</div>
              <div class="fs11 muted">累计 {{ fmt.bytes(capBytes) }}</div>
            </div>
          </div>
          <div v-if="ifaceList.length" class="mt12">
            <div class="fs12 fw5 mb8">网卡列表（<span class="mono">{{ ifaceList.map(x=>x.id).join(' , ') }}</span>）</div>
            <div class="flex" style="gap:6px;flex-wrap:wrap">
              <span v-for="i in ifaceList" :key="i.id" class="tag">{{ i.id }} · {{ i.name }}{{ i.ip ? ' · ' + i.ip : '' }}{{ i.internal ? ' · 回环' : '' }}</span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('zap',15)"></span><span>发起抓包</span></div>
          <div class="form-grid">
            <label>抓包模式
              <select class="inp" v-model="capEngine">
                <option value="auto">自动（本机优先，无引擎时降级为设备抓包）</option>
                <option value="local">本机抓包（Wireshark / Npcap）</option>
                <option value="device">设备侧抓包（SSH 下发 monitor capture）</option>
              </select>
            </label>
            <label>本机抓包选设备
              <select class="inp" v-model="capHost">
                <option value="">（不限）</option>
                <option v-for="d in devices" :key="d.host" :value="d.host">{{ d.name }} · {{ d.ip }}</option>
              </select>
            </label>
            <label>抓包时长（秒）<input class="inp" type="number" min="3" max="300" v-model="capSec"></label>
            <label>本机抓包选网卡
              <select class="inp" v-model="capIface"><option value="">自动选择</option>
                <option v-for="i in ifaceList" :key="i.id" :value="i.id">{{ i.id }} · {{ i.name }}</option></select>
            </label>
          </div>
          <label class="mt8">过滤表达式（BPF 语法，留空抓取全部）
            <input class="inp mono" v-model="capFilter" placeholder="host 10.252.28.40 and port 445"></label>
          <div class="filter-bar mt8">
            <div class="flex gap8">
              <button class="btn primary" :disabled="capping" @click="doCapture">
                <span v-if="capping" class="typing"><span></span><span></span><span></span></span>
                <span v-else v-html="ic('play',15)+'<span>开始抓包</span>'"></span>
              </button>
              <button class="btn" @click="loadCaps">刷新文件列表</button>
            </div>
            <div class="grow"></div>
            <span class="fs12 muted">常用过滤：host 10.0.0.1 / port 80 / tcp port 443 / icmp / ether host 00:11:22:33:44:55</span>
          </div>

          <div v-if="capOut" class="mt12 col gap8">
            <div class="card tight" :style="{borderColor: capOut.ok===false?'var(--danger)':'var(--border)'}">
              <div class="card-head" style="margin-bottom:6px">
                <span class="fs12 fw5">抓包结果</span>
                <div class="grow"></div>
                <span class="src-badge" :class="capOut.engine==='device'?'manual':'zabbix'">{{ capOut.engine==='device'?'设备侧':'本机' }}</span>
              </div>
              <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(130px,1fr))">
                <div class="l fs12 muted">文件<div class="mono" style="color:var(--text)">{{ capOut.file || '-' }}</div></div>
                <div class="l fs12 muted">大小<div class="mono" style="color:var(--text)">{{ fmt.bytes(capOut.size) }}</div></div>
                <div class="l fs12 muted">网卡<div class="mono" style="color:var(--text)">{{ capOut.iface || '-' }}</div></div>
                <div class="l fs12 muted">耗时<div class="mono" style="color:var(--text)">{{ capOut.seconds || '-' }}s</div></div>
              </div>
              <div class="mt8" v-if="capOut.commands">
                <div class="fs12 fw5 mb8">设备侧抓包命令</div>
                <pre class="code-block" style="max-height:160px">{{ capOut.commands.join('\\n') }}</pre>
              </div>
              <div class="mt8" v-if="capOut.output">
                <div class="fs12 fw5 mb8">设备回显</div>
                <pre class="code-block" style="max-height:220px">{{ capOut.output }}</pre>
              </div>
              <div v-if="capOut.error" class="row mt8" style="color:var(--danger)"><span v-html="ic('alert',14)"></span><span class="fs12">{{ capOut.error }}</span></div>
              <div class="flex gap8 mt8">
                <a v-if="capOut.id && capOut.engine!=='device'" class="btn sm" :href="'/api/capture/'+capOut.id+'/download?token='+encodeURIComponent(token)">下载 pcap</a>
                <button class="btn sm" @click="copyCap">复制命令</button>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('file',15)"></span><span>抓包文件（{{ caps.length }}）</span>
            <div class="grow"></div><button class="btn sm" @click="loadCaps" v-html="ic('refresh',13)"></button></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:110px">标识</th><th style="width:170px">时间</th><th style="width:90px">引擎</th><th style="width:110px">大小</th><th style="width:110px">目标</th><th>过滤</th><th style="width:120px">操作</th></tr></thead>
              <tbody>
                <tr v-for="c in caps" :key="c.id">
                  <td class="mono fs11">{{ c.file || c.id }}</td>
                  <td class="fs11 muted">{{ fmt.time(c.at) }}</td>
                  <td><span class="tag" :class="c.engine==='device'?'violet':'green'">{{ c.engine==='device'?'设备':'本机' }}</span></td>
                  <td class="mono-num">{{ fmt.bytes(c.size) }}</td>
                  <td class="mono fs11">{{ c.host || 'local' }}</td>
                  <td class="mono fs11 ellipsis" :title="c.filter||''">{{ c.filter || '（全部）' }}</td>
                  <td>
                    <a v-if="c.engine!=='device'" class="btn sm" :href="'/api/capture/'+c.id+'/download?token='+encodeURIComponent(token)">下载</a>
                    <span v-else class="fs11 muted">—</span>
                  </td>
                </tr>
                <tr v-if="!caps.length"><td colspan="7" class="tbl-empty">暂无抓包文件</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>`,
    setup() {
      const tab = ref('locate');
      const devices = ref([]);
      /* 定位 */
      const locQ = ref(''), locRes = ref(null), locating = ref(false);
      /* 表查询 */
      const tblHost = ref(''), kind = ref('mac'), tblKw = ref(''), tblRows = ref([]);
      /* 会话分析 */
      const flowHost = ref(''), flowTop = ref([]), flowRaw = ref([]), flowStat = reactive({ total: 0, pairs: 0, bytes: 0 });
      /* 抓包 */
      const diag = reactive({ engine: '', path: '', ready: false, hint: '', localInterfaces: [] });
      const ifaces = ref([]), ifaceList = ref([]);
      const capEngine = ref('auto'), capHost = ref(''), capSec = ref(15), capIface = ref(''), capFilter = ref('');
      const capping = ref(false), capOut = ref(null);
      const caps = ref([]);

      const TABS_ = TABS;
      const ic = (n, s) => icon(n, s);
      const openHost = (h) => { const d = devices.value.find(x => x.host === h); if (d) go('/terminal'); toast('请在终端页选择设备 ' + (d.name || h), 'info'); };

      const TBL_COLS = {
        mac: [['vlan', 'VLAN'], ['mac', 'MAC 地址'], ['type', '类型'], ['port', '端口'], ['ip', 'IP 地址']],
        arp: [['ip', 'IP 地址'], ['mac', 'MAC 地址'], ['age', 'Age(分)'], ['iface', '接口']],
        session: [['src', '源地址'], ['sport', '源端口'], ['dst', '目的地址'], ['dport', '目的端口'], ['proto', '协议'], ['bytes', '字节']]
      };
      const tblCols = computed(() => (TBL_COLS[kind.value] || []).map(x => x[1]));
      const tblKeys = computed(() => (TBL_COLS[kind.value] || []).map(x => x[0]));

      const locGroups = computed(() => {
        if (!locRes.value) return [];
        const out = [];
        if (locRes.value.hits.mac.length) out.push({
          key: 'MAC 地址表命中', cols: ['设备', 'VLAN', 'MAC 地址', '类型', '端口', 'IP'],
          keys: ['host', 'vlan', 'mac', 'type', 'port', 'ip'], rows: locRes.value.hits.mac
        });
        if (locRes.value.hits.arp.length) out.push({
          key: 'ARP 表命中', cols: ['设备', 'IP 地址', 'MAC 地址', 'Age', '接口'],
          keys: ['host', 'ip', 'mac', 'age', 'iface'], rows: locRes.value.hits.arp
        });
        return out;
      });

      const flowMax = computed(() => Math.max(1, ...flowTop.value.map(r => r.bytes || 0)));
      const optFlow = computed(() => {
        const base = NC.chartBase(false), ax = NC.AXIS(false);
        const names = flowTop.value.slice(0, 12).map(r => `${shortIp(r.src)}→${shortIp(r.dst)}`);
        return {
          ...base,
          grid: { left: 8, right: 20, top: 24, bottom: 4, containLabel: true },
          tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
          xAxis: { type: 'value', ...ax },
          yAxis: { type: 'category', data: names, ...ax, splitLine: { show: false } },
          series: [{
            type: 'bar', data: flowTop.value.slice(0, 12).map(r => r.flows), barWidth: '56%',
            itemStyle: { borderRadius: [0, 4, 4, 0], color: { type: 'linear', x: 0, y: 0, x2: 1, y2: 0, colorStops: [{ offset: 0, color: '#3b82f6' }, { offset: 1, color: '#22d3ee' }] } },
            label: { show: true, position: 'right', fontSize: 11, color: '#5a6a80' }
          }]
        };
      });
      const shortIp = (s) => String(s || '').split('.').slice(-2).join('.');

      const capBytes = computed(() => caps.value.reduce((a, c) => a + (Number(c.size) || 0), 0));
      /* 下载 pcap 等接口要把 token 带在 query 上，模板里用 token 而不是直接摸 NC.state */
      const token = computed(() => (NC.state && NC.state.token) || '');
      const demoTag = computed(() => devices.value.length ? `${devices.value.length} 台设备可查` : '');

      async function loadDevices() {
        try {
          const d = await api.get('/devices');
          devices.value = d.rows || [];
          if (!tblHost.value && devices.value.length) { tblHost.value = devices.value[0].host; flowHost.value = devices.value[0].host; }
        } catch (e) { }
      }

      async function doLocate() {
        const q = locQ.value.trim();
        if (!q) return toast('请输入 IP 或 MAC', 'warn');
        locating.value = true;
        try { locRes.value = await api.get('/session/locate?q=' + encodeURIComponent(q)); }
        catch (e) { toast(e.message, 'err'); } finally { locating.value = false; }
      }

      async function loadTable() {
        try {
          const r = await api.get(`/session/table?host=${encodeURIComponent(tblHost.value)}&kind=${kind.value}&keyword=${encodeURIComponent(tblKw.value)}`);
          tblRows.value = r.rows || [];
        } catch (e) { toast(e.message, 'err'); }
      }
      watch(kind, () => loadTable());
      watch(tblHost, () => loadTable());
      function exportTable() {
        const keys = tblKeys.value;
        const head = tblCols.value;
        const csv = '\ufeff' + [head, ...tblRows.value.map(r => keys.map(k => r[k] ?? ''))]
          .map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\r\n');
        const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
        const a = document.createElement('a'); a.href = url; a.download = `${tblHost.value}-${kind.value}.csv`; a.click(); URL.revokeObjectURL(url);
      }

      async function loadFlow() {
        try {
          const r = await api.get('/session/flow?host=' + encodeURIComponent(flowHost.value));
          flowTop.value = r.top || []; flowRaw.value = r.raw || [];
          flowStat.total = r.total || 0; flowStat.pairs = (r.top || []).length;
          flowStat.bytes = (r.top || []).reduce((a, b) => a + (b.bytes || 0), 0);
        } catch (e) { toast(e.message, 'err'); }
      }

      async function loadDiag() {
        try {
          const r = await api.get('/capture/diagnose');
          Object.assign(diag, r);
          ifaces.value = r.interfaces || [];
          ifaceList.value = r.localInterfaces || [];
        } catch (e) { }
      }
      async function loadCaps() {
        try { const r = await api.get('/capture/list'); caps.value = r.rows || []; } catch (e) { }
      }
      async function doCapture() {
        capping.value = true; capOut.value = null;
        try {
          const r = await api.post('/capture/start', {
            iface: capIface.value, filter: capFilter.value.trim(),
            seconds: Number(capSec.value) || 15, host: capHost.value, engine: capEngine.value
          });
          capOut.value = r;
          if (r.error) toast(r.error, 'warn');
          else toast(r.engine === 'device' ? '设备侧抓包命令已下发' : '抓包完成', 'ok');
          await loadCaps();
        } catch (e) { toast(e.message, 'err'); } finally { capping.value = false; }
      }
      function copyCap() {
        const txt = (capOut.value?.commands || []).join('\n');
        if (!txt) return toast('没有可复制的命令', 'warn');
        navigator.clipboard?.writeText(txt).then(() => toast('已复制', 'ok')).catch(() => toast('复制失败', 'warn'));
      }

      onMounted(async () => {
        await loadDevices();
        loadDiag(); loadCaps();
      });

      return {
        TABS: TABS_, tab, devices, locQ, locRes, locating, doLocate, locGroups, demoTag,
        tblHost, kind, tblKw, tblRows, tblCols, tblKeys, loadTable, exportTable,
        flowHost, flowTop, flowRaw, flowStat, flowMax, optFlow, loadFlow,
        diag, ifaces, ifaceList, capEngine, capHost, capSec, capIface, capFilter,
        capping, capOut, caps, capBytes, token, doCapture, loadCaps, loadDiag, copyCap,
        ic, go, fmt, openHost
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.TrafficPage = TrafficPage;
  NC.route('/traffic', { title: '会话与流量', comp: 'TrafficPage' });
})();
