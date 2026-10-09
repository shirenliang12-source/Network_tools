/* =========================================================================
   全流量回溯：协议总览 · 会话检索 · 协议字典 · pcap 解析入库
   数据来自旁路采集引擎落库的 flow_sessions 表（/api/flow/*）
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, watch, nextTick } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const TABS = [
    { k: 'stats', n: '协议总览', i: 'pie' },
    { k: 'sessions', n: '会话检索', i: 'search' },
    { k: 'protocols', n: '协议字典', i: 'list' },
    { k: 'parse', n: 'pcap 解析', i: 'camera' }
  ];

  const PROTO_COLOR = {
    http: '#2563eb', https: '#7c3aed', tls: '#7c3aed', dns: '#0891b2', ssh: '#16a34a',
    telnet: '#65a30d', 'modbus-tcp': '#dc2626', s7comm: '#dc2626', 'opc-ua': '#dc2626',
    mqtt: '#f59e0b', mysql: '#db2777', postgresql: '#db2777', mssql: '#db2777',
    redis: '#ef4444', smb: '#475569', ntp: '#0d9488', snmp: '#4f46e5', tcp: '#94a3b8',
    udp: '#94a3b8', ip: '#94a3b8', unknown: '#94a3b8', other: '#94a3b8'
  };
  const protoColor = (p) => PROTO_COLOR[String(p || '').toLowerCase()] || '#64748b';

  const FlowPage = {
    name: 'FlowPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
        <div class="grow"></div>
        <span class="fs12 muted">{{ scanHint }}</span>
      </div>

      <!-- ==================== 协议总览 ==================== -->
      <div v-show="tab==='stats'" class="col gap16">
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr))">
          <div class="result-box"><div class="l fs12 muted">会话总数</div><div class="big">{{ fmt.num(stats.total||0) }}</div><div class="fs11 muted">累计采集</div></div>
          <div class="result-box"><div class="l fs12 muted">协议种类</div><div class="big" style="color:var(--primary)">{{ stats.byProto.length }}</div><div class="fs11 muted">DPI 识别结果</div></div>
          <div class="result-box"><div class="l fs12 muted">累计流量</div><div class="big" style="color:var(--primary)">{{ fmt.bytes(totalBytes) }}</div><div class="fs11 muted">四层载荷体积</div></div>
          <div class="result-box"><div class="l fs12 muted">覆盖时段</div><div class="big" style="font-size:16px">{{ spanText }}</div><div class="fs11 muted">{{ stats.span?.from ? fmt.timeShort(stats.span.from)+' 起' : '暂无数据' }}</div></div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('pie',15)"></span><span>协议构成（按流量）</span>
            <div class="grow"></div><button class="btn sm" @click="loadStats" v-html="ic('refresh',13)+'<span>刷新</span>'"></button></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:150px">协议</th><th style="width:90px">会话数</th><th style="width:150px">占比</th><th style="width:120px">流量</th><th style="width:90px">报文数</th><th style="width:200px">特征端口</th></tr></thead>
              <tbody>
                <tr v-for="p in stats.byProto" :key="p.proto">
                  <td><span class="tag" :style="{color:protoColor(p.proto),borderColor:protoColor(p.proto)+'55',background:protoColor(p.proto)+'14'}">{{ p.proto }}</span>
                      <span class="fs11 muted" v-if="protoTag(p.proto)"> · {{ protoTag(p.proto) }}</span></td>
                  <td class="mono-num">{{ p.sessions }}</td>
                  <td><NcBar :value="p.sessions" :max="maxSessions" :color="protoColor(p.proto)"></NcBar></td>
                  <td class="mono">{{ fmt.bytes(p.bytes) }}</td>
                  <td class="mono-num">{{ fmt.num(p.pkts) }}</td>
                  <td class="mono fs11 muted ellipsis" style="max-width:200px">{{ (pPorts(p.proto)||[]).slice(0,8).join(', ') }}</td>
                </tr>
                <tr v-if="!stats.byProto.length"><td colspan="6" class="tbl-empty">暂无会话数据，先到「pcap 解析」导入，或启动旁路采集任务</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="card" v-if="stats.topPairs.length">
          <div class="card-head"><span v-html="ic('activity',15)"></span><span>流量 Top 汇聚对</span></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:60px">#</th><th>源 → 目的</th><th style="width:110px">应用协议</th><th style="width:110px">会话数</th><th style="width:140px">流量</th></tr></thead>
              <tbody>
                <tr v-for="(p,i) in stats.topPairs" :key="i">
                  <td class="mono muted">{{ i+1 }}</td>
                  <td class="mono ellipsis">
                    <a href="javascript:" @click="ip=p.key.split('→')[0].split(':')[0];loadSessions()">{{ p.key.split('→')[0] }}</a>
                    <span class="muted"> → </span>
                    <a href="javascript:" @click="ip=p.key.split('→')[1].split(':')[0];loadSessions()">{{ p.key.split('→')[1] }}</a>
                  </td>
                  <td><span class="tag">{{ p.appProto }}</span></td>
                  <td class="mono-num">{{ p.count }}</td>
                  <td>{{ fmt.bytes(p.bytes) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ==================== 会话检索 ==================== -->
      <div v-show="tab==='sessions'" class="col gap16">
        <div class="card">
          <div class="filter-bar">
            <div class="search-box" style="flex:1;min-width:260px">
              <span v-html="ic('search',15)"></span>
              <input class="inp" v-model.trim="ip" @keydown.enter="search()" placeholder="源/目的 IP 或前缀，如 10.252.28" style="min-width:180px">
            </div>
            <select class="inp" v-model="proto" style="max-width:180px" @change="search()">
              <option value="">全部协议</option>
              <option v-for="p in protoOpts" :key="p" :value="p">{{ p }}</option>
            </select>
            <select class="inp" v-model="range" style="max-width:150px" @change="search()">
              <option value="">全部时间</option>
              <option value="1">近 1 小时</option>
              <option value="24">近 24 小时</option>
              <option value="72">近 3 天</option>
              <option value="720">近 30 天</option>
            </select>
            <button class="btn primary" @click="search()" v-html="ic('search',15)+'<span>检索</span>'"></button>
            <button class="btn" @click="resetFilter">重置</button>
            <div class="grow"></div>
            <span class="fs12 muted">命中 {{ sTotal }} 条</span>
            <button class="btn" @click="loadSessions" v-html="ic('refresh',15)"></button>
          </div>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>点击任意一行查看会话详情（载荷特征、SNI、DNS 查询名、关联 pcap）。</span></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr>
                <th style="width:140px">开始时间</th><th>源</th><th>目的</th><th style="width:120px">应用协议</th>
                <th style="width:80px">方向</th><th style="width:80px">报文</th><th style="width:110px">字节</th><th style="width:90px">时长</th><th style="width:130px">来源文件</th>
              </tr></thead>
              <tbody>
                <tr v-for="(r,i) in rows" :key="r.id||i" @click="openDetail(r)" style="cursor:pointer">
                  <td class="mono muted">{{ fmt.timeShort(r.startedAt) }}</td>
                  <td class="mono ellipsis" style="max-width:160px">{{ r.srcIp }}<span class="fs11 muted">:{{ r.srcPort }}</span></td>
                  <td class="mono ellipsis" style="max-width:160px">{{ r.dstIp }}<span class="fs11 muted">:{{ r.dstPort }}</span></td>
                  <td><span class="tag" :style="{color:protoColor(r.appProto),borderColor:protoColor(r.appProto)+'55',background:protoColor(r.appProto)+'14'}">{{ r.appProto || r.proto }}</span></td>
                  <td class="mono fs11 muted">{{ dirText(r) }}</td>
                  <td class="mono-num">{{ r.pkts }}</td>
                  <td class="mono">{{ fmt.bytes(r.bytes) }}</td>
                  <td class="mono">{{ fmt.dur((r.durationMs||0)/1000) }}</td>
                  <td class="mono fs11 ellipsis" style="max-width:130px" :title="r.fileId">{{ r.fileId || '-' }}</td>
                </tr>
                <tr v-if="!rows.length"><td colspan="9" class="tbl-empty">没有匹配的会话，换个条件试试</td></tr>
              </tbody>
            </table>
          </div>
          <NcPager :page="page" :size="size" :total="sTotal" @update:page="p=>{page=p;loadSessions()}"></NcPager>
        </div>
      </div>

      <!-- ==================== 会话详情 ==================== -->
      <NcDrawer v-if="detail" :title="'会话详情 ' + (detail.session?.srcIp || '')" wide @close="detail=null">
        <div v-if="detail" class="col gap16">
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
            <div class="result-box"><div class="l fs12 muted">传输层</div><div class="big" style="font-size:16px">{{ detail.session.proto?.toUpperCase() }}</div><div class="fs11 muted">四层协议</div></div>
            <div class="result-box"><div class="l fs12 muted">应用协议</div><div class="big" style="font-size:16px;color:var(--primary)">{{ detail.session.appProto || '未识别' }}</div><div class="fs11 muted">DPI 判定</div></div>
            <div class="result-box"><div class="l fs12 muted">报文 / 字节</div><div class="big" style="font-size:16px">{{ detail.session.pkts }} / {{ fmt.bytes(detail.session.bytes) }}</div><div class="fs11 muted">双向累计</div></div>
            <div class="result-box"><div class="l fs12 muted">时长</div><div class="big" style="font-size:16px">{{ fmt.dur((detail.session.durationMs||0)/1000) }}</div><div class="fs11 muted">{{ fmt.time(detail.session.startedAt) }}</div></div>
          </div>

          <div class="card">
            <div class="card-head"><span v-html="ic('share',15)"></span><span>五元组</span></div>
            <div class="mono fs13" style="line-height:2">
              {{ detail.session.srcIp }}<span class="muted">:{{ detail.session.srcPort }}</span>
              <span class="muted"> → </span>{{ detail.session.dstIp }}<span class="muted">:{{ detail.session.dstPort }}</span>
            </div>
            <div class="row gap8 mt12" v-if="detail.session.tags?.length">
              <span v-for="t in detail.session.tags" :key="t" class="tag">{{ t }}</span>
            </div>
          </div>

          <div class="card" v-if="hintRows.length">
            <div class="card-head"><span v-html="ic('info',15)"></span><span>载荷特征</span></div>
            <div class="table-wrap">
              <table class="ntable"><tbody>
                <tr v-for="h in hintRows" :key="h.k"><td style="width:120px" class="fs12 muted">{{ h.k }}</td><td class="mono ellipsis">{{ h.v }}</td></tr>
              </tbody></table>
            </div>
          </div>

          <div class="card" v-if="detail.file">
            <div class="card-head"><span v-html="ic('camera',15)"></span><span>关联抓包文件</span></div>
            <div class="fs13">原始 pcap：<a :href="'/api/capture/' + detail.file.id + '/download'" target="_blank" class="mono">{{ detail.file.name || detail.file.id }}</a>
              <span class="muted"> · {{ fmt.bytes(detail.file.size) }}</span></div>
          </div>
        </div>
        <template #foot>
          <button class="btn" @click="copyLine">复制五元组</button>
          <button class="btn primary" @click="ip = detail.session.srcIp; detail = null; tab = 'sessions'; loadSessions()">以此主机再检索</button>
        </template>
      </NcDrawer>

      <!-- ==================== 协议字典 ==================== -->
      <div v-show="tab==='protocols'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('list',15)"></span><span>内置协议特征表</span>
            <div class="grow"></div><span class="fs12 muted">共 {{ dictTotal }} 类</span></div>
          <div class="filter-bar">
            <div class="search-box" style="flex:1;max-width:340px">
              <span v-html="ic('search',15)"></span>
              <input class="inp" v-model.trim="dictKw" placeholder="按协议名或端口号过滤" @keydown.enter="loadDict">
            </div>
            <button class="btn" @click="loadDict" v-html="ic('search',15)"></button>
          </div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:160px">协议</th><th style="width:140px">归类</th><th>特征端口</th></tr></thead>
              <tbody>
                <tr v-for="d in dictRows" :key="d.proto">
                  <td><span class="tag" :style="{color:protoColor(d.proto),borderColor:protoColor(d.proto)+'55',background:protoColor(d.proto)+'14'}">{{ d.proto }}</span></td>
                  <td class="fs12 muted">{{ d.tag || '-' }}</td>
                  <td class="mono fs11 muted">{{ d.ports.join(', ') }}</td>
                </tr>
                <tr v-if="!dictRows.length"><td colspan="3" class="tbl-empty">没有匹配的协议</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ==================== pcap 解析 ==================== -->
      <div v-show="tab==='parse'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('camera',15)"></span><span>解析抓包文件</span></div>
          <div class="filter-bar">
            <div class="search-box" style="flex:1;min-width:280px">
              <span v-html="ic('file',15)"></span>
              <input class="inp" v-model.trim="pcapFile" placeholder="填写 data/captures 下的文件名，如 capture-2026.pcap" @keydown.enter="doParse">
            </div>
            <label class="checkbox"><input type="checkbox" v-model="persist"> 解析结果入库</label>
            <button class="btn primary" :disabled="parsing" @click="doParse" v-html="parsing?'解析中…':ic('play',15)+'<span>解析</span>'"></button>
          </div>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>不勾选则只做解析预览；勾选后会话写入会话库，可在「会话检索」中查询与回溯。</span></div>
          <div class="grid mt12" v-if="parseRes.packets!==undefined" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
            <div class="result-box"><div class="l fs12 muted">报文数</div><div class="big">{{ fmt.num(parseRes.packets) }}</div><div class="fs11 muted">linktype {{ parseRes.linkType }}</div></div>
            <div class="result-box"><div class="l fs12 muted">会话数</div><div class="big" style="color:var(--primary)">{{ parseRes.sessions.length }}</div><div class="fs11 muted">{{ parseRes.truncated ? '已截断（超过上限）' : '完整解析' }}</div></div>
            <div class="result-box" v-if="parseRes.inserted!==undefined"><div class="l fs12 muted">入库</div><div class="big" style="color:var(--success)">{{ parseRes.inserted }}</div><div class="fs11 muted">写入会话库</div></div>
          </div>
          <div class="table-wrap mt12" v-if="parseRes.sessions?.length">
            <table class="ntable">
              <thead><tr><th style="width:130px">时间</th><th>源</th><th>目的</th><th style="width:110px">应用协议</th><th style="width:80px">报文</th><th style="width:100px">字节</th><th>特征</th></tr></thead>
              <tbody>
                <tr v-for="(s,i) in parseRes.sessions" :key="i">
                  <td class="mono muted">{{ fmt.timeShort(s.startedAt) }}</td>
                  <td class="mono ellipsis" style="max-width:150px">{{ s.srcIp }}:{{ s.srcPort }}</td>
                  <td class="mono ellipsis" style="max-width:150px">{{ s.dstIp }}:{{ s.dstPort }}</td>
                  <td><span class="tag" :style="{color:protoColor(s.appProto)}">{{ s.appProto }}</span></td>
                  <td class="mono-num">{{ s.pkts }}</td>
                  <td class="mono">{{ fmt.bytes(s.bytes) }}</td>
                  <td class="mono fs11 ellipsis" style="max-width:220px" :title="hintText(s.hint)">{{ hintText(s.hint) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>`,
    setup() {
      const TABS_ = TABS;
      const tab = ref('stats');
      const stats = reactive({ total: 0, byProto: [], topPairs: [], span: {} });
      const protoOpts = ref([]);
      const dictRows = ref([]), dictKw = ref('');
      const dictTotal = ref(0);   /* 内置协议特征表的全量条数（不受过滤影响） */

      /* --- 检索 --- */
      const ip = ref(''), proto = ref(''), fileId = ref('');
      const range = ref('');
      const rows = ref([]), sTotal = ref(0), page = ref(1), size = 100;
      const detail = ref(null);

      /* --- 解析 --- */
      const pcapFile = ref(''), persist = ref(false), parsing = ref(false);
      const parseRes = reactive({ sessions: [] });

      const maxSessions = computed(() => Math.max(1, ...stats.byProto.map(p => p.sessions)));
      const totalBytes = computed(() => stats.byProto.reduce((a, b) => a + Number(b.bytes || 0), 0));
      const spanText = computed(() => {
        const s = stats.span || {};
        if (!s.from || !s.to) return '暂无';
        const d = Math.max(0, new Date(s.to).getTime() - new Date(s.from).getTime()) / 1000;
        return fmt.dur(d);
      });
      const scanHint = computed(() => stats.total ? `已采集 ${fmt.num(stats.total)} 条会话` : '');

      const ic = (n, s) => icon(n, s);
      // 注意：此处不可再定义同名 protoColor，否则会遮蔽 23 行的实现并无限递归
      const protoTag = (p) => { const d = dictRows.value.find(x => x.proto === p); return d ? d.tag : ''; };
      const pPorts = (p) => { const d = dictRows.value.find(x => x.proto === p); return d ? d.ports : []; };
      // 按知名端口粗判角色：目的端口是知名端口说明本机是发起方
      const dirText = (r) => (Number(r.dstPort) > 0 && Number(r.dstPort) <= 1024 ? '发起' : '响应');
      const hintText = (h) => {
        h = h || {};
        return h.method ? `${h.method} ${h.uri || ''}${h.host ? ' @' + h.host : ''}`
          : h.sni ? `SNI ${h.sni}` : h.qname ? `DNS ${h.qname}`
            : h.banner ? `SSH ${h.banner}` : h.ver ? `TLS ${h.ver}` : '';
      };
      const hintRows = computed(() => {
        const h = detail.value?.session?.hint || {};
        const out = [];
        if (h.method) out.push({ k: 'HTTP 方法', v: h.method });
        if (h.uri) out.push({ k: '请求路径', v: h.uri });
        if (h.host) out.push({ k: 'Host', v: h.host });
        if (h.ua) out.push({ k: 'User-Agent', v: h.ua });
        if (h.sni) out.push({ k: 'TLS SNI', v: h.sni });
        if (h.ver) out.push({ k: 'TLS 版本', v: h.ver });
        if (h.qname) out.push({ k: 'DNS 查询', v: `${h.qname}${h.qtype ? ' (type ' + h.qtype + ')' : ''}` });
        if (h.banner) out.push({ k: 'SSH 版本', v: h.banner });
        return out;
      });
      const copyLine = async () => {
        const s = detail.value?.session || {};
        const t = `${s.srcIp}:${s.srcPort} → ${s.dstIp}:${s.dstPort} (${s.appProto || s.proto}, ${s.pkts} 包 / ${s.bytes} 字节)`;
        navigator.clipboard?.writeText(t).then(() => toast('已复制五元组', 'ok')).catch(() => toast('复制失败', 'warn'));
      };

      async function loadStats() {
        try {
          const r = await api.get('/flow/stats');
          Object.assign(stats, { total: r.total, byProto: r.byProto || [], topPairs: r.topPairs || [], span: r.span || {} });
          protoOpts.value = [...new Set((r.byProto || []).map(p => p.proto).filter(Boolean))];
        } catch (e) { }
      }
      async function loadDict() {
        try {
          const r = await api.get('/flow/protocols');
          const kw = dictKw.value.toLowerCase();
          dictTotal.value = (r.rows || []).length;
          dictRows.value = kw ? r.rows.filter(d => d.proto.includes(kw) || d.tag?.includes(kw) || d.ports.some(p => String(p).includes(kw))) : r.rows;
        } catch (e) { }
      }
      async function loadSessions() {
        const qs = new URLSearchParams();
        if (ip.value) qs.set('ip', ip.value);
        if (proto.value) qs.set('proto', proto.value);
        if (range.value) {
          const from = new Date(Date.now() - Number(range.value) * 3600000).toISOString();
          qs.set('from', from);
        }
        qs.set('limit', String(size));
        qs.set('offset', String((page.value - 1) * size));
        try {
          const r = await api.get('/flow/sessions?' + qs.toString());
          rows.value = r.rows || [];
          sTotal.value = r.total || 0;
        } catch (e) { toast(e.message, 'err'); }
      }
      const search = () => { page.value = 1; loadSessions(); };
      const resetFilter = () => { ip.value = ''; proto.value = ''; range.value = ''; page.value = 1; loadSessions(); };
      const openDetail = async (r) => {
        try {
          const d = await api.get('/flow/sessions/' + encodeURIComponent(r.id));
          detail.value = d;
        } catch (e) { toast(e.message, 'err'); }
      };

      async function doParse() {
        if (!pcapFile.value) return toast('请输入抓包文件名', 'warn');
        parsing.value = true;
        parseRes.sessions = [];
        try {
          const r = await api.post('/flow/parse', { file: pcapFile.value.trim(), persist: persist.value ? 1 : 0 });
          Object.assign(parseRes, { packets: r.packets, sessions: r.sessions || [], linkType: r.linkType, truncated: r.truncated, inserted: r.inserted });
          toast(`解析完成：${r.packets} 包 / ${(r.sessions || []).length} 会话${persist.value ? `，入库 ${r.inserted} 条` : ''}`, 'ok');
          if (persist.value) loadStats();
        } catch (e) { toast(e.message, 'err'); } finally { parsing.value = false; }
      }

      watch(tab, (t) => {
        if (t === 'sessions') loadSessions();
        if (t === 'protocols') loadDict();
      });

      onMounted(() => {
        loadStats();
        loadDict();
        if (ip.value || proto.value) loadSessions();
      });

      return {
        TABS: TABS_, tab, stats, fmt, protoOpts, dictRows, dictKw, loadDict, ic, protoColor, protoTag, pPorts, loadStats, dictTotal,
        ip, proto, fileId, range, rows, sTotal, page, size, loadSessions, search, resetFilter, openDetail, detail,
        dirText, hintText, hintRows, copyLine,
        maxSessions, totalBytes, spanText, scanHint,
        pcapFile, persist, parsing, parseRes, doParse
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.FlowPage = FlowPage;
  NC.route('/flow', { title: '全流量回溯', comp: 'FlowPage' });
})();
