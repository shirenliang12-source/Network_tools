/* =========================================================================
   内网测速：内置吞吐 / iperf3 / 浏览器 HTTP / 设备链路 / 延迟丢包探测
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, nextTick } = Vue;
  const NC = window.NC, { api, fmt, icon, toast } = NC;

  const TABS = [
    { k: 'server', n: '测速服务端', i: 'server' },
    { k: 'builtin', n: '吞吐 / iperf3', i: 'activity' },
    { k: 'http', n: '浏览器 HTTP', i: 'download' },
    { k: 'probe', n: '延迟丢包探测', i: 'wifi' },
    { k: 'history', n: '测速历史', i: 'clock' }
  ];

  const SPEED_PRESETS = [50, 100, 200, 500];

  const SpeedPage = {
    name: 'SpeedPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
      </div>

      <!-- ============ 服务端 ============ -->
      <div v-show="tab==='server'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('server',15)"></span><span>本机作为测速服务端</span></div>
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(190px,1fr))">
            <div class="result-box"><div class="l fs12 muted">内置吞吐端口</div><div class="big lat">{{ srv.port || '-' }}</div><div class="fs11 muted">其他电脑向此端口测速</div></div>
            <div class="result-box"><div class="l fs12 muted">iperf3</div>
              <div class="big" :style="{fontSize:17,color: srv.iperf && srv.iperf.available ? 'var(--success)':'var(--warn)'}">{{ srv.iperf && srv.iperf.available ? '可用' : '未安装' }}</div>
              <div class="fs11 muted ellipsis" :title="(srv.iperf||{}).hint">{{ (srv.iperf||{}).hint || (srv.iperf||{}).path || '—' }}</div></div>
            <div class="result-box"><div class="l fs12 muted">HTTP 测速端口</div><div class="big">{{ srv.httpPort || '同端口' }}</div><div class="fs11 muted">浏览器下载 / 上传</div></div>
          </div>

          <div class="fs13 fw5 mt12 mb8">局域网地址（任何人可用这些地址访问本控制台）</div>
          <div class="flex" style="gap:6px;flex-wrap:wrap">
            <span v-for="i in srv.ips" :key="i.address" class="tag" style="font-family:var(--mono);font-size:12px">
              {{ i.address }} <span class="muted">/{{ i.cidr }}</span> <span class="muted">{{ i.name }}</span>
            </span>
            <span v-if="!srv.ips.length" class="fs12 muted">未检测到局域网地址</span>
          </div>

          <div class="fs13 fw5 mt12 mb8">对端发起测速的三种方式</div>
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px">
            <div class="result-box">
              <div class="l fs12 muted">① 用 iperf3（推荐，最权威）</div>
              <pre class="code-block" style="max-height:none;font-size:11.5px">iperf3 -c {{ (srv.ips[0]||{}).address || '127.0.0.1' }} -p {{ srv.port }} -t 10</pre>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">② 内置引擎（零依赖）</div>
              <div class="fs11 muted" style="line-height:1.7">打开「吞吐 / iperf3」页，填目标 IP 与端口 {{ srv.port }} 直接测，无需安装任何软件。</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">③ 浏览器 HTTP</div>
              <div class="fs11 muted" style="line-height:1.7">打开「浏览器 HTTP」页，由浏览器直接下载 / 上传，反映真实用户体验。</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ============ 吞吐 / iperf3 ============ -->
      <div v-show="tab==='builtin'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('activity',15)"></span><span>吞吐测试</span></div>
          <div class="form-grid">
            <label>目标地址<input class="inp mono" v-model="bt.host" placeholder="如 10.252.28.99（填本机地址可自测）"></label>
            <label>端口<input class="inp mono" v-model="bt.port" placeholder="5201"></label>
            <label>方向
              <select class="inp" v-model="bt.mode"><option value="download">下载（服务端 → 本机）</option><option value="upload">上传（本机 → 服务端）</option></select>
            </label>
            <label>时长（秒）<input class="inp" type="number" min="1" max="120" v-model="bt.seconds"></label>
            <label>并发流<input class="inp" type="number" min="1" max="32" v-model="bt.parallel"></label>
            <label class="checkbox" style="display:flex;align-items:center;gap:6px">
              <input type="checkbox" v-model="bt.useIperf" :disabled="!(srv.iperf||{}).available"> 使用 iperf3 引擎
            </label>
          </div>
          <div class="flex gap8 mt8">
            <button class="btn primary" :disabled="btBusy" @click="runBuiltin">
              <span v-if="btBusy" class="typing"><span></span><span></span><span></span></span>
              <span v-else v-html="ic('zap',15)+'<span>开始测试</span>'"></span>
            </button>
            <button class="btn" @click="bt = { host:'', port: srv.port||5201, seconds:8, parallel:1, mode:'download', useIperf:false }">重置</button>
            <div class="grow"></div>
            <span class="fs12 muted" v-html="(srv.iperf||{}).hint || ''"></span>
          </div>

          <div v-if="btRes" class="mt12">
            <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr))">
              <div class="result-box"><div class="l fs12 muted">平均吞吐</div>
                <div class="big" :class="(btRes.engine==='iperf3'||btRes.engine==='builtin') && btRes.bps ? 'up':''">{{ fmt.bps(btRes.bps) }}</div>
                <div class="fs11 muted">{{ btRes.engine==='self' ? '回环自测' : btRes.engine }}</div></div>
              <div class="result-box"><div class="l fs12 muted">实测时长</div><div class="big" style="color:var(--text-2)">{{ (btRes.seconds||0).toFixed(1) }}s</div><div class="fs11 muted">{{ btRes.parallel || 1 }} 条流</div></div>
              <div class="result-box"><div class="l fs12 muted">目标</div><div class="big mono" style="font-size:15px">{{ btRes.host || '本机' }}:{{ btRes.port || '-' }}</div><div class="fs11 muted">{{ btRes.mode || '-' }}</div></div>
            </div>
            <div v-if="btRes.note" class="hint-line mt8" style="color:var(--warn)"><span v-html="ic('alert',13)"></span><span>{{ btRes.note }}</span></div>
            <div v-if="btRes.error" class="row mt8" style="color:var(--danger)"><span v-html="ic('alert',14)"></span><span class="fs12">{{ btRes.error }}</span></div>
            <div v-if="btRes.raw" class="mt8"><div class="fs12 fw5 mb8">原始输出</div><pre class="code-block" style="max-height:200px">{{ btRes.raw }}</pre></div>
          </div>
        </div>

        <div class="card" v-if="runs.length">
          <div class="card-head"><span v-html="ic('clock',15)"></span><span>本页历史（{{ runs.length }}）</span>
            <div class="grow"></div><button class="btn sm" @click="runs=[]">清空</button></div>
          <div v-if="runs.length>1">
            <NcChart :option="optRuns" height="240px"></NcChart>
          </div>
          <div class="table-wrap mt12">
            <table class="ntable">
              <thead><tr><th style="width:150px">时间</th><th style="width:120px">目标</th><th style="width:90px">方向</th><th style="width:60px">并发</th><th style="width:130px">吞吐</th><th style="width:90px">引擎</th></tr></thead>
              <tbody>
                <tr v-for="(r,i) in runs" :key="i">
                  <td class="fs11 muted">{{ fmt.time(r.at) }}</td>
                  <td class="mono fs11">{{ r.host }}:{{ r.port }}</td>
                  <td>{{ r.mode }}</td>
                  <td class="mono-num">{{ r.parallel }}</td>
                  <td class="mono-num fw5">{{ fmt.bps(r.bps) }}</td>
                  <td><span class="tag">{{ r.engine }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ============ 浏览器 HTTP ============ -->
      <div v-show="tab==='http'" class="col gap16">
        <div class="grid" style="grid-template-columns:1fr 1fr;gap:16px">
          <div class="card">
            <div class="card-head"><span v-html="ic('download',15)"></span><span>浏览器下载测速</span></div>
            <div class="fs12 muted mb8">从服务端拉取大文件，测量「用户实际感受到的下载速度」。</div>
            <div class="flex" style="gap:6px;flex-wrap:wrap">
              <button v-for="p in SPEED_PRESETS" :key="p" class="btn sm" :class="{primary: dlMB===p}" @click="dlMB=p">{{ p }} MB</button>
            </div>
            <div class="flex gap8 mt8">
              <input class="inp mono" type="number" min="1" max="500" v-model="dlMB" style="max-width:120px">
              <span class="fs12 muted">MB</span>
              <div class="grow"></div>
              <button class="btn primary" :disabled="dlBusy" @click="dlTest">
                <span v-if="dlBusy" class="typing"><span></span><span></span><span></span></span>
                <span v-else v-html="ic('download',15)+'<span>开始下载</span>'"></span>
              </button>
              <button class="btn" :disabled="dlBusy" @click="dlStop">停止</button>
            </div>
            <div class="mt12" v-if="dlProg.pct>0">
              <div class="flex gap8 fs12"><span>已接收 {{ fmt.bytes(dlProg.bytes) }}</span><div class="grow"></div><span class="mono-num fw5">{{ dlProg.pct.toFixed(1) }}%</span></div>
              <div class="bar" style="margin-top:5px"><i :style="{width: dlProg.pct+'%', background:'var(--primary)'}"></i></div>
            </div>
            <div class="grid mt12" style="grid-template-columns:1fr 1fr">
              <div class="result-box"><div class="l fs12 muted">平均速率</div><div class="big lat" :class="{up: dlRes && dlRes.bps>0}">{{ dlRes ? fmt.bps(dlRes.bps) : '—' }}</div></div>
              <div class="result-box"><div class="l fs12 muted">耗时</div><div class="big" style="color:var(--text-2)">{{ dlRes ? dlRes.seconds.toFixed(2)+'s' : '—' }}</div></div>
            </div>
            <div v-if="dlRes" class="mt8">
              <div class="chart-pick"><span class="fs12 fw5">速率曲线</span></div>
              <NcChart :option="optDl" height="170px"></NcChart>
            </div>
          </div>

          <div class="card">
            <div class="card-head"><span v-html="ic('upload',15)"></span><span>浏览器上传测速</span></div>
            <div class="fs12 muted mb8">向服务端推送大文件，测量上行带宽与上传稳定性。</div>
            <div class="flex" style="gap:6px;flex-wrap:wrap">
              <button v-for="p in SPEED_PRESETS" :key="p" class="btn sm" :class="{primary: upMB===p}" @click="upMB=p">{{ p }} MB</button>
            </div>
            <div class="flex gap8 mt8">
              <input class="inp mono" type="number" min="1" max="200" v-model="upMB" style="max-width:120px">
              <span class="fs12 muted">MB</span>
              <div class="grow"></div>
              <button class="btn primary" :disabled="upBusy" @click="upTest">
                <span v-if="upBusy" class="typing"><span></span><span></span><span></span></span>
                <span v-else v-html="ic('upload',15)+'<span>开始上传</span>'"></span>
              </button>
              <button class="btn" :disabled="upBusy" @click="upStop">停止</button>
            </div>
            <div class="mt12" v-if="upProg.pct>0">
              <div class="flex gap8 fs12"><span>已发送 {{ fmt.bytes(upProg.bytes) }}</span><div class="grow"></div><span class="mono-num fw5">{{ upProg.pct.toFixed(1) }}%</span></div>
              <div class="bar" style="margin-top:5px"><i :style="{width: upProg.pct+'%', background:'var(--success)'}"></i></div>
            </div>
            <div class="grid mt12" style="grid-template-columns:1fr 1fr">
              <div class="result-box"><div class="l fs12 muted">平均速率</div><div class="big up" :class="{up: upRes && upRes.bps>0}">{{ upRes ? fmt.bps(upRes.bps) : '—' }}</div></div>
              <div class="result-box"><div class="l fs12 muted">耗时</div><div class="big" style="color:var(--text-2)">{{ upRes ? upRes.seconds.toFixed(2)+'s' : '—' }}</div></div>
            </div>
            <div v-if="upRes" class="mt8">
              <div class="fs12 fw5 mb8">速率曲线</div>
              <NcChart :option="optUp" height="170px"></NcChart>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><span v-html="ic('globe',15)"></span><span>结果说明</span></div>
          <div class="fs12 muted" style="line-height:1.8">
            · 下载结果受「浏览器 → 服务端」链路影响，包含 HTTP 传输开销，与 iperf3 结果通常相差 5%~15%。<br>
            · 上传走 <span class="mono">POST /api/speed/http/upload</span>，服务端仅统计字节数不落盘，测完即弃。<br>
            · 若数值偏低，可同时使用「延迟丢包探测」排查是否存在丢包或双工半双工问题。
          </div>
        </div>
      </div>

      <!-- ============ 探测 ============ -->
      <div v-show="tab==='probe'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('wifi',15)"></span><span>延迟 / 丢包 / 抖动探测</span></div>
          <div class="form-grid">
            <label style="grid-column:1/-1">探测目标（多个用空格或逗号分隔，IP 后可加 :端口 测 TCP）
              <input class="inp mono" v-model="pr.targets" placeholder="10.252.28.99 10.252.28.1 192.168.1.1:443"></label>
            <label>发包次数<input class="inp" type="number" min="1" max="50" v-model="pr.count"></label>
            <label>间隔（毫秒）<input class="inp" type="number" min="50" max="2000" v-model="pr.intervalMs"></label>
            <label>单次超时（毫秒）<input class="inp" type="number" min="500" max="10000" v-model="pr.timeoutMs"></label>
          </div>
          <div class="flex gap8 mt8">
            <button class="btn primary" :disabled="prBusy" @click="runProbe">
              <span v-if="prBusy" class="typing"><span></span><span></span><span></span></span>
              <span v-else v-html="ic('wifi',15)+'<span>开始探测</span>'"></span>
            </button>
            <div class="grow"></div>
            <span class="fs12 muted">{{ prRows.length }} 条结果</span>
          </div>
          <div class="grid mt12" v-if="prStat.total" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
            <div class="result-box"><div class="l fs12 muted">平均延迟</div><div class="big lat">{{ prStat.avg.toFixed(1) }}<span style="font-size:12px"> ms</span></div></div>
            <div class="result-box"><div class="l fs12 muted">平均丢包</div><div class="big" :class="prStat.loss>1?'down':'up'">{{ prStat.loss.toFixed(1) }}<span style="font-size:12px"> %</span></div></div>
            <div class="result-box"><div class="l fs12 muted">抖动</div><div class="big" style="color:var(--warn)">{{ prStat.jitter.toFixed(1) }}<span style="font-size:12px"> ms</span></div></div>
            <div class="result-box"><div class="l fs12 muted">最差延迟</div><div class="big" style="color:var(--danger)">{{ prStat.max.toFixed(1) }}<span style="font-size:12px"> ms</span></div></div>
          </div>
          <div class="table-wrap mt12">
            <table class="ntable">
              <thead><tr><th style="width:190px">目标</th><th style="width:80px">丢包</th><th style="width:90px">平均</th><th style="width:80px">最小</th><th style="width:80px">最大</th><th style="width:80px">抖动</th><th style="width:150px">TCP 连通</th><th style="width:200px">质量</th></tr></thead>
              <tbody>
                <tr v-for="(r,i) in prRows" :key="i">
                  <td class="mono fw5">{{ r.host }}<div class="fs11 muted" v-if="r.target && r.target!==r.host">{{ r.target }}</div></td>
                  <td><span class="pill" :class="r.loss>1?'down':(r.loss>0?'warn':'up')">{{ r.loss }}%</span></td>
                  <td class="mono-num">{{ r.avg }} ms</td>
                  <td class="mono-num muted">{{ r.min }} ms</td>
                  <td class="mono-num" :style="{color:r.max>60?'var(--danger)':'var(--text)'}">{{ r.max }} ms</td>
                  <td class="mono-num">{{ r.jitter }} ms</td>
                  <td><span v-if="r.tcp" class="pill" :class="r.tcp.ok?'up':'down'">{{ r.tcp.ok ? r.tcp.ms+'ms' : (r.tcp.error||'不可达') }}</span><span v-else class="fs11 muted">未指定端口</span></td>
                  <td><NcBar :value="grade(r)" :max="100" :color="grade(r)>=80?'#16a34a':(grade(r)>=60?'#d97706':'#dc2626')"></NcBar>
                      <div class="fs11 muted mt4">{{ gradeText(r) }}</div></td>
                </tr>
                <tr v-if="!prRows.length"><td colspan="8" class="tbl-empty">暂无结果，输入目标后开始探测</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ============ 历史 ============ -->
      <div v-show="tab==='history'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('clock',15)"></span><span>测速与探测记录</span>
            <div class="grow"></div><button class="btn sm" @click="loadResults" v-html="ic('refresh',13)"></button></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:140px">时间</th><th style="width:70px">用户</th><th style="width:80px">类型</th><th style="width:170px">对象</th><th style="width:130px">结果</th><th>详情</th></tr></thead>
              <tbody>
                <tr v-for="(r,i) in results" :key="i">
                  <td class="fs11 muted">{{ fmt.time(r.at) }}</td>
                  <td>{{ r.user }}</td>
                  <td><span class="tag" :class="r.kind==='probe'?'amber':(r.kind==='deploy'?'red':'green')">{{ kindText(r) }}</span></td>
                  <td class="mono fs11">{{ (r.hosts || (r.hosts===undefined? (r.targets||[]).join(','):'') || '').toString().slice(0,60) }}</td>
                  <td class="mono-num fw5">{{ r.bps ? fmt.bps(r.bps) : (r.results ? r.results.length + ' 目标' : '-') }}</td>
                  <td class="fs11 muted ellipsis" :title="detail(r)">{{ detail(r) }}</td>
                </tr>
                <tr v-if="!results.length"><td colspan="6" class="tbl-empty">暂无记录</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>`,
    setup() {
      const tab = ref('http');
      const srv = reactive({ port: 5201, ips: [], iperf: { available: false, path: '', hint: '' }, httpPort: '' });
      /* 吞吐 */
      const bt = reactive({ host: '', port: 5201, seconds: 8, parallel: 1, mode: 'download', useIperf: false });
      const btBusy = ref(false), btRes = ref(null);
      const runs = ref([]);
      /* HTTP */
      const dlMB = ref(50), dlBusy = ref(false), dlRes = ref(null), upMB = ref(20), upBusy = ref(false), upRes = ref(null);
      const dlProg = reactive({ bytes: 0, pct: 0, samples: [] }), upProg = reactive({ bytes: 0, pct: 0, samples: [] });
      /* 探测 */
      const pr = reactive({ targets: '', count: 5, intervalMs: 300, timeoutMs: 1500 });
      const prBusy = ref(false), prRows = ref([]), prStat = reactive({ total: 0, avg: 0, loss: 0, jitter: 0, max: 0 });
      /* 历史 */
      const results = ref([]);

      const TABS_ = TABS, SPEED_PRESETS_ = SPEED_PRESETS;
      const ic = (n, s) => icon(n, s);

      const optRuns = computed(() => {
        const base = NC.chartBase(false), ax = NC.AXIS(false);
        return {
          ...base,
          grid: { left: 8, right: 16, top: 24, bottom: 4, containLabel: true },
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'category', data: runs.value.map(r => fmt.timeShort(r.at)), ...ax },
          yAxis: { type: 'value', name: 'Mbps', ...ax },
          series: [{
            type: 'bar', data: runs.value.map(r => +((r.bps || 0) / 1e6).toFixed(1)), barWidth: '52%',
            itemStyle: { borderRadius: [4, 4, 0, 0], color: '#3b82f6' },
            label: { show: true, position: 'top', fontSize: 10.5, color: '#5a6a80' }
          }]
        };
      });
      const optDl = computed(() => lineOpt(dlProg.samples));
      const optUp = computed(() => lineOpt(upProg.samples));
      function lineOpt(samples) {
        const base = NC.chartBase(false), ax = NC.AXIS(false);
        return {
          ...base,
          grid: { left: 8, right: 16, top: 16, bottom: 4, containLabel: true },
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'category', data: samples.map(s => s.t.toFixed(1) + 's'), ...ax },
          yAxis: { type: 'value', name: 'Mbps', ...ax },
          series: [{ type: 'line', smooth: true, showSymbol: false, data: samples.map(s => +((s.bps || 0) / 1e6).toFixed(1)), lineStyle: { width: 2 }, areaStyle: { opacity: .12 } }]
        };
      }

      const grade = (r) => {
        const loss = Number(r.loss) || 0, avg = Number(r.avg) || 0, jit = Number(r.jitter) || 0;
        let g = 100 - loss * 8 - Math.max(0, avg - 15) * 1.2 - jit * 0.6;
        if (r.tcp && !r.tcp.ok) g -= 15;
        return Math.max(0, Math.min(100, g));
      };
      const gradeText = (r) => { const g = grade(r); return g >= 90 ? '质量优秀' : g >= 75 ? '质量良好' : g >= 55 ? '存在抖动' : '链路劣化，建议排查'; };

      async function loadSrv() {
        try { const r = await api.get('/speed/server'); Object.assign(srv, r); if (!bt.port) bt.port = r.port; }
        catch (e) { }
      }
      async function loadResults() {
        try { const r = await api.get('/speed/results'); results.value = r.rows || []; } catch (e) { }
      }

      async function runBuiltin() {
        if (!bt.host.trim()) return toast('请填写目标地址', 'warn');
        btBusy.value = true; btRes.value = null;
        try {
          const r = await api.post('/speed/builtin', {
            host: bt.host.trim(), port: Number(bt.port) || 5201, seconds: Number(bt.seconds) || 8,
            mode: bt.mode, parallel: Number(bt.parallel) || 1, useIperf: !!bt.useIperf
          });
          btRes.value = { ...r, host: bt.host.trim(), port: bt.port, mode: bt.mode, parallel: bt.parallel, at: new Date().toISOString() };
          if (r.ok && r.bps) runs.value.unshift(btRes.value);
          toast(r.ok ? `测试完成：${fmt.bps(r.bps)}` : (r.error || '测试失败'), r.ok ? 'ok' : 'err');
          loadResults();
        } catch (e) { toast(e.message, 'err'); } finally { btBusy.value = false; }
      }

      /* ------------------------- 浏览器下载 ------------------------- */
      let dlAbort = null;
      async function dlTest() {
        const mb = Math.max(1, Number(dlMB.value) || 50);
        dlBusy.value = true; dlRes.value = null;
        dlProg.bytes = 0; dlProg.pct = 0; dlProg.samples = [];
        dlAbort = new AbortController();
        const t0 = performance.now();
        let received = 0;
        const timer = setInterval(() => {
          const el = (performance.now() - t0) / 1000;
          const bps = received * 8 / Math.max(el, 0.02);
          dlProg.bytes = received;
          dlProg.pct = Math.min(100, received / (mb * 1048576) * 100);
          dlProg.samples.push({ t: el, bps });
        }, 250);
        try {
          const res = await api.raw(`/speed/http/download?bytes=${Math.round(mb * 1048576)}`, { method: 'GET', headers: { Accept: '*/*' } });
          if (!res.body) throw new Error('当前浏览器不支持流式读取');
          const reader = res.body.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            received += value.length;
          }
          const sec = (performance.now() - t0) / 1000;
          dlRes.value = { bps: received * 8 / Math.max(sec, 0.02), bytes: received, seconds: sec };
          toast(`下载完成：${fmt.bps(dlRes.value.bps)}（${fmt.bytes(received)} / ${sec.toFixed(2)}s）`, 'ok');
        } catch (e) {
          if (e.name === 'AbortError') toast('已停止下载', 'warn'); else toast('下载失败：' + e.message, 'err');
        } finally { clearInterval(timer); dlBusy.value = false; dlAbort = null; }
      }
      function dlStop() { if (dlAbort) dlAbort.abort(); }

      /* ------------------------- 浏览器上传 ------------------------- */
      function upTest() {
        const mb = Math.max(1, Number(upMB.value) || 20);
        upBusy.value = true; upRes.value = null;
        upProg.bytes = 0; upProg.pct = 0; upProg.samples = [];
        const total = Math.min(200, mb) * 1048576;
        // 填充固定字节，避免浏览器/中间设备做压缩优化
        const data = new Uint8Array(total).fill(0x41);
        const payload = new Blob([data], { type: 'application/octet-stream' });

        const t0 = performance.now();
        upTimer = setInterval(() => {
          const el = (performance.now() - t0) / 1000;
          upProg.samples.push({ t: el, bps: upProg.bytes * 8 / Math.max(el, 0.02) });
        }, 250);
        const xhr = new XMLHttpRequest();
        upAbort = () => xhr.abort();
        xhr.open('POST', '/api/speed/http/upload');
        xhr.setRequestHeader('Authorization', 'Bearer ' + (NC.state.token || ''));
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        xhr.upload.onprogress = (e) => {
          upProg.bytes = e.loaded;
          upProg.pct = Math.min(100, e.loaded / total * 100);
        };
        xhr.onload = () => {
          const sec = (performance.now() - t0) / 1000;
          upRes.value = { bps: upProg.bytes * 8 / Math.max(sec, 0.02), bytes: upProg.bytes, seconds: sec };
          toast(`上传完成：${fmt.bps(upRes.value.bps)}（${fmt.bytes(upProg.bytes)} / ${sec.toFixed(2)}s）`, 'ok');
          finishUp();
        };
        xhr.onerror = () => { toast('上传失败：网络中断', 'err'); finishUp(); };
        xhr.send(payload);
      }
      let upAbort = null, upTimer = null;
      function finishUp() { if (upTimer) clearInterval(upTimer); upTimer = null; upBusy.value = false; upAbort = null; }
      function upStop() { if (upAbort) { upAbort(); toast('已停止上传', 'warn'); } }

      async function runProbe() {
        const targets = String(pr.targets || '').split(/[\s,;]+/).filter(Boolean);
        if (!targets.length) return toast('请填写探测目标', 'warn');
        prBusy.value = true; prRows.value = [];
        Object.assign(prStat, { total: 0, avg: 0, loss: 0, jitter: 0, max: 0 });
        try {
          const r = await api.post('/speed/probe', {
            targets, count: Number(pr.count) || 5, intervalMs: Number(pr.intervalMs) || 300, timeoutMs: Number(pr.timeoutMs) || 1500
          });
          prRows.value = r.rows || [];
          const rows = prRows.value;
          prStat.total = rows.length;
          prStat.avg = avg(rows, 'avg'); prStat.max = Math.max(0, ...rows.map(x => Number(x.max) || 0));
          prStat.loss = rows.length ? rows.reduce((a, b) => a + (Number(b.loss) || 0), 0) / rows.length : 0;
          prStat.jitter = avg(rows, 'jitter');
          loadResults();
        } catch (e) { toast(e.message, 'err'); } finally { prBusy.value = false; }
      }
      function avg(rows, k) { return rows.length ? rows.reduce((a, b) => a + (Number(b[k]) || 0), 0) / rows.length : 0; }

      const kindText = (r) => ({ builtin: '吞吐', probe: '探测', deploy: '下发', speed: '测速' })[r.kind] || r.kind || '-';
      const detail = (r) => {
        if (r.kind === 'probe' && Array.isArray(r.results)) {
          const bad = r.results.filter(x => (Number(x.loss) || 0) > 0).length;
          return `丢包目标 ${bad}/${r.results.length}，平均 ${(avg(r.results, 'avg') || 0).toFixed(1)}ms`;
        }
        if (r.kind === 'deploy') return `命令 ${(r.commands || []).length} 条 → ${(r.results || []).filter(x => x.ok).length} 台成功`;
        return r.commands ? r.commands.join(' ; ').slice(0, 120) : '';
      };

      onMounted(async () => { await loadSrv(); loadResults(); });

      return {
        TABS: TABS_, tab, srv, bt, btBusy, btRes, runs, runBuiltin, optRuns,
        dlMB, dlBusy, dlRes, dlProg, dlTest, dlStop, optDl,
        upMB, upBusy, upRes, upProg, upTest, upStop, optUp,
        pr, prBusy, prRows, prStat, runProbe, grade, gradeText,
        results, loadResults, kindText, detail,
        SPEED_PRESETS: SPEED_PRESETS_, ic, fmt
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.SpeedPage = SpeedPage;
  NC.route('/speed', { title: '内网测速', comp: 'SpeedPage' });
})();
