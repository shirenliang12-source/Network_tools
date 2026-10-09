/* =========================================================================
   流量性能钻取与协议报表（AnaTraf 风格）
   · KPI：TCP 重传率 / 握手时延 / HTTP·DNS 响应时间 / 平均·峰值速率 / FIN·RST
   · 协议报表：按流量/会话/报文聚合的 L7 构成
   · 流量时序：1s 粒度吞吐 + Top Talker
   数据：/api/flow/metrics（基于 pcap 解析结果聚合）
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, watch, nextTick } = Vue;
  const NC = window.NC, { api, fmt, icon, toast } = NC;

  const PROTO_COLOR = {
    http: '#2563eb', https: '#7c3aed', tls: '#7c3aed', dns: '#0891b2', ssh: '#16a34a',
    telnet: '#65a30d', 'modbus-tcp': '#dc2626', s7comm: '#dc2626', 'opc-ua': '#dc2626',
    mqtt: '#f59e0b', mysql: '#db2777', postgresql: '#db2777', mssql: '#db2777',
    redis: '#ef4444', smb: '#475569', ntp: '#0d9488', snmp: '#4f46e5', tcp: '#94a3b8',
    udp: '#94a3b8', ip: '#94a3b8', unknown: '#94a3b8', other: '#94a3b8'
  };
  const protoColor = (p) => PROTO_COLOR[String(p || '').toLowerCase()] || '#64748b';
  const hb = (v) => v >= 1e9 ? (v / 1e9).toFixed(2) + ' Gbps'
    : v >= 1e6 ? (v / 1e6).toFixed(2) + ' Mbps'
      : v >= 1e3 ? (v / 1e3).toFixed(1) + ' Kbps' : (v || 0) + ' bps';

  const FlowMetricsPage = {
    name: 'FlowMetricsPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
        <div class="grow"></div>
        <span class="fs12 muted" v-if="m">覆盖 {{ fmt.timeShort(m.span.from) }} → {{ fmt.timeShort(m.span.to) }}（{{ fmt.duration(m.span.ms) }}）</span>
      </div>

      <!-- 工具栏：选择 pcap 并计算 -->
      <div class="card">
        <div class="card-head"><span v-html="ic('camera',15)"></span><span>数据源（CAP_DIR 内的 pcap 文件）</span></div>
        <div class="row gap12 wrap">
          <select v-model="selFile" class="ipt" style="min-width:280px">
            <option value="">— 请选择抓包文件 —</option>
            <option v-for="f in files" :key="f.file" :value="f.file">{{ f.file }} · {{ fmt.bytes(f.size||0) }} · {{ fmt.timeShort(f.at) }}</option>
          </select>
          <button class="btn primary" :disabled="!selFile || loading" @click="compute" v-html="ic('play',13)+'<span>解析并计算</span>'"></button>
          <button class="btn" :disabled="loading" @click="loadFiles" v-html="ic('refresh',13)+'<span>刷新列表</span>'"></button>
          <span class="divider-v"></span>
          <button class="btn" :disabled="loading||uploading" @click="$refs.fileInput.click()" v-html="ic('upload',13)+'<span>上传 PCAP</span>'"></button>
          <input ref="fileInput" type="file" accept=".pcap,.cap,.pcapng" style="display:none" @change="onUpload">
          <button class="btn" :disabled="!selFile || loading" @click="aiRootCause" v-html="ic('robot',13)+'<span>AI 根因解读</span>'"></button>
          <span class="fs12 muted" v-if="error" style="color:var(--danger)">{{ error }}</span>
          <span class="fs12 muted" v-else-if="loading">解析中…</span>
          <span class="fs12 muted" v-else-if="uploading">上传解析中…</span>
          <span class="fs12 muted" v-else-if="m">已聚合 {{ m.totals.sessions }} 会话 / {{ fmt.num(m.totals.packets) }} 报文</span>
        </div>
      </div>

      <!-- AI 根因解读弹窗 -->
      <NcDrawer v-if="aiOpen" title="AI 流量根因解读" wide @close="aiOpen=false">
        <div class="col gap12" style="padding:4px 2px" v-if="aiText">
          <div class="card"><div class="card-body fs13" style="white-space:pre-wrap;line-height:1.7">{{ aiText }}</div></div>
        </div>
        <div class="col gap12" style="padding:4px 2px" v-else>
          <div class="fs13 muted">正在分析 {{ selFile }} 的流量指标并生成根因解读…</div>
        </div>
        <template #foot>
          <button class="btn" @click="aiOpen=false">关闭</button>
        </template>
      </NcDrawer>

      <!-- ==================== 性能概览 ==================== -->
      <div v-show="tab==='perf'" class="col gap16">
        <div v-if="m" class="grid" style="grid-template-columns:repeat(auto-fit,minmax(190px,1fr))">
          <div class="result-box"><div class="l fs12 muted">TCP 重传率</div>
            <div class="big" :style="{color: m.kpi.retransRate>=1?'var(--danger)':m.kpi.retransRate>0?'var(--warn)':'var(--ok)'}">{{ m.kpi.retransRate }}%</div>
            <div class="fs11 muted">{{ m.kpi.retransSegments }} 段 · {{ m.kpi.retransSessions }} 会话</div></div>
          <div class="result-box"><div class="l fs12 muted">平均握手时延</div>
            <div class="big" style="color:var(--primary)">{{ m.kpi.avgHandshakeMs }} <span class="fs14 muted">ms</span></div>
            <div class="fs11 muted">{{ m.kpi.handshakeSamples }} 个样本</div></div>
          <div class="result-box"><div class="l fs12 muted">平均 HTTP 响应</div>
            <div class="big" style="color:var(--primary)">{{ m.kpi.avgHttpRespMs }} <span class="fs14 muted">ms</span></div>
            <div class="fs11 muted">{{ m.kpi.httpSamples }} 个事务</div></div>
          <div class="result-box"><div class="l fs12 muted">平均 DNS 响应</div>
            <div class="big" style="color:var(--primary)">{{ m.kpi.avgDnsRespMs }} <span class="fs14 muted">ms</span></div>
            <div class="fs11 muted">{{ m.kpi.dnsSamples }} 个查询</div></div>
          <div class="result-box"><div class="l fs12 muted">平均速率</div>
            <div class="big" style="color:var(--ok)">{{ hb(m.kpi.avgBps) }}</div>
            <div class="fs11 muted">全时段均值</div></div>
          <div class="result-box"><div class="l fs12 muted">峰值速率（微突发）</div>
            <div class="big" style="color:var(--warn)">{{ hb(m.kpi.peakBps) }}</div>
            <div class="fs11 muted">最忙 1 秒</div></div>
          <div class="result-box"><div class="l fs12 muted">FIN 会话</div>
            <div class="big">{{ m.kpi.finSessions }}</div>
            <div class="fs11 muted">正常关闭</div></div>
          <div class="result-box"><div class="l fs12 muted">RST 会话</div>
            <div class="big" :style="{color: m.kpi.rstSessions?'var(--danger)':'inherit'}">{{ m.kpi.rstSessions }}</div>
            <div class="fs11 muted">异常中断</div></div>
        </div>

        <div class="card" v-if="m && m.byProto.length">
          <div class="card-head"><span v-html="ic('pie',15)"></span><span>L7 协议构成（按流量 Top 12）</span></div>
          <NcChart :option="optProto" height="320px"></NcChart>
        </div>

        <div class="card" v-if="m && m.timeline.length">
          <div class="card-head"><span v-html="ic('activity',15)"></span><span>吞吐时序（1s 粒度）</span></div>
          <NcChart :option="optTimeline" height="280px"></NcChart>
        </div>
        <div v-if="!m" class="card"><div class="tbl-empty">请选择抓包文件并点击「解析并计算」</div></div>
      </div>

      <!-- ==================== 协议报表 ==================== -->
      <div v-show="tab==='proto'" class="col gap16">
        <div class="card" v-if="m">
          <div class="card-head"><span v-html="ic('list',15)"></span><span>协议汇总报表</span>
            <div class="grow"></div><span class="fs12 muted">单位：流量 / 会话数 / 报文数</span></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:160px">协议</th><th style="width:90px">会话数</th><th style="width:160px">流量占比</th><th style="width:120px">流量</th><th style="width:90px">报文数</th></tr></thead>
              <tbody>
                <tr v-for="p in m.byProto" :key="p.proto">
                  <td><span class="tag" :style="{color:protoColor(p.proto),borderColor:protoColor(p.proto)+'55',background:protoColor(p.proto)+'14'}">{{ p.proto }}</span></td>
                  <td class="mono-num">{{ p.sessions }}</td>
                  <td><NcBar :value="p.bytes" :max="maxProtoBytes" :color="protoColor(p.proto)"></NcBar></td>
                  <td class="mono">{{ fmt.bytes(p.bytes) }}</td>
                  <td class="mono-num">{{ fmt.num(p.pkts) }}</td>
                </tr>
                <tr v-if="!m.byProto.length"><td colspan="5" class="tbl-empty">暂无数据</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div v-if="!m" class="card"><div class="tbl-empty">请选择抓包文件并点击「解析并计算」</div></div>
      </div>

      <!-- ==================== 流量时序 / Top Talker ==================== -->
      <div v-show="tab==='timeline'" class="col gap16">
        <div class="card" v-if="m && m.timeline.length">
          <div class="card-head"><span v-html="ic('activity',15)"></span><span>吞吐时序（bps）</span></div>
          <NcChart :option="optTimeline" height="300px"></NcChart>
        </div>
        <div class="card" v-if="m && m.topTalkers.length">
          <div class="card-head"><span v-html="ic('share',15)"></span><span>Top Talker（按流量）</span></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:50px">#</th><th>源 → 目的</th><th style="width:120px">应用协议</th><th style="width:110px">会话数</th><th style="width:120px">流量</th></tr></thead>
              <tbody>
                <tr v-for="(p,i) in m.topTalkers" :key="i">
                  <td class="mono muted">{{ i+1 }}</td>
                  <td class="mono ellipsis">{{ p.key }}</td>
                  <td><span class="tag">{{ p.appProto||'—' }}</span></td>
                  <td class="mono-num">{{ p.sessions }}</td>
                  <td>{{ fmt.bytes(p.bytes) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div v-if="!m" class="card"><div class="tbl-empty">请选择抓包文件并点击「解析并计算」</div></div>
      </div>
    </div>`,

    setup() {
      const ic = (n, s) => icon(n, s);
      const TABS = [
        { k: 'perf', n: '性能概览', i: 'dashboard' },
        { k: 'proto', n: '协议报表', i: 'list' },
        { k: 'timeline', n: '流量时序', i: 'activity' }
      ];
      const tab = ref('perf');
      const files = ref([]);
      const selFile = ref('');
      const loading = ref(false);
      const uploading = ref(false);
      const error = ref('');
      const m = ref(null);
      const aiOpen = ref(false);
      const aiText = ref('');
      const fileInput = ref(null);

      async function loadFiles() {
        try {
          const d = await api.get('/capture/list');
          files.value = (d.rows || []).filter(r => /\.pcap(ng)?$/.test(r.file || ''));
        } catch (e) { error.value = '读取文件列表失败'; }
      }

      async function onUpload(e) {
        const f = e.target.files && e.target.files[0];
        e.target.value = '';
        if (!f) return;
        uploading.value = true; error.value = '';
        try {
          const fd = new FormData();
          fd.append('file', f);
          const j = await api.raw('/flow/upload', { method: 'POST', body: fd });
          m.value = j.metrics; selFile.value = j.file;
          toast('已上传并解析：' + j.originalName, 'ok');
          await loadFiles();
        } catch (e) { error.value = '上传失败：' + (e.message || e); }
        finally { uploading.value = false; }
      }

      async function aiRootCause() {
        if (!selFile.value) return toast('请先选择抓包文件', 'warn');
        aiOpen.value = true; aiText.value = '';
        try {
          const d = await api.raw('/ai/chat', { method: 'POST', body: { flow: { file: selFile.value }, messages: [{ role: 'user', content: '请基于当前流量分析结果，给出根因解读与优化建议' }], useContext: true } });
          const j = await d.json().catch(() => ({}));
          aiText.value = (j.answer || (j.error ? '失败：' + j.error : '无返回'));
        } catch (e) { aiText.value = '请求异常：' + (e.message || e); }
      }

      async function compute() {
        if (!selFile.value) return toast('请先选择抓包文件', 'warn');
        loading.value = true; error.value = '';
        try {
          const d = await api.post('/flow/metrics', { file: selFile.value });
          if (!d.ok) { error.value = d.error || '计算失败'; m.value = null; }
          else m.value = d;
        } catch (e) { error.value = '请求异常：' + (e.message || e); m.value = null; }
        finally { loading.value = false; }
      }

      const maxProtoBytes = computed(() => Math.max(1, ...(m.value ? m.value.byProto.map(p => p.bytes) : [1])));

      const optProto = computed(() => {
        if (!m.value) return {};
        const base = NC.chartBase(true), ax = NC.AXIS(false);
        const top = m.value.byProto.slice(0, 12);
        return {
          ...base,
          tooltip: { trigger: 'item', formatter: p => `${p.name}<br/>${fmt.bytes(p.value)} (${p.percent}%)` },
          legend: { type: 'scroll', orient: 'vertical', right: 8, top: 10, textStyle: { color: '#8aa0b8', fontSize: 11 } },
          series: [{
            type: 'pie', radius: ['38%', '70%'], center: ['38%', '52%'],
            data: top.map(p => ({ name: p.proto, value: p.bytes, itemStyle: { color: protoColor(p.proto) } })),
            label: { color: '#c6d2e2', fontSize: 11, formatter: '{b}' }
          }]
        };
      });

      const optTimeline = computed(() => {
        if (!m.value) return {};
        const base = NC.chartBase(false), ax = NC.AXIS(false);
        const tl = m.value.timeline;
        return {
          ...base,
          grid: { left: 8, right: 16, top: 24, bottom: 4, containLabel: true },
          tooltip: { trigger: 'axis', formatter: p => { const i = p[0].dataIndex; return `${fmt.timeShort(new Date(tl[i].t * 1000).toISOString())}<br/>${hb(tl[i].bps)}` } },
          xAxis: { type: 'category', data: tl.map(r => fmt.timeShort(new Date(r.t * 1000).toISOString())), ...ax, axisLabel: { color: '#8aa0b8', fontSize: 10 } },
          yAxis: { type: 'value', ...ax, axisLabel: { color: '#8aa0b8', fontSize: 10, formatter: v => hb(v) } },
          series: [{
            type: 'line', smooth: true, showSymbol: false, data: tl.map(r => r.bps),
            areaStyle: { color: 'rgba(59,130,246,0.18)' },
            lineStyle: { color: '#3b82f6', width: 2 }, itemStyle: { color: '#3b82f6' }
          }]
        };
      });

      onMounted(loadFiles);

      return {
        TABS, tab, files, selFile, loading, uploading, error, m,
        aiOpen, aiText, fileInput,
        loadFiles, compute, onUpload, aiRootCause, maxProtoBytes, optProto, optTimeline,
        ic, fmt, protoColor, hb
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.FlowMetricsPage = FlowMetricsPage;
  NC.route('/flow-metrics', { title: '性能与协议报表', comp: 'FlowMetricsPage' });
})();
