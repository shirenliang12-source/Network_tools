/* =========================================================================
   主机通信关系时序图（AnaTraf 风格）
   · 力导向图：节点=主机 IP，边=通信，权重=字节，颜色=子网
   · 时间演化：拖动时间轴 / 播放，按时间窗点亮节点与边（流量脉冲）
   · 节点详情：点击节点查看收发/度/主流协议
   · 路径测量：选两节点 → 逐跳探测（/api/flow/path）
   · AI 根因解读：基于当前流量指标
   数据：/api/flow/graph
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, onBeforeUnmount, watch, nextTick } = Vue;
  const NC = window.NC, { api, fmt, icon, toast } = NC;

  const SUBNET_COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#06b6d4', '#ef4444', '#84cc16', '#f97316', '#14b8a6'];

  const FlowGraphPage = {
    name: 'FlowGraphPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="card">
        <div class="card-head">
          <span v-html="ic('share',15)"></span><span>数据源（CAP_DIR 内的 pcap 文件）</span>
          <div class="grow"></div>
          <button class="btn" :disabled="!selFile || loading" @click="aiRootCause" v-html="ic('robot',13)+'<span>AI 根因解读</span>'"></button>
        </div>
        <div class="row gap12 wrap">
          <select v-model="selFile" class="ipt" style="min-width:280px">
            <option value="">— 请选择抓包文件 —</option>
            <option v-for="f in files" :key="f.file" :value="f.file">{{ f.file }} · {{ fmt.bytes(f.size||0) }} · {{ fmt.timeShort(f.at) }}</option>
          </select>
          <button class="btn primary" :disabled="!selFile || loading" @click="build" v-html="ic('play',13)+'<span>构建关系图</span>'"></button>
          <button class="btn" :disabled="loading" @click="loadFiles" v-html="ic('refresh',13)+'<span>刷新</span>'"></button>
          <span class="fs12 muted" v-if="error" style="color:var(--danger)">{{ error }}</span>
          <span class="fs12 muted" v-else-if="loading">构建中…</span>
          <span class="fs12 muted" v-else-if="g">节点 {{ g.nodes.length }} · 边 {{ g.links.length }} · 时间帧 {{ g.buckets.length }} · 跨度 {{ fmt.duration(g.meta.span) }}</span>
        </div>

        <div class="row gap12 wrap" style="margin-top:10px" v-if="g">
          <div class="field" style="width:260px"><label>时间轴（帧 {{ frame+1 }}/{{ g.buckets.length }} · {{ fmt.timeShort(new Date(g.buckets[frame].t0).toISOString()) }} → {{ fmt.timeShort(new Date(g.buckets[frame].t1).toISOString()) }}）</label>
            <input type="range" min="0" :max="g.buckets.length-1" v-model.number="frame" style="width:100%">
          </div>
          <button class="btn" @click="togglePlay" v-html="playing?ic('pause',13)+'<span>暂停</span>':ic('play',13)+'<span>播放</span>'"></button>
          <div class="divider-v"></div>
          <div class="field" style="width:200px"><label>路径测量 · 目标</label>
            <select v-model="pathTarget" class="ipt">
              <option value="">— 选目标节点 —</option>
              <option v-for="n in g.nodes" :key="n.id" :value="n.id">{{ n.id }} · {{ n.subnet }}</option>
            </select>
          </div>
          <button class="btn" :disabled="!pathTarget || pathLoading" @click="measurePath" v-html="ic('route',13)+'<span>测量路径</span>'"></button>
        </div>
      </div>

      <div class="card" v-if="g">
        <div class="card-head"><span v-html="ic('share',15)"></span><span>通信关系图（力导向 · 随时间演化）</span>
          <div class="grow"></div>
          <span class="fs12 muted">节点大小=累计流量 · 边粗细=字节 · 颜色=子网</span></div>
        <NcChart :option="graphOption" height="560px" @click="onNodeClick"></NcChart>
      </div>
      <div v-else class="card"><div class="tbl-empty">请选择抓包文件并点击「构建关系图」</div></div>

      <!-- 节点详情 -->
      <NcDrawer v-if="detail" :title="'节点详情 · ' + detail.id" @close="detail=false">
        <div class="col gap12" style="padding:4px 2px">
          <div class="row gap16 wrap">
            <div class="result-box" style="min-width:160px"><div class="l fs12 muted">子网</div><div class="big fs18">{{ detail.subnet }}</div></div>
            <div class="result-box" style="min-width:160px"><div class="l fs12 muted">累计收发</div><div class="big fs18">{{ fmt.bytes(detail.value) }}</div></div>
            <div class="result-box" style="min-width:140px"><div class="l fs12 muted">连接度</div><div class="big fs18">{{ detail.degree }}</div></div>
            <div class="result-box" style="min-width:140px"><div class="l fs12 muted">主流协议</div><div class="big fs18">{{ detail.topApp || '—' }}</div></div>
          </div>
          <div class="fs13 muted">入向 {{ fmt.bytes(detail.inBytes) }} · 出向 {{ fmt.bytes(detail.outBytes) }} · 报文 {{ fmt.num(detail.pkts) }}</div>
          <button class="btn" @click="pathTarget=detail.id; measurePath()" v-html="ic('route',13)+'<span>以该节点为目标测量路径</span>'"></button>
        </div>
      </NcDrawer>

      <!-- 路径测量结果 -->
      <NcDrawer v-if="pathOpen" title="路径测量 · 逐跳探测" wide @close="pathOpen=false">
        <div class="col gap12" style="padding:4px 2px" v-if="pathResult && pathResult.ok">
          <div class="row gap12 wrap">
            <div class="result-box"><div class="l fs12 muted">目标</div><div class="big fs16">{{ pathResult.target }} <span class="fs12 muted">{{ pathResult.ip }}</span></div></div>
            <div class="result-box"><div class="l fs12 muted">跳数</div><div class="big fs16">{{ pathResult.hopCount }}</div></div>
            <div class="result-box"><div class="l fs12 muted">丢包率</div><div class="big fs16" :style="{color:pathResult.loss>=20?'var(--danger)':'var(--ok)'}">{{ pathResult.loss }}%</div></div>
          </div>
          <div class="table-wrap" v-if="pathResult.hops && pathResult.hops.length">
            <table class="ntable">
              <thead><tr><th style="width:50px">TTL</th><th>跃点 IP</th><th style="width:110px">平均</th><th style="width:110px">最慢</th><th style="width:90px">丢包</th><th>主机名</th></tr></thead>
              <tbody>
                <tr v-for="h in pathResult.hops" :key="h.ttl">
                  <td class="mono">{{ h.ttl }}</td>
                  <td class="mono">{{ h.ip || '—' }}</td>
                  <td class="mono-num">{{ h.avg!=null? h.avg+'ms':'—' }}</td>
                  <td class="mono-num">{{ h.max!=null? h.max+'ms':'—' }}</td>
                  <td class="mono-num" :style="{color:h.loss>20?'var(--danger)':'inherit'}">{{ h.loss!=null? h.loss+'%':'—' }}</td>
                  <td class="ellipsis">{{ h.host || '—' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="card"><div class="card-body fs13" style="white-space:pre-wrap;line-height:1.7">{{ (pathResult.notes||[]).join('\\n') }}</div></div>
        </div>
        <div class="col gap12" style="padding:4px 2px" v-else-if="pathResult && !pathResult.ok">
          <div class="fs13" style="color:var(--danger)">测量失败：{{ pathResult.error }}</div>
        </div>
        <div class="col gap12" style="padding:4px 2px" v-else>
          <div class="fs13 muted">正在逐跳探测 {{ pathTarget }} …</div>
        </div>
      </NcDrawer>

      <!-- AI 根因解读 -->
      <NcDrawer v-if="aiOpen" title="AI 流量根因解读" wide @close="aiOpen=false">
        <div class="col gap12" style="padding:4px 2px" v-if="aiText"><div class="card"><div class="card-body fs13" style="white-space:pre-wrap;line-height:1.7">{{ aiText }}</div></div></div>
        <div class="col gap12" style="padding:4px 2px" v-else><div class="fs13 muted">正在分析流量指标并生成根因解读…</div></div>
        <template #foot><button class="btn" @click="aiOpen=false">关闭</button></template>
      </NcDrawer>
    </div>`,

    setup() {
      const ic = (n, s) => icon(n, s);
      const files = ref([]);
      const selFile = ref('');
      const loading = ref(false);
      const error = ref('');
      const g = ref(null);
      const frame = ref(0);
      const playing = ref(false);
      let timer = null;
      const detail = ref(false);
      const pathTarget = ref('');
      const pathLoading = ref(false);
      const pathOpen = ref(false);
      const pathResult = ref(null);
      const aiOpen = ref(false);
      const aiText = ref('');

      async function loadFiles() {
        try { const d = await api.get('/capture/list'); files.value = (d.rows || []).filter(r => /\.pcap(ng)?$/.test(r.file || '')); }
        catch (e) { error.value = '读取文件列表失败'; }
      }
      async function build() {
        if (!selFile.value) return toast('请先选择抓包文件', 'warn');
        loading.value = true; error.value = ''; g.value = null;
        try {
          const d = await api.post('/flow/graph', { file: selFile.value, buckets: 12 });
          if (!d.ok) { error.value = d.error || '构建失败'; }
          else { g.value = d; frame.value = 0; }
        } catch (e) { error.value = '请求异常：' + (e.message || e); }
        finally { loading.value = false; }
      }

      const subnetColorOf = (sn) => {
        let h = 0; for (let i = 0; i < sn.length; i++) h = (h * 31 + sn.charCodeAt(i)) | 0;
        return SUBNET_COLORS[Math.abs(h) % SUBNET_COLORS.length];
      };

      const graphOption = computed(() => {
        if (!g.value) return {};
        const G = g.value;
        const f = Math.max(0, Math.min(G.buckets.length - 1, frame.value));
        const bk = G.buckets[f];
        const nodeBytes = new Map(bk.nodes.map(n => [n.id, n.bytes]));
        const linkBytes = new Map(bk.links.map(l => [l.source + '|' + l.target, l.bytes]));
        const maxNode = Math.max(1, ...G.nodes.map(n => n.value));
        const maxLink = Math.max(1, ...G.links.map(l => l.bytes));

        const categories = [...new Set(G.nodes.map(n => n.subnet))].map(sn => ({ name: sn, itemStyle: { color: subnetColorOf(sn) } }));
        const nodes = G.nodes.map(n => {
          const fb = nodeBytes.get(n.id) || 0;
          const size = 12 + Math.sqrt((n.value / maxNode)) * 42;
          const active = fb > 0;
          return {
            id: n.id, name: n.id, category: n.subnet, value: n.value,
            symbolSize: size,
            itemStyle: { opacity: active ? 1 : 0.25 },
            label: { show: size > 22 || active, color: '#c6d2e2', fontSize: 10 },
            _src: n
          };
        });
        const links = G.links.map(l => {
          const fb = linkBytes.get(l.source + '|' + l.target) || 0;
          const w = 0.6 + (l.bytes / maxLink) * 7;
          return {
            source: l.source, target: l.target, value: l.bytes,
            lineStyle: { width: w, opacity: fb > 0 ? 0.85 : 0.12, color: subnetColorOf(G.nodes.find(n => n.id === l.source)?.subnet || '') },
            _active: fb > 0
          };
        });

        return {
          tooltip: { trigger: 'item', backgroundColor: 'rgba(6,14,26,.95)', borderColor: 'rgba(64,152,255,.35)', textStyle: { color: '#dbe8ff', fontSize: 12 },
            formatter: (p) => {
              if (p.dataType === 'edge') return `${p.data.source} → ${p.data.target}<br/>字节 ${fmt.bytes(p.data.value)}`;
              const n = p.data._src || {};
              return `<b>${p.data.name}</b><br/>子网 ${n.subnet || ''}<br/>收发 ${fmt.bytes(n.value || 0)}<br/>度 ${n.degree || 0}<br/>主流 ${n.topApp || '—'}`;
            }
          },
          legend: [{ data: categories.map(c => c.name), textStyle: { color: '#8aa0b8', fontSize: 11 }, top: 4, type: 'scroll' }],
          series: [{
            type: 'graph', layout: 'force', roam: true, draggable: true,
            categories, data: nodes, links,
            force: { repulsion: 220, edgeLength: [60, 160], gravity: 0.08, friction: 0.18 },
            emphasis: { focus: 'adjacency', label: { show: true }, lineStyle: { width: 4 } },
            lineStyle: { curveness: 0.12 }
          }]
        };
      });

      function onNodeClick(p) {
        if (p.dataType === 'node' && p.data._src) { detail.value = p.data._src; }
      }

      function togglePlay() {
        if (playing.value) { playing.value = false; if (timer) { clearInterval(timer); timer = null; } return; }
        if (!g.value) return;
        playing.value = true;
        timer = setInterval(() => {
          if (!g.value) { playing.value = false; clearInterval(timer); return; }
          frame.value = frame.value >= g.value.buckets.length - 1 ? 0 : frame.value + 1;
        }, 900);
      }
      watch(frame, () => { if (timer) { /* keep playing */ } });

      async function measurePath() {
        if (!pathTarget.value) return toast('请选择目标节点', 'warn');
        pathOpen.value = true; pathLoading.value = true; pathResult.value = null;
        try {
          const d = await api.raw('/flow/path', { method: 'POST', body: { target: pathTarget.value, rounds: 3, maxHops: 30 } });
          pathResult.value = await d.json().catch(() => ({}));
        } catch (e) { pathResult.value = { ok: false, error: e.message || '测量异常' }; }
        finally { pathLoading.value = false; }
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

      onMounted(loadFiles);
      onBeforeUnmount(() => { if (timer) clearInterval(timer); });

      return {
        ic, fmt, files, selFile, loading, error, g, frame, playing, detail,
        pathTarget, pathLoading, pathOpen, pathResult, aiOpen, aiText,
        loadFiles, build, graphOption, onNodeClick, togglePlay, measurePath, aiRootCause
      };
    }
  };
  window.PAGES = window.PAGES || {};
  window.PAGES.FlowGraphPage = FlowGraphPage;
  NC.route('/flow-graph', { title: '通信关系时序图', comp: 'FlowGraphPage' });
})();
