/* =========================================================================
 * 可编辑大屏可视化（深色 NOC 大屏）—— 支持拖拽/缩放/增删组件、属性编辑、
 * 多套大屏切换、主题与刷新配置，全部持久化。
 * ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick } = Vue;
  const NC = window.NC, { api, fmt, icon } = NC;

  const COLORS = ['#22d3ee', '#3b82f6', '#34d399', '#fbbf24', '#a78bfa', '#fb7185', '#60a5fa', '#f97316'];
  const THEMES = {
    default: { bg: '#06080f', panel: 'rgba(10,18,30,.72)', accent: '#4098ff', accent2: '#22d3ee' },
    cyan:    { bg: '#04141a', panel: 'rgba(6,26,32,.72)',  accent: '#22d3ee', accent2: '#34d399' },
    green:   { bg: '#04140b', panel: 'rgba(6,26,16,.72)',  accent: '#34d399', accent2: '#22d3ee' },
    amber:   { bg: '#1a1204', panel: 'rgba(30,22,8,.72)',  accent: '#fbbf24', accent2: '#fb923c' },
    purple:  { bg: '#0f0a1a', panel: 'rgba(20,14,34,.72)', accent: '#a78bfa', accent2: '#22d3ee' }
  };
  const TYPE_META = {
    kpi:     { label: '指标卡片', icon: 'layers',  w: 4, h: 2 },
    statbar: { label: '横向指标条', icon: 'list',  w: 4, h: 1 },
    line:    { label: '折线图', icon: 'history', w: 4, h: 4 },
    bar:     { label: '柱状图', icon: 'bar',    w: 4, h: 3 },
    donut:   { label: '环图', icon: 'pie',    w: 3, h: 3 },
    gauges:  { label: '多仪表盘', icon: 'gauge',  w: 4, h: 3 },
    ports:   { label: '端口状态矩阵', icon: 'grid',  w: 4, h: 5 },
    list:    { label: '列表', icon: 'list',  w: 4, h: 5 },
    table:   { label: '表格', icon: 'table', w: 4, h: 4 },
    progress:{ label: '进度条', icon: 'bar',  w: 4, h: 4 },
    text:    { label: '文本/公告', icon: 'file', w: 4, h: 2 }
  };

  const DashboardPage = {
    name: 'DashboardPage',
    template: `
    <div class="screen dash" :style="themeVars(dash && dash.theme)">
      <!-- 顶栏 -->
      <div class="screen-head dash-head">
        <div class="side l">
          <span class="screen-clock">{{ clock }}</span>
          <select v-if="dash" v-model="selDashId" @change="switchDash(selDashId)" class="dash-sel" :disabled="editMode">
            <option v-for="d in dashboards" :key="d.id" :value="d.id">{{ d.name }}{{ d.builtin ? '（内置）' : '' }}</option>
          </select>
          <span class="src-badge demo">演示模式（内置模拟数据）</span>
        </div>
        <h1>{{ dash ? dash.name : '大屏可视化' }}</h1>
        <div class="side r">
          <template v-if="editMode">
            <select v-model="dash.theme" class="dash-sel" @change="dirty=true" title="主题">
              <option v-for="(v,k) in THEMES" :key="k" :value="k">{{ {default:'默认蓝',cyan:'青色',green:'绿色',amber:'琥珀',purple:'紫色'}[k] }}</option>
            </select>
            <input class="dash-sel" type="number" min="3" max="120" v-model.number="dash.refreshSec" @change="dirty=true" style="width:64px" title="全局刷新(秒)" />
            <button class="btn sm" @click="showPalette=true" v-html="ic('plus',14)+'<span>添加组件</span>'"></button>
            <button class="btn sm" :disabled="!dirty" @click="save" v-html="ic('save',14)+'<span>保存</span>'"></button>
            <button class="btn sm ghost" :disabled="!dirty" @click="discard" v-html="ic('refresh',14)+'<span>放弃</span>'"></button>
            <button class="btn sm" @click="exitEdit" v-html="ic('check',14)+'<span>完成编辑</span>'"></button>
          </template>
          <template v-else>
            <span class="screen-clock">刷新 {{ dash ? dash.refreshSec : 15 }}s</span>
            <button class="icon-btn" style="background:rgba(255,255,255,.06);border-color:rgba(120,180,255,.25);color:#9fc4f0" @click="loadAll" v-html="ic('refresh',16)"></button>
            <button v-if="canEdit" class="btn sm" style="background:rgba(255,255,255,.06);border-color:rgba(120,180,255,.25);color:#9fc4f0" @click="enterEdit" v-html="ic('edit',14)+'<span>编辑大屏</span>'"></button>
            <button class="btn sm" style="background:rgba(255,255,255,.06);border-color:rgba(120,180,255,.25);color:#9fc4f0" @click="exit" v-html="'退出大屏'"></button>
          </template>
        </div>
      </div>

      <div v-if="!dash" class="empty" style="padding:80px">加载中…</div>

      <!-- 网格 -->
      <div v-else ref="gridRef" class="dash-grid" :class="{editing:editMode}"
        :style="gridStyle">
        <div v-for="w in (dash && dash.widgets) || []" :key="w.id" class="dash-w"
          :style="cellStyle(w)">
          <div class="dash-w-h" :class="{grab:editMode}" @pointerdown="startDrag($event,w)">
            <span class="dash-w-t" :title="w.title">{{ w.title }}</span>
            <span class="dash-w-acts" v-if="editMode">
              <button class="mini" :title="'编辑属性'" @click.stop="openProps(w)" v-html="ic('settings',13)"></button>
              <button class="mini danger" :title="'删除组件'" @click.stop="removeWidget(w)" v-html="ic('trash',13)"></button>
            </span>
          </div>
          <div class="dash-w-b">
            <!-- KPI -->
            <div v-if="w.type==='kpi' && w._data" class="kpi-grid">
              <div v-for="i in (w._data && w._data.items) || []" :key="i.label" class="kpi-item">
                <div class="v" :style="{color:i.color||'#dbe8ff'}">{{ i.value }}</div>
                <div class="l">{{ i.label }}</div>
              </div>
            </div>
            <!-- 横向指标条 -->
            <div v-else-if="w.type==='statbar' && w._data" class="statbar">
              <div v-for="(i,idx) in (w._data && w._data.items) || []" :key="i.label" class="sb-item">
                <template v-if="idx"><span class="sb-sep"></span></template>
                <div class="v" :style="{color:i.color||'#22d3ee'}">{{ i.value }}</div>
                <div class="l">{{ i.label }}</div>
              </div>
            </div>
            <!-- 折线/柱状/环图 -->
            <nc-chart v-else-if="(w.type==='line'||w.type==='bar'||w.type==='donut') && w._data"
              :option="chartOption(w)" height="100%" />
            <!-- 多仪表盘 -->
            <div v-else-if="w.type==='gauges' && w._data" class="gauges">
              <div v-for="g in gaugeList(w._data)" :key="g.k" class="gauge sm" style="position:relative">
                <svg width="62" height="62" viewBox="0 0 80 80" style="transform:rotate(-90deg)">
                  <circle cx="40" cy="40" r="32" fill="none" stroke="rgba(64,152,255,.14)" stroke-width="7"/>
                  <circle cx="40" cy="40" r="32" fill="none" :stroke="gaugeColor(g.v,g.warn,g.danger)" stroke-width="7" stroke-linecap="round"
                    :stroke-dasharray="201" :stroke-dashoffset="201*(1-Math.min(100,g.v||0)/100)"/>
                </svg>
                <div style="position:absolute;inset:0;display:grid;place-items:center">
                  <div style="text-align:center"><div style="font-size:15px;font-weight:700;font-family:var(--mono)" :style="{color:gaugeColor(g.v,g.warn,g.danger)}">{{ (g.v||0).toFixed(0) }}</div><div style="font-size:9px;color:var(--d-text-2)">{{ g.u }}</div></div>
                </div>
                <div style="position:absolute;bottom:-2px;width:100%;text-align:center;font-size:11px;color:var(--d-text-2)">{{ g.k }}</div>
              </div>
            </div>
            <!-- 端口矩阵 -->
            <div v-else-if="w.type==='ports' && w._data" class="d-port-grid sp-b scroll">
              <div v-for="p in (w._data && w._data.ports) || []" :key="p.name" class="d-port"
                :class="{down: p.operStatus!==1, err: ((p.inErrors||0)+(p.outErrors||0)+(p.crcErrors||0))>0 && p.operStatus===1}"
                :title="p.name + ' ' + (p.operStatus===1?'UP':'DOWN') + ' 入' + fmt.bps(p.inBps||0) + ' 出' + fmt.bps(p.outBps||0)">
                {{ shortPort(p.name) }}
              </div>
            </div>
            <!-- 列表（告警/健康度） -->
            <div v-else-if="w.type==='list' && w._data" class="d-list scroll">
              <div v-for="a in (w._data && w._data.items) || []" :key="a.id" class="d-alarm" :class="a.severity">
                <span class="t">{{ fmt.timeShort(a.clock) }}</span>
                <div class="txt"><b :title="a.title">{{ a.title }}</b><span>{{ a.host }}{{ a.message ? ' · ' + a.message : '' }}</span></div>
              </div>
              <div v-if="!((w._data && w._data.items) || []).length" class="empty" style="padding:24px 0;color:var(--d-text-2)">暂无数据</div>
            </div>
            <!-- 表格（健康度） -->
            <div v-else-if="w.type==='table' && w._data" class="scroll" style="height:100%">
              <table style="width:100%;border-collapse:collapse">
                <thead><tr style="text-align:left;color:var(--d-text-2);font-size:11px">
                  <th style="padding:4px 6px">设备</th><th style="padding:4px 6px">IP</th><th style="padding:4px 6px;width:96px">健康度</th></tr></thead>
                <tbody>
                  <tr v-for="h in (w._data && w._data.items) || []" :key="h.host" style="border-top:1px dashed rgba(64,152,255,.1)">
                    <td style="padding:5px 6px"><div style="font-size:12.5px;color:#dbe8ff">{{ h.name }}</div><div style="font-size:10.5px;color:var(--d-text-2)">{{ h.model }} · {{ h.role }}</div></td>
                    <td style="padding:5px 6px;font-family:var(--mono);font-size:11.5px;color:#9fc4f0">{{ h.ip }}</td>
                    <td style="padding:5px 6px;text-align:right">
                      <div style="font-family:var(--mono);font-size:13px;font-weight:600" :style="{color: h.status? gaugeColor(h.health,40,25,true):'#f87171'}">{{ h.status? h.health:'离线' }}</div>
                      <div style="height:4px;border-radius:3px;background:rgba(64,152,255,.14);margin-top:3px;overflow:hidden"><div :style="{width:(h.status?h.health:0)+'%',height:'100%',background:gaugeColor(h.health,40,25,true)}"></div></div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <!-- 进度条（健康度） -->
            <div v-else-if="w.type==='progress' && w._data" class="prog scroll">
              <div v-for="h in (w._data && w._data.items) || []" :key="h.host" class="prog-row">
                <span class="pl">{{ h.name }}</span>
                <div class="pbar"><div :style="{width:(h.status?h.health:0)+'%',background:gaugeColor(h.health,40,25,true)}"></div></div>
                <span class="pv" :style="{color:h.status?gaugeColor(h.health,40,25,true):'#f87171'}">{{ h.status? h.health:'—' }}</span>
              </div>
            </div>
            <!-- 文本 -->
            <div v-else-if="w.type==='text'" class="d-text">{{ (w.options && w.options.text) || '（空白文本组件，编辑可输入公告/说明）' }}</div>
            <div v-else class="empty" style="padding:24px;color:var(--d-text-2)">加载中…</div>
          </div>
          <div v-if="editMode" class="wresize" @pointerdown="startResize($event,w)" title="拖拽缩放"></div>
        </div>
      </div>

      <!-- 添加组件面板 -->
      <div v-if="showPalette" class="dash-modal" @click.self="showPalette=false">
        <div class="dash-modal-box">
          <div class="dm-h">添加组件 <button class="mini" @click="showPalette=false" v-html="ic('close',14)"></button></div>
          <div class="dm-body">
            <div v-for="(m,k) in TYPE_META" :key="k" class="pal-card" @click="addWidget(k)">
              <span class="pal-ic" v-html="ic(m.icon,20)"></span>
              <span>{{ m.label }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 组件属性抽屉 -->
      <div v-if="editing" class="dash-drawer">
        <div class="dd-h">组件属性
          <button class="mini" @click="editing=null" v-html="ic('close',14)"></button>
        </div>
        <div class="dd-body">
          <label class="fld"><span>标题</span><input v-model="editing.title" @input="dirty=true" /></label>
          <label class="fld"><span>数据源</span>
            <select v-model="editing.source" @change="onSourceChange">
              <option v-for="s in sourcesFor(editing.type)" :key="s.source" :value="s.source">{{ s.label }}</option>
            </select>
          </label>
          <template v-for="p in paramsFor(editing.source)" :key="p.key">
            <label class="fld" v-if="p.options && p.options.length">
              <span>{{ p.label }}</span>
              <select v-model="editing.params[p.key]" @change="dirty=true">
                <option v-for="o in p.options" :key="o" :value="o">{{ o===''?'（默认）':o }}</option>
              </select>
            </label>
            <label class="fld" v-else>
              <span>{{ p.label }}</span>
              <input v-model="editing.params[p.key]" @input="dirty=true" />
            </label>
          </template>
          <label class="fld"><span>刷新间隔(秒)</span><input type="number" min="3" max="600" v-model.number="editing.refreshSec" @input="dirty=true" /></label>
          <label class="fld" v-if="editing.type==='text'"><span>文本内容</span>
            <textarea rows="5" v-model="editing.options.text" @input="dirty=true" placeholder="支持多行文本，作为公告/说明"></textarea>
          </label>
          <div class="dd-tip">位置 (列{{ editing.x }}, 行{{ editing.y }}) · 尺寸 {{ editing.w }}×{{ editing.h }}</div>
          <button class="btn danger sm" @click="removeWidget(editing)" v-html="ic('trash',14)+'<span>删除此组件</span>'"></button>
        </div>
      </div>
    </div>`,
    setup() {
      const dashboards = ref([]);
      const dash = ref(null);
      const selDashId = ref('');
      const editMode = ref(false);
      const dirty = ref(false);
      const canEdit = ref(false);
      const sources = ref([]);
      const showPalette = ref(false);
      const editing = ref(null);
      const clock = ref('');
      const gridRef = ref(null);
      const cw = ref(1200);
      let timer = null, clockTimer = null, ticker = null, drag = null, resz = null;

      const ic = (n, s) => icon(n, s);
      const go = NC.go;
      const uid = (p) => (p || 'w_') + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

      const themeVars = (t) => {
        const x = THEMES[t] || THEMES.default;
        return { '--bg': x.bg, '--panel': x.panel, '--accent': x.accent, '--accent2': x.accent2 };
      };
      const accent = computed(() => (THEMES[dash.value && dash.value.theme] || THEMES.default).accent);
      const gridStyle = computed(() => {
        if (!dash.value) return {};
        const cols = dash.value.cols || 12, rowH = dash.value.rowH || 76;
        return { gridTemplateColumns: `repeat(${cols}, 1fr)`, gridAutoRows: rowH + 'px' };
      });
      const cellStyle = (w) => ({
        gridColumn: (w.x + 1) + ' / span ' + w.w,
        gridRow: (w.y + 1) + ' / span ' + h_of(w)
      });
      const h_of = (w) => w.h;

      const gaugeColor = (v, warn, danger, invert) => {
        v = Number(v) || 0;
        if (invert) return v <= danger ? '#f87171' : v <= warn ? '#fbbf24' : '#34d399';
        return v >= danger ? '#f87171' : v >= warn ? '#fbbf24' : '#34d399';
      };
      const shortPort = (n) => {
        const m = String(n).match(/(\d+)$/);
        if (/Ethernet1\//.test(n) && !/TenGig/.test(n)) return 'e' + n.split('/').pop();
        return (m ? m[1] : String(n).slice(-3)).slice(-3);
      };

      function gaugeList(d) {
        return [
          { k: 'CPU', v: d.cpu, u: '%', warn: 70, danger: 85 },
          { k: '内存', v: d.mem, u: '%', warn: 75, danger: 90 },
          { k: '温度', v: d.temp, u: '℃', warn: 50, danger: 65 }
        ];
      }

      function chartOption(w) {
        const d = w._data || {};
        if (w.type === 'donut') {
          return {
            tooltip: { trigger: 'item', backgroundColor: 'rgba(6,14,26,.95)', borderColor: 'rgba(64,152,255,.35)', textStyle: { color: '#dbe8ff', fontSize: 12 } },
            series: [{
              type: 'pie', radius: ['44%', '72%'], center: ['50%', '50%'], avoidLabelOverlap: true,
              itemStyle: { borderColor: 'rgba(4,8,15,.9)', borderWidth: 2 },
              label: { show: true, color: '#cfe4ff', fontSize: 11, formatter: '{b}\n{d}%' },
              labelLine: { show: false },
              data: (d.data || [])
            }]
          };
        }
        if (w.type === 'line') {
          const base = NC.chartBase(true);
          const labels = d.labels || [], vals = d.values || [];
          return {
            ...base, grid: { left: 8, right: 14, top: 24, bottom: 4, containLabel: true },
            xAxis: { type: 'category', data: labels, boundaryGap: false, ...NC.AXIS(true), axisLabel: { color: '#8298bb', fontSize: 10, interval: Math.ceil(labels.length / 8) } },
            yAxis: { type: 'value', ...NC.SPLIT(true), axisLabel: { color: '#8298bb', fontSize: 10, formatter: v => (v / 1e6).toFixed(0) + 'M' }, name: 'bps', nameTextStyle: { color: '#5c708a' } },
            series: [{
              type: 'line', smooth: true, symbol: 'none', name: '流量', data: vals,
              lineStyle: { width: 2, color: accent.value, shadowColor: accent.value + '88', shadowBlur: 12 },
              areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: hexA(accent.value, .42) }, { offset: 1, color: hexA(accent.value, 0) }]) }
            }]
          };
        }
        if (w.type === 'bar') {
          const items = d.items || [];
          return {
            grid: { left: 6, right: 46, top: 10, bottom: 4, containLabel: true },
            tooltip: { trigger: 'axis', backgroundColor: 'rgba(6,14,26,.95)', borderColor: 'rgba(64,152,255,.35)', textStyle: { color: '#dbe8ff', fontSize: 12 }, formatter: p => `${p[0].name}<br/>${fmt.bps ? fmt.bps(p[0].value) : p[0].value}` },
            xAxis: { type: 'value', show: false },
            yAxis: { type: 'category', data: items.map(i => i.label), axisLine: { lineStyle: { color: 'rgba(64,152,255,.2)' } }, axisTick: { show: false }, axisLabel: { color: '#a9c0da', fontSize: 11 } },
            series: [{
              type: 'bar', data: items.map(i => ({ value: i.value, itemStyle: { color: i.color || accent.value, borderRadius: [0, 5, 5, 0] } })),
              barWidth: items.length > 12 ? 8 : 14,
              label: { show: true, position: 'right', color: '#7f97b8', fontSize: 10, formatter: p => fmt.bps ? fmt.bps(p.value) : p.value }
            }]
          };
        }
        return NC.chartBase(true);
      }
      function hexA(hex, a) {
        const h = hex.replace('#', ''); const n = parseInt(h.length === 3 ? h.split('').map(x => x + x).join('') : h, 16);
        return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
      }

      function buildQuery(w) {
        const q = new URLSearchParams();
        q.set('source', w.source);
        const p = w.params || {};
        for (const k in p) if (p[k] !== '' && p[k] != null) q.set(k, p[k]);
        return q.toString();
      }
      async function loadWidget(w) {
        if (!w || w.type === 'text') { w._loaded = true; return; }
        try {
          const d = await api.get('/dashboard/data?' + buildQuery(w));
          w._data = d.error ? null : d;
          w._error = d.error || '';
        } catch (e) { w._error = e.message; w._data = null; }
        w._loaded = true; w._last = Date.now();
      }
      async function loadAll() {
        if (!dash.value) return;
        for (const w of dash.value.widgets) await loadWidget(w);
      }

      async function loadDashboards() {
        try {
          const d = await api.get('/dashboards');
          dashboards.value = d.list || [];
          selDashId.value = d.active || (dashboards.value[0] && dashboards.value[0].id) || '';
        } catch (e) { NC.toast('大屏列表加载失败：' + e.message, 'err'); }
      }
      async function loadDashboard(id) {
        try {
          const d = await api.get('/dashboards/' + id);
          dash.value = reactive(d.dashboard);
          selDashId.value = id;
          await loadAll();
        } catch (e) { NC.toast('大屏加载失败：' + e.message, 'err'); }
      }
      async function switchDash(id) {
        if (editMode.value && dirty.value) { if (!confirm('有未保存的修改，切换将丢失，确定？')) { selDashId.value = dash.value.id; return; } }
        editMode.value = false; dirty.value = false; editing.value = null;
        await loadDashboard(id);
      }

      function startTimer() {
        stopTimer();
        ticker = setInterval(() => {
          if (editMode.value || !dash.value) return;
          const now = Date.now();
          for (const w of dash.value.widgets) {
            const eff = (w.refreshSec || dash.value.refreshSec || 15) * 1000;
            if (!w._last || now - w._last >= eff) loadWidget(w);
          }
        }, 1000);
      }
      function stopTimer() { if (ticker) { clearInterval(ticker); ticker = null; } }

      function enterEdit() { editMode.value = true; stopTimer(); ensureSources(); }
      function exitEdit() { editMode.value = false; editing.value = null; startTimer(); }
      async function save() {
        try {
          const r = await api.put('/dashboards/' + dash.value.id, {
            name: dash.value.name, theme: dash.value.theme, refreshSec: dash.value.refreshSec,
            cols: dash.value.cols, rowH: dash.value.rowH, widgets: dash.value.widgets
          });
          if (r.ok) { dash.value = reactive(r.dashboard); dirty.value = false; NC.toast('大屏已保存', 'ok'); }
        } catch (e) { NC.toast('保存失败：' + e.message, 'err'); }
      }
      async function discard() {
        const id = dash.value.id; dirty.value = false; editMode.value = false; editing.value = null;
        await loadDashboard(id);
      }
      function exit() { if (editMode.value && dirty.value) { if (!confirm('有未保存的修改，退出将丢失，确定？')) return; } go('/devices'); }

      async function ensureSources() {
        if (sources.value.length) return;
        try { const d = await api.get('/dashboard/sources'); sources.value = d.sources || []; } catch {}
      }
      const sourcesFor = (type) => sources.value.filter(s => (s.types || []).includes(type));
      const paramsFor = (src) => { const s = sources.value.find(x => x.source === src); return s ? (s.params || []) : []; };
      function onSourceChange() {
        const s = sources.value.find(x => x.source === editing.value.source);
        editing.value.params = {};
        if (s) (s.params || []).forEach(p => { editing.value.params[p.key] = p.def; });
        dirty.value = true;
        loadWidget(editing.value);
      }
      function openProps(w) { editing.value = w; ensureSources(); }

      function addWidget(type) {
        ensureSources();
        const meta = TYPE_META[type] || { w: 4, h: 3 };
        const cand = sourcesFor(type);
        const def = cand[0];
        const params = {};
        if (def) (def.params || []).forEach(p => { params[p.key] = p.def; });
        const maxY = dash.value.widgets.reduce((m, w) => Math.max(m, w.y + w.h), 0);
        const w = reactive({
          id: uid(), type, title: meta.label, x: 0, y: maxY, w: meta.w, h: meta.h,
          source: def ? def.source : '', params, refreshSec: dash.value.refreshSec, options: {}, _loaded: false, _data: null
        });
        dash.value.widgets.push(w);
        dirty.value = true; showPalette.value = false;
        loadWidget(w);
        editing.value = w;
      }
      function removeWidget(w) {
        const i = dash.value.widgets.indexOf(w);
        if (i >= 0) dash.value.widgets.splice(i, 1);
        if (editing.value === w) editing.value = null;
        dirty.value = true;
      }

      /* 拖拽移动 */
      function startDrag(e, w) {
        if (!editMode.value || e.button !== 0) return;
        e.preventDefault();
        drag = { id: w.id, sx: e.clientX, sy: e.clientY, ox: w.x, oy: w.y };
        window.addEventListener('pointermove', onDrag);
        window.addEventListener('pointerup', endDrag);
      }
      function onDrag(e) {
        if (!drag) return;
        const w = dash.value.widgets.find(x => x.id === drag.id); if (!w) return;
        const cols = dash.value.cols || 12, rowH = dash.value.rowH || 76;
        const cellW = cw.value / cols;
        const dc = Math.round((e.clientX - drag.sx) / cellW);
        const dr = Math.round((e.clientY - drag.sy) / rowH);
        w.x = Math.max(0, Math.min(drag.ox + dc, cols - w.w));
        w.y = Math.max(0, drag.oy + dr);
        dirty.value = true;
      }
      function endDrag() { drag = null; window.removeEventListener('pointermove', onDrag); window.removeEventListener('pointerup', endDrag); }

      /* 拖拽缩放 */
      function startResize(e, w) {
        if (!editMode.value || e.button !== 0) return;
        e.preventDefault(); e.stopPropagation();
        resz = { id: w.id, sx: e.clientX, sy: e.clientY, ow: w.w, oh: w.h };
        window.addEventListener('pointermove', onResize);
        window.addEventListener('pointerup', endResize);
      }
      function onResize(e) {
        if (!resz) return;
        const w = dash.value.widgets.find(x => x.id === resz.id); if (!w) return;
        const cols = dash.value.cols || 12, rowH = dash.value.rowH || 76;
        const cellW = cw.value / cols;
        const dw = Math.round((e.clientX - resz.sx) / cellW);
        const dh = Math.round((e.clientY - resz.sy) / rowH);
        w.w = Math.max(2, Math.min(resz.ow + dw, cols - w.x));
        w.h = Math.max(2, Math.min(resz.oh + dh, 60));
        dirty.value = true;
      }
      function endResize() { resz = null; window.removeEventListener('pointermove', onResize); window.removeEventListener('pointerup', endResize); }

      function measure() { if (gridRef.value) cw.value = gridRef.value.clientWidth; }
      async function loadMe() {
        try { const m = await api.get('/auth/me'); canEdit.value = (m.user && (m.user.role === 'admin' || (m.user.perms || []).includes('auth'))); } catch {}
      }

      onMounted(async () => {
        await loadMe();
        await loadDashboards();
        if (selDashId.value) await loadDashboard(selDashId.value);
        startTimer();
        const tick = () => { clock.value = new Date().toLocaleString('zh-CN', { hour12: false }); };
        tick(); clockTimer = setInterval(tick, 1000);
        await nextTick(); measure();
        window.addEventListener('resize', measure);
      });
      onBeforeUnmount(() => { stopTimer(); if (clockTimer) clearInterval(clockTimer); window.removeEventListener('resize', measure); endDrag(); endResize(); });

      return {
        THEMES, TYPE_META, dashboards, dash, selDashId, editMode, dirty, canEdit, sources,
        showPalette, editing, clock, gridRef,
        themeVars, gridStyle, cellStyle, h_of, gaugeColor, shortPort, gaugeList, chartOption,
        loadAll, switchDash, enterEdit, exitEdit, save, discard, exit,
        sourcesFor, paramsFor, onSourceChange, openProps, addWidget, removeWidget,
        startDrag, startResize, ic, go, fmt
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.ScreenPage = DashboardPage;
  NC.route('/screen', { title: '大屏可视化', comp: 'ScreenPage' });
})();
