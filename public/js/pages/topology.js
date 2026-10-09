/* =========================================================================
   网络拓扑：自动布局 · 手动编辑 · 状态着色 · 节点详情
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, nextTick, watch } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const COLORS = {
    核心: '#2563eb', 汇聚: '#0891b2', 接入: '#16a34a', 防火墙: '#d97706', 边界: '#7c3aed', 路由: '#db2777', 无线: '#0ea5e9'
  };
  const COL = { 防火墙: 0, 核心: 1, 汇聚: 2, 接入: 3, 边界: 0, 路由: 0, 无线: 3 };

  const TopologyPage = {
    name: 'TopologyPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="kpi">
        <div class="kpi-card" v-for="g in roleStats" :key="g.k">
          <div class="kpi-icon" :style="{background:g.color+'18', color:g.color}" v-html="ic('layers')"></div>
          <div><div class="kpi-val" :style="{color:g.color}">{{ g.n }}</div><div class="kpi-lbl">{{ g.k }}设备</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-red" v-html="ic('alert')"></div>
          <div><div class="kpi-val" style="color:var(--danger)">{{ offline }}</div><div class="kpi-lbl">离线设备</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-cyan" v-html="ic('share')"></div>
          <div><div class="kpi-val">{{ links.length }}</div><div class="kpi-lbl">链路</div></div>
        </div>
      </div>

      <div class="card">
        <div class="filter-bar">
          <div class="search-box" style="min-width:220px">
            <span v-html="ic('search',15)"></span>
            <input class="inp" v-model.trim="kw" placeholder="点击节点或在下方列表中选择" @keydown.enter="focusNext">
          </div>
          <span class="fs12 muted">图例：</span>
          <span v-for="(v,k) in COLORS" :key="k" class="tag" :style="{background:v+'14',color:v}">{{ k }}</span>
          <span class="tag" style="background:var(--danger-weak);color:var(--danger)">离线节点虚线</span>
          <div class="grow"></div>
          <button class="btn" @click="relayout" v-html="ic('share',15)+'<span>重排</span>'"></button>
          <button class="btn" @click="save" v-html="ic('check',15)+'<span>保存拓扑</span>'"></button>
          <button class="btn" @click="load" v-html="ic('refresh',15)"></button>
        </div>

        <div class="grid" style="grid-template-columns:1fr 340px;gap:14px">
          <div class="card tight" style="padding:6px">
            <NcChart :option="opt" height="560px" @click="onNodeClick"></NcChart>
          </div>
          <div class="col gap12">
            <div class="card tight">
              <div class="card-head" style="margin-bottom:6px"><span class="fs13 fw5">设备清单</span><span class="grow"></span><span class="fs11 muted">{{ nodes.length }} 台</span></div>
              <div class="table-wrap" style="max-height:420px;overflow:auto">
                <table class="ntable">
                  <thead><tr><th style="width:46px"></th><th>设备</th><th style="width:100px">角色</th><th>状态</th></tr></thead>
                  <tbody>
                    <tr v-for="n in nodes" :key="n.id" :style="{cursor:'pointer'}" @click="sel(n.id)">
                      <td><span class="sev-dot" :class="n.status?'information':'disaster'" :style="{background:n.status?'#16a34a':'#dc2626'}"></span></td>
                      <td class="fw5 ellipsis">{{ n.label }}<div class="fs11 muted mono">{{ n.ip }}</div></td>
                      <td><span class="tag" :style="{background:(COLORS[n.type]||'#64748b')+'18',color:COLORS[n.type]||'#64748b'}">{{ n.type }}</span></td>
                      <td><span class="pill" :class="n.status?'up':'down'">{{ n.status?'在线':'离线' }}</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
            <div class="card tight" v-if="cur">
              <div class="card-head" style="margin-bottom:6px"><span class="fs13 fw5">{{ cur.label }}</span>
                <div class="grow"></div><span class="pill" :class="cur.status?'up':'down'">{{ cur.status?'在线':'离线' }}</span></div>
              <div class="col gap4 fs12">
                <div><span class="muted">设备名：</span>{{ cur.label }}</div>
                <div><span class="muted">HostID：</span><span class="mono">{{ cur.id }}</span></div>
                <div><span class="muted">管理地址：</span><span class="mono">{{ cur.ip }}</span></div>
                <div><span class="muted">厂商型号：</span>{{ cur.vendor }} {{ cur.model || '' }}</div>
                <div><span class="muted">区域：</span>{{ cur.zone || '-' }} <span class="muted">角色：</span>{{ cur.type }}</div>
                <div v-if="cur.cpu != null"><span class="muted">CPU：</span>{{ cur.cpu }}% <span class="muted">内存：</span>{{ cur.mem }}% <span class="muted">温度：</span>{{ cur.temp }}℃</div>
              </div>
              <div class="flex gap8 mt8">
                <button class="btn sm primary" @click="openTerm(cur)" v-html="ic('terminal',13)+'<span>终端</span>'"></button>
                <button class="btn sm" @click="go('/device/'+encodeURIComponent(cur.id))">设备详情</button>
              </div>
            </div>
            <div v-else class="card tight">
              <div class="fs12 muted">点击拓扑图或左侧清单中的设备，查看详情并直接进入终端。</div>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><span v-html="ic('list',15)"></span><span>链路明细（{{ links.length }}）</span></div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr><th style="width:60px">#</th><th style="width:180px">上游</th><th style="width:40px"></th><th style="width:180px">下游</th><th style="width:120px">上游地址</th><th style="width:120px">下游地址</th><th style="width:90px">状态</th></tr></thead>
            <tbody>
              <tr v-for="(l,i) in links" :key="i">
                <td class="mono muted">{{ i+1 }}</td>
                <td class="fw5">{{ nameOf(l.source) }}</td>
                <td class="center" style="color:var(--text-3)">—</td>
                <td class="fw5">{{ nameOf(l.target) }}</td>
                <td class="mono fs11">{{ ipOf(l.source) }}</td>
                <td class="mono fs11">{{ ipOf(l.target) }}</td>
                <td><span class="pill" :class="statusOf(l)">链路正常</span></td>
              </tr>
              <tr v-if="!links.length"><td colspan="7" class="tbl-empty">暂无链路数据</td></tr>
            </tbody>
          </table>
        </div>
        <div class="hint-line"><span v-html="ic('info',13)"></span><span>拓扑首次打开时由设备角色自动生成（防火墙 → 核心 → 汇聚 → 接入），保存后由你自定义；未保存的修改刷新页面会丢失。</span></div>
      </div>
    </div>`,
    setup() {
      const nodes = ref([]), links = ref([]), cur = ref(null), kw = ref('');
      const offline = ref(0);

      const ic = (n, s) => icon(n, s);
      const roleStats = computed(() => {
        const m = {};
        for (const n of nodes.value) { const k = n.type || '其他'; m[k] = m[k] || { k, n: 0, color: COLORS[k] || '#64748b' }; m[k].n++; }
        return Object.values(m);
      });
      const opt = computed(() => layout(nodes.value, links.value, kw.value));

      function layout(ns, ls, kwv) {
        const q = (kwv || '').toLowerCase();
        const show = (n) => !q || (n.label + n.id + (n.ip || '')).toLowerCase().includes(q);
        const visible = ns.filter(show);
        const visibleSet = new Set(visible.map(n => n.id));
        const cols = {};
        for (const n of visible) { const c = COL[n.type] ?? 1; (cols[c] = cols[c] || []).push(n); }
        for (const arr of Object.values(cols)) arr.sort((a, b) => (a.label || '').localeCompare(b.label || ''));
        const CN = { 0: '边界 / 安全', 1: '核心', 2: '汇聚', 3: '接入' };
        const maxLen = Math.max(1, ...Object.values(cols).map(a => a.length));
        const EN = Object.keys(cols).map(Number).sort((a, b) => a - b);
        const nodeData = visible.map(n => {
          const c = COL[n.type] ?? 1;
          const arr = cols[c] || [];
          const idx = arr.indexOf(n);
          const total = Math.max(1, arr.length);
          const gap = Math.min(120, 620 / Math.max(1, maxLen));
          const y = (idx - (total - 1) / 2) * gap;
          const color = COLORS[n.type] || '#64748b';
          return {
            id: n.id, name: n.label, x: c * 300, y,
            symbolSize: n.type === '核心' || n.type === '防火墙' ? 42 : 30,
            itemStyle: { color: n.status ? color : '#94a3b8', borderColor: n.status ? '#fff' : '#dc2626', borderWidth: n.status ? 0 : 2, shadowBlur: n.status ? 10 : 0, shadowColor: color + '55' },
            label: { fontSize: 11, formatter: n.label.length > 16 ? n.label.slice(0, 15) + '…' : n.label, color: '#16202e', fontWeight: n.type === '核心' ? 600 : 400 },
            _meta: n
          };
        });
        const linkData = ls
          .filter(l => visibleSet.has(l.source) && visibleSet.has(l.target))
          .map(l => ({ source: l.source, target: l.target, lineStyle: { color: '#94a3b8', width: 1.6, curveness: 0.12 } }));
        return {
          tooltip: {
            trigger: 'item',
            formatter: (p) => {
              if (p.dataType === 'node') {
                const m = p.data._meta || {};
                return `<b>${m.label || m.name || ''}</b><br/>${m.vendor || ''} ${m.model || ''}<br/>${m.ip || ''}<br/>CPU ${m.cpu ?? '-'}% · 内存 ${m.mem ?? '-'}% · 健康度 ${m.health ?? '-'}<br/>${m.status ? '在线' : '离线'}`;
              }
              return `${p.data.source} → ${p.data.target}`;
            },
            backgroundColor: 'rgba(255,255,255,.98)', borderColor: '#e2e8f1', textStyle: { color: '#16202e', fontSize: 12 }
          },
          animationDuration: 600,
          series: [{
            type: 'graph', layout: 'none', coordinateSystem: undefined,
            data: nodeData, links: linkData,
            roam: true, draggable: true,
            edgeSymbol: ['none', 'arrow'], edgeSymbolSize: [0, 7],
            emphasis: { focus: 'adjacency', scale: 1.08, lineStyle: { width: 3 } },
            lineStyle: { color: 'source', opacity: .8 },
            labelLayout: { hideOverlap: true }
          }],
          graphic: EN.map(c => ({
            type: 'text', left: 20 + c * 300, top: 8,
            style: { text: CN[c] || ('列' + c), fontSize: 12, fill: '#93a2b5', fontWeight: 500 }
          }))
        };
      }

      function sel(id) { cur.value = nodes.value.find(n => n.id === id) || null; }
      function onNodeClick(p) { if (p && p.dataType === 'node') sel(p.data.id); }
      function nameOf(id) { const n = nodes.value.find(x => x.id === id); return n ? n.label : id; }
      function ipOf(id) { const n = nodes.value.find(x => x.id === id); return n ? (n.ip || '-') : '-'; }
      function statusOf(l) { const a = nodes.value.find(x => x.id === l.source), b = nodes.value.find(x => x.id === l.target); return (a && a.status) && (b && b.status) ? 'up' : 'warn'; }
      function focusNext() { const list = nodes.value.filter(n => (n.label || '').includes(kw.value)); if (list.length) sel(list[0].id); }

      async function load() {
        try {
          const [r, d] = await Promise.all([api.get('/topology'), api.get('/devices').catch(() => ({ rows: [] }))]);
          const map = {};
          for (const x of (d.rows || [])) map[x.host] = x;
          nodes.value = (r.nodes || []).map(n => {
            const dev = map[n.id] || {};
            return {
              ...n, zone: dev.zone || '', cpu: dev.cpu, mem: dev.mem, temp: dev.temp,
              health: dev.health, uptimeSec: dev.uptimeSec, role: dev.role,
              status: dev.status !== undefined ? (dev.status !== 0 && dev.status !== false) : n.status
            };
          });
          links.value = r.links || [];
          offline.value = nodes.value.filter(n => n.status === false).length;
          cur.value = null;
        } catch (e) { toast('加载拓扑失败：' + e.message, 'err'); }
      }
      async function save() {
        try {
          await api.put('/topology', { nodes: nodes.value, links: links.value });
          toast('拓扑已保存（' + nodes.value.length + ' 个节点 / ' + links.value.length + ' 条链路）', 'ok');
        } catch (e) { toast(e.message, 'err'); }
      }
      function relayout() { toast('已重新计算布局', 'info'); nextTick(() => { }); }
      function openTerm(n) { go('/terminal'); toast('请在终端页选择设备 ' + n.label, 'info'); }

      onMounted(load);
      watch(() => kw.value, () => { });

      return { nodes, links, cur, kw, offline, roleStats, opt, ic, sel, onNodeClick, nameOf, ipOf, statusOf, focusNext, load, save, relayout, openTerm, go, fmt, COLORS };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.TopologyPage = TopologyPage;
  NC.route('/topology', { title: '网络拓扑', comp: 'TopologyPage' });
})();
