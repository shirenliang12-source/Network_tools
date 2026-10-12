/* 数据清理中心：资产生命周期与历史记录保留策略 */
(function () {
  const { ref, reactive, computed, onMounted } = Vue;
  const NC = window.NC, { api, fmt, icon, toast } = NC;

  const LABELS = {
    scan: '网络扫描', diagnostics: '专项诊断', logs: '诊断日志', traffic: '流量会话',
    speed: '测速结果', captures: '抓包文件', recordings: '终端录像'
  };

  const CleanupPage = {
    name: 'CleanupPage',
    template: `
    <div class="col gap16">
      <div class="hint-line row gap8" style="align-items:center">
        <span v-html="ic('shield',15)"></span>
        <span><b>安全清理原则：</b>Zabbix 上游主机不会被平台删除；资产操作可恢复，历史清理不可恢复且全部写入审计日志。</span>
        <div class="grow"></div><span class="tag red">仅管理员</span>
      </div>

      <div class="kpi">
        <div class="kpi-card"><div class="kpi-icon i-blue" v-html="ic('server')"></div><div><div class="kpi-val">{{ stats.active||0 }}</div><div class="kpi-lbl">正常资产</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-amber" v-html="ic('eye')"></div><div><div class="kpi-val">{{ stats.hidden||0 }}</div><div class="kpi-lbl">已隐藏</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-cyan" v-html="ic('database')"></div><div><div class="kpi-val">{{ stats.detached||0 }}</div><div class="kpi-lbl">已解除同步</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-red" v-html="ic('trash')"></div><div><div class="kpi-val">{{ stats.deleted||0 }}</div><div class="kpi-lbl">回收站</div></div></div>
      </div>

      <div class="card">
        <div class="filter-bar">
          <div><div class="fw6">资产生命周期</div><div class="fs11 muted mt8">隐藏不影响 Zabbix；解除同步会保留平台快照并停止跟随；本地资产删除后进入回收站。</div></div>
          <div class="grow"></div>
          <input class="inp" style="width:220px" v-model.trim="keyword" placeholder="设备名 / IP / 来源">
          <select class="inp" v-model="assetFilter"><option value="">全部状态</option><option value="active">正常</option><option value="hidden">已隐藏</option><option value="detached">已解除同步</option><option value="deleted">回收站</option></select>
          <button class="btn" :disabled="loading" @click="load" v-html="ic('refresh',14)+'<span>刷新</span>'"></button>
        </div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr><th>设备</th><th>管理地址</th><th>数据来源</th><th>主机组 / 区域</th><th>状态</th><th style="width:250px">操作</th></tr></thead>
            <tbody>
              <tr v-for="a in filteredAssets" :key="a.host">
                <td><b>{{ a.name }}</b><div class="mono fs11 muted">{{ a.host }}</div></td>
                <td class="mono">{{ a.ip||'-' }}</td>
                <td><span class="tag" :class="a.source==='zabbix'?'green':a.source==='local'?'blue':'amber'">{{ a.sourceLabel }}</span></td>
                <td><div>{{ (a.groupNames||[]).join('、')||a.zone||'-' }}</div><div v-if="a.lifecycleBy" class="fs11 muted">操作者：{{ a.lifecycleBy }}</div></td>
                <td><span class="pill" :class="stateClass(a.lifecycle)">{{ stateName(a.lifecycle) }}</span></td>
                <td>
                  <div class="btn-group" v-if="a.lifecycle==='active'">
                    <button v-if="a.source==='zabbix'" class="btn sm" @click="assetAction(a,'hide')">隐藏</button>
                    <button v-if="a.source==='zabbix'" class="btn sm" @click="assetAction(a,'unlink')">解除同步</button>
                    <button v-if="a.source!=='zabbix'" class="btn sm danger" @click="assetAction(a,'delete')">移入回收站</button>
                  </div>
                  <button v-else class="btn sm primary" @click="assetAction(a,'restore')">{{ a.lifecycle==='detached'?'重新接入同步':'恢复' }}</button>
                </td>
              </tr>
              <tr v-if="!filteredAssets.length"><td colspan="6" class="tbl-empty">没有匹配的资产</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><span v-html="ic('trash',15)"></span><span>历史记录批量清理</span></div>
        <div class="row gap12" style="align-items:end;flex-wrap:wrap">
          <label style="min-width:180px">保留最近天数
            <select class="inp mt8" v-model.number="days"><option :value="7">7 天</option><option :value="30">30 天</option><option :value="90">90 天</option><option :value="180">180 天</option><option :value="365">365 天</option></select>
          </label>
          <button class="btn" :disabled="loading" @click="load">重新统计</button>
          <div class="grow"></div>
          <button class="btn danger" :disabled="cleaning || !selected.length || !selectedCount" @click="cleanHistory">{{ cleaning?'清理中…':'清理所选历史数据' }}</button>
        </div>
        <div class="result-grid mt12">
          <label v-for="(label,key) in labels" :key="key" class="result-box" style="cursor:pointer">
            <div class="row-between"><span class="checkbox"><input type="checkbox" :value="key" v-model="selected"> {{ label }}</span><span class="tag">{{ history[key]||0 }} 条</span></div>
            <div class="fs11 muted mt8">将清理 {{ fmt.time(before) }} 之前的记录</div>
          </label>
        </div>
        <div class="hint-line mt12"><span v-html="ic('info',13)"></span><span>扫描与诊断清理会级联删除关联主机、端口和发现项；抓包文件与终端录像会同时删除磁盘文件。审计日志始终保留，不在清理范围内。</span></div>
      </div>
    </div>`,
    setup() {
      const loading = ref(false), cleaning = ref(false), days = ref(30), before = ref('');
      const assets = ref([]), keyword = ref(''), assetFilter = ref('');
      const stats = reactive({ active: 0, hidden: 0, detached: 0, deleted: 0 });
      const history = reactive({});
      const selected = ref(['scan', 'diagnostics', 'logs', 'traffic', 'speed', 'captures', 'recordings']);
      const labels = LABELS;
      const ic = (n, s) => icon(n, s);
      const filteredAssets = computed(() => {
        const k = keyword.value.toLowerCase();
        return assets.value.filter(a => (!assetFilter.value || a.lifecycle === assetFilter.value) &&
          (!k || `${a.name} ${a.host} ${a.ip} ${a.sourceLabel}`.toLowerCase().includes(k)));
      });
      const selectedCount = computed(() => selected.value.reduce((n, k) => n + Number(history[k] || 0), 0));
      const stateName = s => ({ active: '正常', hidden: '已隐藏', detached: '已解除同步', deleted: '回收站' }[s] || s);
      const stateClass = s => ({ active: 'up', hidden: 'neutral', detached: 'neutral', deleted: 'down' }[s] || 'neutral');
      async function load() {
        loading.value = true;
        try {
          const r = await api.get('/system/cleanup?days=' + days.value);
          assets.value = r.assets || []; Object.assign(stats, r.assetStats || {});
          Object.assign(history, r.history || {}); before.value = r.before;
        } catch (e) { toast(e.message, 'err'); }
        finally { loading.value = false; }
      }
      async function assetAction(a, action) {
        const names = { hide: '隐藏', unlink: '解除同步', delete: '移入回收站', restore: '恢复' };
        if (!confirm(`确定对“${a.name}”执行${names[action]}？`)) return;
        try {
          await api.post('/system/cleanup/assets/' + encodeURIComponent(a.host), { action });
          toast(`${a.name} 已${names[action]}`, 'ok'); await load();
        } catch (e) { toast(e.message, 'err'); }
      }
      async function cleanHistory() {
        if (!confirm(`将永久清理 ${days.value} 天前所选的 ${selectedCount.value} 条历史记录，审计日志仍会保留。确定继续？`)) return;
        cleaning.value = true;
        try {
          const r = await api.post('/system/cleanup/history', { days: days.value, categories: selected.value });
          toast('历史数据清理完成', 'ok'); await load();
        } catch (e) { toast(e.message, 'err'); }
        finally { cleaning.value = false; }
      }
      onMounted(load);
      return { loading, cleaning, days, before, assets, keyword, assetFilter, stats, history, selected, labels,
        filteredAssets, selectedCount, stateName, stateClass, assetAction, cleanHistory, load, ic, fmt };
    }
  };
  window.PAGES = window.PAGES || {};
  window.PAGES.CleanupPage = CleanupPage;
  NC.route('/cleanup', { title: '数据清理中心', comp: 'CleanupPage' });
})();
