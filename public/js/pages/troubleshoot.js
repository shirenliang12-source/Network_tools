/* =========================================================================
 * 排障工作台 · 告警 → 根因闭环
 * 左：活动告警列表（按级别/设备/关键字过滤）
 * 右：选中告警 → 一键诊断（自动采集证据）→ 结论/分步证据/可能原因/处置建议 → 导出报告
 * ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, onBeforeUnmount, watch } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const TroubleshootPage = {
    name: 'TroubleshootPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="kpi">
        <div class="kpi-card"><div class="kpi-icon i-red" v-html="ic('alert')"></div><div><div class="kpi-val" style="color:var(--danger)">{{ stats.disaster }}</div><div class="kpi-lbl">灾难</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-amber" v-html="ic('alert')"></div><div><div class="kpi-val" style="color:var(--warn)">{{ stats.high }}</div><div class="kpi-lbl">严重</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-blue" v-html="ic('bell')"></div><div><div class="kpi-val">{{ stats.average }}</div><div class="kpi-lbl">一般</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-cyan" v-html="ic('bell')"></div><div><div class="kpi-val">{{ stats.warning }}</div><div class="kpi-lbl">警告</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-purple" v-html="ic('shield')"></div><div><div class="kpi-val" style="color:var(--purple)">{{ rows.length }}</div><div class="kpi-lbl">活动告警</div></div></div>
      </div>

      <div class="grid" style="grid-template-columns:minmax(360px,440px) 1fr;gap:16px;align-items:start">
        <!-- 左：告警列表 -->
        <div class="card">
          <div class="card-head"><span v-html="ic('bell',15)"></span><span>活动告警</span>
            <div class="grow"></div>
            <button class="btn sm" :class="{primary:auto}" @click="toggleAuto" v-html="ic(auto?'stop':'play',14)"></button>
            <button class="btn sm" @click="load()" v-html="ic('refresh',14)"></button>
          </div>
          <div class="filter-bar" style="flex-wrap:wrap">
            <div class="search-box" style="min-width:100%">
              <span v-html="ic('search',15)"></span>
              <input class="inp" v-model.trim="f.keyword" placeholder="设备 / 标题 / 描述" @keydown.enter="load()">
            </div>
            <select class="inp" v-model="f.severity" @change="load()">
              <option value="">全部级别</option>
              <option value="disaster">灾难</option><option value="high">严重</option>
              <option value="average">一般</option><option value="warning">警告</option><option value="information">信息</option>
            </select>
            <select class="inp" v-model="f.host" @change="load()"><option value="">全部设备</option><option v-for="h in hosts" :key="h" :value="h">{{ h }}</option></select>
          </div>
          <div class="col gap8" style="margin-top:8px;max-height:62vh;overflow:auto">
            <div v-for="a in rows" :key="a.eventid||a.id" class="ts-alarm" :class="{active: sel && (sel.eventid||sel.id)===(a.eventid||a.id)}" @click="select(a)">
              <div class="row gap6"><span class="sev-dot" :class="a.severity"></span><b class="fs13">{{ a.host }}</b><span class="grow"></span><span class="fs11 muted">{{ fmt.ago(a.clock) }}</span></div>
              <div class="fs12 mt4" :style="{color:sevColor(a.severity)}">{{ a.title }}</div>
              <div class="fs11 muted ellipsis mt2" style="max-width:100%">{{ a.message }}</div>
            </div>
            <div v-if="!rows.length" class="tbl-empty">没有活动告警</div>
          </div>
        </div>

        <!-- 右：诊断面板 -->
        <div class="card">
          <div class="card-head"><span v-html="ic('search',15)"></span><span>一键诊断</span>
            <div class="grow"></div>
            <button class="btn sm primary" :disabled="!sel||loading" @click="runDiag()" v-html="ic('zap',14)+'<span>开始诊断</span>'"></button>
            <button class="btn sm" :disabled="!diag" @click="exportReport()" v-html="ic('download',14)+'<span>导出报告</span>'"></button>
          </div>

          <div v-if="!sel" class="ts-empty">
            <div v-html="ic('search',40)"></div>
            <div class="fs13 muted mt8">从左侧选择一条告警，点击「开始诊断」自动采集证据并给出根因与处置建议</div>
          </div>

          <div v-else class="col gap14">
            <div class="row gap8 items-center">
              <span class="sev-dot" :class="sel.severity"></span>
              <b class="fs15">{{ sel.host }}</b>
              <span class="tag" :style="{color:sevColor(sel.severity)}">{{ sevText(sel.severity) }}</span>
              <span class="grow"></span>
              <span class="fs12 muted">{{ fmt.time(sel.clock) }}</span>
            </div>
            <div class="fs14 fw5">{{ sel.title }}</div>
            <div class="fs12 muted" v-if="sel.message">{{ sel.message }}</div>

            <div v-if="loading" class="ts-loading"><span class="spin" v-html="ic('refresh',16)"></span> 正在采集证据（设备/端口/历史/可达性）…</div>

            <template v-if="diag">
              <div class="ts-summary" v-html="ic('robot',15)+' <b>'+diag.summary+'</b>'"></div>

              <div class="ts-block">
                <div class="ts-block-h"><span v-html="ic('list',14)"></span> 分步证据</div>
                <div v-for="(s,i) in diag.steps" :key="i" class="ts-step">
                  <div class="ts-step-n">{{ i+1 }}</div>
                  <div class="col gap2" style="flex:1">
                    <div class="fs13 fw5">{{ s.name }}</div>
                    <div class="fs12 mono muted" style="white-space:pre-wrap">{{ s.evidence }}</div>
                    <div class="fs12" style="color:var(--primary)">→ {{ s.finding }}</div>
                  </div>
                </div>
              </div>

              <div class="ts-block">
                <div class="ts-block-h"><span v-html="ic('alert',14)"></span> 可能原因</div>
                <div v-for="(c,i) in diag.causes" :key="i" class="ts-cause">
                  <span class="conf" :class="c.confidence">{{ confText(c.confidence) }}</span>
                  <span>{{ c.prob }}</span>
                </div>
              </div>

              <div class="ts-block">
                <div class="ts-block-h"><span v-html="ic('check',14)"></span> 处置建议</div>
                <ol class="ts-recs">
                  <li v-for="(r,i) in diag.recommendations" :key="i">{{ r }}</li>
                </ol>
              </div>
              <div class="fs11 muted">分类：{{ diag.category }} · 生成于 {{ fmt.time(diag.generatedAt) }}</div>
            </template>
          </div>
        </div>
      </div>
    </div>`,
    setup(props) {
      const rows = ref([]), stats = reactive({ disaster: 0, high: 0, average: 0, warning: 0, information: 0 });
      const f = reactive({ severity: '', host: String((props.query && props.query.host) || ''), keyword: '' });
      const hosts = ref([]), auto = ref(false);
      const sel = ref(null), diag = ref(null), loading = ref(false);

      const ic = (n, s) => icon(n, s);
      const sevColor = (s) => ({ disaster: '#dc2626', critical: '#dc2626', high: '#ea580c', average: '#f59e0b', warning: '#eab308', information: '#3b82f6' }[s] || '#64748b');
      const sevText = (s) => NC.SEV_CN[s] || s || '-';
      const confText = (c) => ({ high: '高', medium: '中', low: '低' }[c] || '低');

      async function load() {
        try {
          const q = new URLSearchParams();
          if (f.severity) q.set('severity', f.severity);
          if (f.host) q.set('host', f.host);
          if (f.keyword) q.set('keyword', f.keyword);
          const r = await api.get('/troubleshoot/alarms?' + q.toString());
          rows.value = r.rows || [];
          Object.assign(stats, r.stats || {});
          if (!hosts.value.length) {
            try { const d = await api.get('/devices'); hosts.value = [...new Set((d.rows || []).map(x => x.host))]; } catch (e) {}
          }
        } catch (e) { toast('加载告警失败：' + e.message, 'err'); }
      }
      function select(a) { sel.value = a; diag.value = null; }

      async function runDiag() {
        if (!sel.value) return;
        loading.value = true; diag.value = null;
        try {
          const r = await api.post('/troubleshoot/diagnose', { alarm: sel.value });
          diag.value = r;
        } catch (e) { toast(e.message, 'err'); }
        finally { loading.value = false; }
      }

      function exportReport() {
        if (!sel.value || !diag.value) return;
        const d = diag.value;
        const lines = [];
        lines.push('# 排障诊断报告');
        lines.push('');
        lines.push(`- 设备：${sel.value.host}`);
        lines.push(`- 级别：${sevText(sel.value.severity)}`);
        lines.push(`- 告警：${sel.value.title}`);
        lines.push(`- 发生：${fmt.time(sel.value.clock)}`);
        lines.push(`- 分类：${d.category}`);
        lines.push('');
        lines.push('## 结论');
        lines.push(d.summary);
        lines.push('');
        lines.push('## 分步证据');
        d.steps.forEach((s, i) => { lines.push(`${i + 1}. 【${s.name}】`); lines.push(`   证据：${s.evidence}`); lines.push(`   判断：${s.finding}`); });
        lines.push('');
        lines.push('## 可能原因');
        d.causes.forEach(c => lines.push(`- [${confText(c.confidence)}置信] ${c.prob}`));
        lines.push('');
        lines.push('## 处置建议');
        d.recommendations.forEach(r => lines.push(`- ${r}`));
        lines.push('');
        lines.push(`> 报告由排障工作台自动生成 · ${fmt.time(d.generatedAt)}`);
        const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `排障报告_${sel.value.host}_${fmt.dateShort ? fmt.dateShort(sel.value.clock) : sel.value.clock}.md`;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        toast('报告已导出', 'ok');
      }

      let timer = null;
      function toggleAuto() { auto.value = !auto.value; if (auto.value) timer = setInterval(load, 20000); else clearInterval(timer); }
      onMounted(load);
      onBeforeUnmount(() => clearInterval(timer));

      return { rows, stats, f, hosts, auto, sel, diag, loading, ic, sevColor, sevText, confText, load, select, runDiag, exportReport, toggleAuto, fmt };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.TroubleshootPage = TroubleshootPage;
  NC.route('/troubleshoot', { title: '排障工作台', comp: 'TroubleshootPage' });
})();
