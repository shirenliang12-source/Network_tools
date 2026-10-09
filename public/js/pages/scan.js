/* =========================================================================
   网络扫描：本机执行的存活发现 / 端口扫描 / 服务识别 / 风险判定
   扫描结果同时回流到资产台账与告警中心
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, watch } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const TABS = [
    { k: 'tasks', n: '扫描任务', i: 'list' },
    { k: 'hosts', n: '发现主机', i: 'server' },
    { k: 'ports', n: '开放端口', i: 'database' },
    { k: 'risks', n: '风险清单', i: 'shield' },
    { k: 'report', n: '扫描报告', i: 'file' }
  ];

  const RISK_COLOR = {
    critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#0891b2', info: '#64748b'
  };
  const RISK_TEXT = { critical: '极高危', high: '高危', medium: '中危', low: '低危', info: '提示' };
  const RISK_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

  const ScanPage = {
    name: 'ScanPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
        <div class="grow"></div>
        <span class="fs12 muted">单次上限 {{ env.maxHosts }} 个地址 · 扫描在控制台本机执行</span>
      </div>

      <!-- ==================== 概览 ==================== -->
      <div class="card">
        <div class="card-head"><span v-html="ic('search',15)"></span><span>扫描概览</span>
          <div class="grow"></div>
          <button class="btn primary sm" @click="quickOpen()" v-html="ic('zap',13)+'<span>快速扫描</span>'"></button>
          <button class="btn sm" @click="loadAll" v-html="ic('refresh',13)+'<span>刷新</span>'"></button></div>
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(170px,1fr))">
          <div class="result-box">
            <div class="l fs12 muted">扫描任务</div>
            <div class="big">{{ tasks.length }}</div>
            <div class="fs11 muted">启用 {{ enabledCount }} 个</div>
          </div>
          <div class="result-box">
            <div class="l fs12 muted">最近一次扫描</div>
            <div class="big" style="font-size:17px">{{ lastRun ? lastRun.hostsAlive + '/' + lastRun.hostsTotal : '—' }}</div>
            <div class="fs11 muted">存活 / 目标</div>
          </div>
          <div class="result-box">
            <div class="l fs12 muted">开放端口</div>
            <div class="big" style="color:var(--primary)">{{ lastRun ? lastRun.portsOpen : 0 }}</div>
            <div class="fs11 muted">{{ lastRun ? fmt.ago(lastRun.startedAt) + '扫描' : '暂无记录' }}</div>
          </div>
          <div class="result-box">
            <div class="l fs12 muted">高危主机</div>
            <div class="big" :style="{color: riskHosts ? 'var(--danger,#dc2626)' : 'var(--success)'}">{{ riskHosts }}</div>
            <div class="fs11 muted">{{ riskPorts }} 个端口存在风险</div>
          </div>
        </div>
      </div>

      <!-- ==================== 扫描任务 ==================== -->
      <div v-show="tab==='tasks'" class="card">
        <div class="card-head"><span v-html="ic('list',15)"></span><span>任务列表</span>
          <div class="grow"></div>
          <button class="btn primary sm" @click="edit(null)" v-html="ic('plus',14)+'<span>新建任务</span>'"></button></div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr>
              <th style="width:190px">任务</th><th style="width:190px">目标网段</th>
              <th style="width:150px">端口范围</th><th style="width:80px">发现方式</th>
              <th style="width:70px">并发</th><th style="width:90px">周期</th>
              <th style="width:90px">保留</th><th style="width:100px">状态</th><th style="width:150px">操作</th>
            </tr></thead>
            <tbody>
              <tr v-for="t in tasks" :key="t.id">
                <td class="ellipsis" style="max-width:190px" :title="t.name"><b>{{ t.name }}</b>
                  <div class="fs11 muted">{{ fmt.ago(t.lastStartedAt) }}执行 · {{ Number(t.runs||0) }} 次</div></td>
                <td class="mono fs11 ellipsis" style="max-width:190px" :title="t.targets">{{ t.targets }}</td>
                <td class="mono fs11 ellipsis" style="max-width:150px" :title="t.ports">{{ portText(t.ports) }}</td>
                <td><span class="tag">{{ modeText(t.discoverMode) }}</span></td>
                <td class="mono fs11">{{ Number(t.concurrency||60) }}</td>
                <td class="mono fs11">{{ Number(t.intervalSec||0) }}s</td>
                <td class="mono fs11">{{ Number(t.retainHours||0) }}h</td>
                <td><span class="tag" :style="statusStyle(t)">{{ statusText(t) }}</span></td>
                <td class="row gap6">
                  <button class="btn sm" @click="runTask(t)" v-html="ic('play',13)"></button>
                  <button class="btn sm" @click="toggle(t)">{{ t.enabled?'停用':'启用' }}</button>
                  <button class="btn sm" @click="edit(t)">{{ ic('edit',13) }}</button>
                  <button class="btn sm" @click="del(t)">{{ ic('trash',13) }}</button>
                </td>
              </tr>
              <tr v-if="!tasks.length"><td colspan="9" class="tbl-empty">还没有扫描任务，点右上角「新建任务」创建；也可以直接用「快速扫描」先试一次</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ==================== 发现主机 ==================== -->
      <div v-show="tab==='hosts'" class="card">
        <div class="card-head"><span v-html="ic('server',15)"></span><span>发现的主机</span>
          <div class="grow"></div>
          <select class="inp sm" style="width:180px" v-model="runId">
            <option v-for="r in runs" :key="r.id" :value="r.id">{{ r.name }} · {{ fmt.ago(r.startedAt) }}</option>
          </select>
          <input class="inp sm" style="width:150px" v-model="hostFilter.ip" placeholder="按 IP 过滤">
          <select class="inp sm" style="width:110px" v-model="hostFilter.risk">
            <option value="">全部风险</option>
            <option v-for="l in RISK_ORDER" :key="l" :value="l">{{ RISK_TEXT[l] }}</option>
          </select>
        </div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr>
              <th style="width:150px">IP 地址</th><th style="width:160px">主机名</th>
              <th style="width:70px">开放端口</th><th style="width:90px">风险等级</th>
              <th>风险标签</th>
            </tr></thead>
            <tbody>
              <tr v-for="h in hosts.rows" :key="h.id" style="cursor:pointer" @click="showHost(h)">
                <td class="mono">{{ h.ip }}</td>
                <td class="ellipsis" style="max-width:160px">{{ h.hostname || '—' }}</td>
                <td class="mono">{{ Number(h.openPorts||0) }}</td>
                <td><span class="tag" :style="{color: riskColor(h.riskLevel)}">{{ RISK_TEXT[h.riskLevel] || h.riskLevel }}</span></td>
                <td class="fs11 muted ellipsis">{{ (h.riskTags||[]).join('、') || '无明显风险' }}</td>
              </tr>
              <tr v-if="!hosts.rows.length"><td colspan="5" class="tbl-empty">该次扫描没有发现主机，换个网段或换一种发现方式再试</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ==================== 开放端口 ==================== -->
      <div v-show="tab==='ports'" class="card">
        <div class="card-head"><span v-html="ic('database',15)"></span><span>开放的端口</span>
          <div class="grow"></div>
          <select class="inp sm" style="width:180px" v-model="runId">
            <option v-for="r in runs" :key="r.id" :value="r.id">{{ r.name }} · {{ fmt.ago(r.startedAt) }}</option>
          </select>
          <input class="inp sm" style="width:110px" v-model="portFilter.port" placeholder="端口">
          <input class="inp sm" style="width:130px" v-model="portFilter.service" placeholder="服务名">
          <select class="inp sm" style="width:110px" v-model="portFilter.risk">
            <option value="">全部风险</option>
            <option v-for="l in RISK_ORDER" :key="l" :value="l">{{ RISK_TEXT[l] }}</option>
          </select>
        </div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr>
              <th style="width:140px">IP</th><th style="width:70px">端口</th><th style="width:140px">服务</th>
              <th style="width:90px">风险</th><th>首帧报文（banner）</th>
            </tr></thead>
            <tbody>
              <tr v-for="p in ports.rows" :key="p.id">
                <td class="mono">{{ p.ip }}</td>
                <td class="mono"><b>{{ Number(p.port) }}</b></td>
                <td class="ellipsis" style="max-width:140px">{{ p.service || 'unknown' }}<span v-if="p.product" class="muted fs11"> · {{ p.product }}</span></td>
                <td><span class="tag" :style="{color: riskColor(p.riskLevel)}">{{ RISK_TEXT[p.riskLevel] || p.riskLevel }}</span></td>
                <td class="mono fs11 ellipsis" style="max-width:320px" :title="p.banner">{{ p.banner || '—' }}</td>
              </tr>
              <tr v-if="!ports.rows.length"><td colspan="5" class="tbl-empty">该次扫描没有发现开放端口</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ==================== 风险清单 ==================== -->
      <div v-show="tab==='risks'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('shield',15)"></span><span>风险分布</span>
            <div class="grow"></div>
            <select class="inp sm" style="width:180px" v-model="runId">
              <option v-for="r in runs" :key="r.id" :value="r.id">{{ r.name }} · {{ fmt.ago(r.startedAt) }}</option>
            </select>
          </div>
          <div class="row gap12">
            <div v-for="r in stats.byRisk" :key="r.level" class="result-box"
                 style="flex:1;min-width:120px;cursor:pointer"
                 @click="portFilter.risk=r.level; tab='ports'">
              <div class="l fs12 muted">{{ RISK_TEXT[r.level] || r.level }}</div>
              <div class="big" :style="{color: riskColor(r.level)}">{{ r.count }}</div>
              <div class="fs11 muted">个端口</div>
            </div>
            <div v-if="!stats.byRisk.length" class="tbl-empty">该次扫描没有端口记录</div>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><span v-html="ic('activity',15)"></span><span>高危端口 TOP</span></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:90px">端口</th><th style="width:70px">数量</th><th style="width:140px">风险</th><th>处置建议</th></tr></thead>
              <tbody>
                <tr v-for="p in stats.byPort" :key="p.port">
                  <td class="mono"><b>{{ Number(p.port) }}</b></td>
                  <td class="mono">{{ p.count }}</td>
                  <td><span class="tag" :style="{color: riskColor(portRisk(p.port).level)}">{{ RISK_TEXT[portRisk(p.port).level] }}</span></td>
                  <td class="fs12">{{ portRisk(p.port).desc || '无匹配规则，建议结合业务确认该端口是否必要开放' }}</td>
                </tr>
                <tr v-if="!stats.byPort.length"><td colspan="4" class="tbl-empty">暂无数据</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ==================== 扫描报告 ==================== -->
      <div v-show="tab==='report'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('file',15)"></span><span>本次扫描摘要</span>
            <div class="grow"></div>
            <button class="btn sm" @click="exportCsv" v-html="ic('download',13)+'<span>导出 CSV</span>'"></button></div>
          <div v-if="run" class="col gap12">
            <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr))">
              <div class="result-box"><div class="l fs12 muted">任务名称</div><div class="fs13" style="font-weight:600">{{ run.name }}</div>
                <div class="fs11 muted ellipsis">{{ run.targets }}</div></div>
              <div class="result-box"><div class="l fs12 muted">发现方式</div><div class="big" style="font-size:17px">{{ modeText(run.mode) }}</div>
                <div class="fs11 muted">{{ portText(run.data?.ports) }}</div></div>
              <div class="result-box"><div class="l fs12 muted">扫描时长</div><div class="big" style="font-size:17px">{{ ((run.durationMs||0)/1000).toFixed(1) }}s</div>
                <div class="fs11 muted">{{ fmt.ago(run.startedAt) }}</div></div>
              <div class="result-box"><div class="l fs12 muted">状态</div><div class="big" style="font-size:17px;color:var(--success)">{{ statusOf(run) }}</div>
                <div class="fs11 muted">共执行扫描历史 {{ runs.length }} 条</div></div>
            </div>
          </div>
          <div v-else class="tbl-empty">先在上方选一次扫描</div>
        </div>
        <div class="card">
          <div class="card-head"><span v-html="ic('history',15)"></span><span>扫描历史</span></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr>
                <th style="width:180px">任务</th><th style="width:190px">目标</th>
                <th style="width:70px">存活</th><th style="width:80px">开放端口</th>
                <th style="width:80px">高危主机</th><th style="width:90px">耗时</th><th style="width:130px">开始时间</th><th style="width:90px">操作</th>
              </tr></thead>
              <tbody>
                <tr v-for="r in runs" :key="r.id">
                  <td class="ellipsis" style="max-width:180px">{{ r.name }}</td>
                  <td class="mono fs11 ellipsis" style="max-width:190px" :title="r.targets">{{ r.targets }}</td>
                  <td class="mono">{{ r.hostsAlive }}/{{ r.hostsTotal }}</td>
                  <td class="mono">{{ r.portsOpen }}</td>
                  <td class="mono" :style="{color: r.risks ? 'var(--danger,#dc2626)' : 'inherit'}">{{ r.risks }}</td>
                  <td class="mono fs11">{{ ((r.durationMs||0)/1000).toFixed(1) }}s</td>
                  <td class="fs11 muted">{{ fmt.ago(r.startedAt) }}</td>
                  <td><button class="btn sm" @click="runId=r.id; tab='hosts'">查看</button></td>
                </tr>
                <tr v-if="!runs.length"><td colspan="8" class="tbl-empty">还没有扫描记录</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ==================== 新建 / 编辑任务 ==================== -->
      <NcModal v-if="form" :title="form.id ? '编辑扫描任务' : '新建扫描任务'" @close="form=null">
        <template #body>
          <div class="field"><label>任务名称</label>
            <input class="inp" v-model="form.name" placeholder="例如：办公网段季度巡检"></div>
          <div class="field"><label>目标网段</label>
            <input class="inp mono" v-model="form.targets" placeholder="10.252.28.0/24 或 192.168.1.1-50，多个目标用逗号分隔"></div>
          <div class="row gap12">
            <div class="field" style="flex:1"><label>端口范围</label>
              <input class="inp mono" v-model="form.ports" placeholder="22,80,443 或 1000-2000"></div>
            <div class="field" style="flex:1"><label>端口预设</label>
              <select class="inp" @change="applyPreset($event)">
                <option value="">选择预设覆盖上面的端口</option>
                <option v-for="p in meta.presets" :key="p.key" :value="p.ports.join(',')">{{ p.label }}</option>
              </select></div>
          </div>
          <div class="row gap12">
            <div class="field" style="flex:1"><label>发现方式</label>
              <select class="inp" v-model="form.discoverMode">
                <option v-for="m in meta.modes" :key="m.key" :value="m.key">{{ m.label }}</option>
              </select></div>
            <div class="field" style="flex:1"><label>并发连接数</label>
              <input class="inp" type="number" min="1" max="400" v-model.number="form.concurrency"></div>
            <div class="field" style="flex:1"><label>单连接超时(ms)</label>
              <input class="inp" type="number" min="200" max="10000" v-model.number="form.timeoutMs"></div>
          </div>
          <div class="row gap12">
            <div class="field" style="flex:1"><label>定时周期（秒）</label>
              <input class="inp" type="number" min="60" v-model.number="form.intervalSec"></div>
            <div class="field" style="flex:1"><label>结果保留（小时）</label>
              <input class="inp" type="number" min="1" v-model.number="form.retainHours"></div>
          </div>
          <label class="checkbox"><input type="checkbox" v-model="form.banner"> 抓取服务 banner（识别更准，但每台主机多一次握手）</label>
          <label class="checkbox"><input type="checkbox" v-model="form.enabled"> 启用（到点自动扫描）</label>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>{{ modeDesc }}</span></div>
          <div class="hint-line"><span v-html="ic('alert',13)"></span><span>扫描结果会自动并入设备台账与告警中心；单次最多扫描 {{ env.maxHosts }} 个地址。</span></div>
        </template>
        <template #foot>
          <button class="btn" @click="form=null">取消</button>
          <button class="btn primary" :disabled="saving" @click="save">{{ saving?'保存中...':'保存' }}</button>
        </template>
      </NcModal>

      <!-- ==================== 快速扫描 ==================== -->
      <NcModal v-if="qform" title="快速扫描（不建任务，扫一次即返）" @close="qform=null">
        <template #body>
          <div class="field"><label>目标网段</label>
            <input class="inp mono" v-model="qform.targets" placeholder="127.0.0.1 或 10.252.28.0/30"></div>
          <div class="field"><label>端口范围</label>
            <input class="inp mono" v-model="qform.ports" placeholder="22,80,443,3389,445"></div>
          <div class="row gap12">
            <div class="field" style="flex:1"><label>发现方式</label>
              <select class="inp" v-model="qform.discoverMode">
                <option v-for="m in meta.modes" :key="m.key" :value="m.key">{{ m.label }}</option>
              </select></div>
            <div class="field" style="flex:1"><label>并发连接数</label>
              <input class="inp" type="number" min="1" max="400" v-model.number="qform.concurrency"></div>
          </div>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>先跑一次看看网段里有什么，满意了再存成定时任务。</span></div>
        </template>
        <template #foot>
          <button class="btn" @click="qform=null">取消</button>
          <button class="btn primary" :disabled="qrunning" @click="doQuick">{{ qrunning?'扫描中...':'开始扫描' }}</button>
        </template>
      </NcModal>
    </div>`,
    setup() {
      const TABS_ = TABS, RISK_ORDER_ = RISK_ORDER, RISK_TEXT_ = RISK_TEXT;
      const tab = ref('tasks');
      const tasks = ref([]), runs = ref([]), runId = ref('');
      const hosts = reactive({ total: 0, rows: [] });
      const ports = reactive({ total: 0, rows: [] });
      const stats = reactive({ byRisk: [], byPort: [], byService: [], riskPorts: 0, hostCount: 0 });
      const env = reactive({ maxHosts: 4096 });
      const meta = reactive({ presets: [], modes: [], riskRules: [] });
      const form = ref(null), qform = ref(null);
      const saving = ref(false), qrunning = ref(false);
      const hostFilter = reactive({ ip: '', risk: '' });
      const portFilter = reactive({ port: '', service: '', risk: '' });

      const ic = (n, s) => icon(n, s);
      const riskColor = (l) => RISK_COLOR[l] || '#64748b';

      const enabledCount = computed(() => tasks.value.filter(t => t.enabled).length);
      const lastRun = computed(() => runs.value[0] || null);
      const run = computed(() => runs.value.find(r => r.id === runId.value) || null);
      const riskHosts = computed(() => run.value ? Number(run.value.risks || 0) : 0);
      const riskPorts = computed(() => stats.riskPorts || 0);
      const modeDesc = computed(() => (meta.modes.find(m => m.key === form.value?.discoverMode) || {}).desc || '');

      const modeText = (k) => (meta.modes.find(m => m.key === k) || { label: k || 'tcp' }).label.replace(/（.*?）/g, '');
      const portText = (v) => {
        const s = String(v || '');
        return s.length > 34 ? s.slice(0, 32) + '…' : (s || '—');
      };
      const statusText = (t) => !t.enabled ? '已停用' : (t.status === 'running' ? '执行中' : (Number(t.runs) ? '空闲' : '未执行'));
      const statusStyle = (t) => !t.enabled ? { color: '#94a3b8' } : t.status === 'running' ? { color: '#16a34a' } : { color: '#2563eb' };
      const statusOf = (r) => r.status === 'done' ? '已完成' : (r.status === 'error' ? '失败' : r.status);
      /** 端口的风险规则（用于 TOP 表给出处置建议，规则表来自 /scan/presets） */
      const portRisk = (port) => {
        const n = Number(port);
        for (const r of meta.riskRules) if ((r.ports || []).includes(n)) return r;
        return { level: 'info', desc: '' };
      };
      const showHost = (h) => {
        portFilter.port = ''; portFilter.service = ''; portFilter.risk = h.riskLevel || '';
        hostFilter.ip = h.ip;
        tab.value = 'ports';
      };

      /* ------------------------------ 数据加载 ------------------------------ */
      async function loadMeta() {
        if (meta.presets.length) return;
        try {
          const r = await api.get('/scan/presets');
          Object.assign(meta, { presets: r.presets || [], modes: r.modes || [], riskRules: r.riskRules || [] });
        } catch (e) { }
      }
      async function loadAll() {
        try {
          const r = await api.get('/scan/tasks');
          tasks.value = r.rows || [];
        } catch (e) { toast(e.message, 'err'); }
        await loadRuns();
      }
      async function loadRuns() {
        try {
          const r = await api.get('/scan/runs?limit=30');
          runs.value = r.rows || [];
          if (!runId.value && runs.value.length) runId.value = runs.value[0].id;
        } catch { }
      }
      async function loadHosts() {
        if (!runId.value) { hosts.rows = []; hosts.total = 0; return; }
        try {
          const r = await api.get('/scan/hosts?runId=' + runId.value + '&ip=' + encodeURIComponent(hostFilter.ip)
            + '&risk=' + encodeURIComponent(hostFilter.risk) + '&limit=500');
          hosts.rows = r.rows || []; hosts.total = r.total || 0;
        } catch (e) { toast(e.message, 'err'); }
      }
      async function loadPorts() {
        if (!runId.value) { ports.rows = []; ports.total = 0; return; }
        try {
          const r = await api.get('/scan/ports?runId=' + runId.value + '&port=' + encodeURIComponent(portFilter.port)
            + '&service=' + encodeURIComponent(portFilter.service) + '&risk=' + encodeURIComponent(portFilter.risk) + '&limit=1000');
          ports.rows = r.rows || []; ports.total = r.total || 0;
        } catch (e) { toast(e.message, 'err'); }
      }
      async function loadStats() {
        if (!runId.value) { stats.byRisk = []; stats.byPort = []; stats.riskPorts = 0; return; }
        try { Object.assign(stats, await api.get('/scan/stats?runId=' + runId.value)); }
        catch (e) { toast(e.message, 'err'); }
      }
      const refreshRunData = async () => { await loadHosts(); await loadPorts(); await loadStats(); };

      /* ------------------------------ 任务操作 ------------------------------ */
      function edit(t) {
        form.value = t ? JSON.parse(JSON.stringify(t)) : {
          name: '', targets: '', ports: '22,80,443,3389,445', discoverMode: 'tcp',
          concurrency: 60, timeoutMs: 1200, intervalSec: 3600, retainHours: 72,
          banner: true, enabled: false, status: 'idle'
        };
      }
      function applyPreset(e) {
        const v = e.target.value;
        if (v) { form.value.ports = v; e.target.value = ''; }
      }
      function quickOpen() {
        qform.value = { targets: '', ports: '22,80,443,3389,445', discoverMode: 'tcp', concurrency: 60 };
      }
      async function save() {
        const f = form.value;
        if (!f.name) return toast('任务名称必填', 'warn');
        if (!f.targets) return toast('扫描目标必填，例如 10.252.28.0/24', 'warn');
        saving.value = true;
        try {
          if (f.id) await api.put('/scan/tasks/' + f.id, f); else await api.post('/scan/tasks', f);
          toast('任务已保存', 'ok');
          form.value = null;
          await loadAll();
        } catch (e) { toast(e.message, 'err'); } finally { saving.value = false; }
      }
      async function runTask(t) {
        try {
          const r = await api.post('/scan/tasks/' + t.id + '/run', {});
          toast(r.error ? r.error : `扫描完成：存活 ${r.alive} 台 / 开放端口 ${r.openPorts} 个${r.riskHosts ? ' / 高危主机 ' + r.riskHosts + ' 台' : ''}`, r.error ? 'err' : 'ok');
          await loadAll();
        } catch (e) { toast(e.message, 'err'); }
      }
      async function toggle(t) {
        try {
          const r = await api.post('/scan/tasks/' + t.id + '/toggle', { enabled: !t.enabled });
          toast(r.task?.enabled ? '已启用' : '已停用', 'ok');
          await loadAll();
        } catch (e) { toast(e.message, 'err'); }
      }
      async function del(t) {
        if (!confirm(`确定删除扫描任务「${t.name}」？历史扫描记录会保留。`)) return;
        try { await api.del('/scan/tasks/' + t.id); toast('已删除', 'ok'); await loadAll(); }
        catch (e) { toast(e.message, 'err'); }
      }
      async function doQuick() {
        const f = qform.value;
        if (!f.targets) return toast('扫描目标必填', 'warn');
        qrunning.value = true;
        try {
          const r = await api.post('/scan/quick', {
            targets: f.targets, ports: f.ports, discoverMode: f.discoverMode, concurrency: f.concurrency
          });
          qform.value = null;
          toast(r.error ? r.error : `快速扫描完成：存活 ${r.alive} 台 / 开放端口 ${r.openPorts} 个，已入库`, r.error ? 'err' : 'ok');
          await loadRuns();
          if (r.runId) { runId.value = r.runId; await refreshRunData(); }
        } catch (e) { toast(e.message, 'err'); } finally { qrunning.value = false; }
      }
      function exportCsv() {
        if (!runId.value) return toast('先选一次扫描', 'warn');
        window.location.href = '/api/scan/export?runId=' + runId.value;
      }

      watch(tab, (t) => { if (t === 'hosts') loadHosts(); if (t === 'ports') loadPorts(); if (t === 'risks') loadStats(); });
      watch(runId, refreshRunData);
      watch(() => [hostFilter.ip, hostFilter.risk], loadHosts);
      watch(() => [portFilter.port, portFilter.service, portFilter.risk], loadPorts);

      onMounted(async () => {
        await loadMeta();
        try { const r = await api.get('/scan/tasks'); env.maxHosts = r.env?.maxHosts || env.maxHosts; } catch { }
        await loadAll();
      });

      return {
        TABS: TABS_, RISK_ORDER: RISK_ORDER_, RISK_TEXT: RISK_TEXT_,
        tab, tasks, runs, runId, hosts, ports, stats, env, meta,
        form, qform, saving, qrunning, hostFilter, portFilter, ic, go, fmt,
        enabledCount, lastRun, run, riskHosts, riskPorts, modeDesc,
        riskColor, modeText, portText, statusText, statusStyle, statusOf, portRisk, showHost,
        loadAll, loadRuns, refreshRunData, edit, applyPreset, quickOpen, doQuick,
        save, runTask, toggle, del, exportCsv
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.ScanPage = ScanPage;
  NC.route('/scan', { title: '网络扫描', comp: 'ScanPage' });
})();
