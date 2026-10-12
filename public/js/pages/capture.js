/* =========================================================================
   旁路采集任务：旁路抓包（tshark/dumpcap）与设备侧采集的滚动轮转任务管理
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, watch } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const TABS = [
    { k: 'tasks', n: '采集任务', i: 'list' },
    { k: 'files', n: '抓包文件', i: 'camera' }
  ];

  const TASK_KIND = [
    { v: 'pcap', n: '旁路抓包', d: '本机网卡镜像，解析五元组与载荷特征' },
    { v: 'device', n: '设备侧采集', d: 'SSH 拉取交换机 MAC / ARP 表做周期巡检' }
  ];

  const CapturePage = {
    name: 'CapturePage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
        <div class="grow"></div>
        <span class="fs12 muted">{{ env.ready ? (env.engine + ' 已就绪') : '抓包环境未就绪' }}</span>
      </div>

      <!-- ==================== 采集任务 ==================== -->
      <div v-show="tab==='tasks'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('server',15)"></span><span>采集引擎</span>
            <div class="grow"></div><button class="btn sm" @click="loadAll" v-html="ic('refresh',13)+'<span>刷新</span>'"></button></div>
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
            <div class="result-box">
              <div class="l fs12 muted">抓包程序</div>
              <div class="big" :style="{fontSize:17, color: env.ready ? 'var(--success)' : 'var(--warn)'}">{{ env.engine || '未检测到' }}</div>
              <div class="fs11 muted ellipsis" :title="env.bin || env.hint">{{ env.bin || env.hint }}</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">可用网卡</div>
              <div class="big" style="color:var(--primary)">{{ ifaces.length }}</div>
              <div class="fs11 muted">非回环接口</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">任务总数</div>
              <div class="big">{{ tasks.length }}</div>
              <div class="fs11 muted">其中启用 {{ enabledCount }} 个</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">累计抓包</div>
              <div class="big">{{ fmt.bytes(files.reduce((a,b)=>a+Number(b.size||0),0)) }}</div>
              <div class="fs11 muted">{{ files.length }} 个文件</div>
            </div>
          </div>
          <div class="hint-line mt12" v-if="!env.ready"><span v-html="ic('alert',13)"></span><span>{{ env.hint }}</span></div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('list',15)"></span><span>任务列表</span>
            <div class="grow"></div>
            <button class="btn primary sm" @click="edit(null)" v-html="ic('plus',14)+'<span>新建任务</span>'"></button></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr>
                <th style="width:200px">任务</th><th style="width:90px">类型</th><th style="width:120px">网卡 / 目标</th>
                <th style="width:200px">过滤条件</th><th style="width:90px">轮转</th><th style="width:90px">执行</th>
                <th style="width:120px">保留</th><th style="width:100px">运行状态</th><th style="width:150px">操作</th>
              </tr></thead>
              <tbody>
                <tr v-for="t in tasks" :key="t.id">
                  <td class="ellipsis" style="max-width:200px" :title="t.name"><b>{{ t.name }}</b>
                    <div class="fs11 muted">{{ fmt.ago(t.lastStartedAt) }}执行 · {{ Number(t.runs||0) }} 次</div></td>
                  <td><span class="tag" :class="t.kind==='device'?'':'green'">{{ kindText(t.kind) }}</span></td>
                  <td class="mono fs11 ellipsis" style="max-width:120px">{{ t.kind==='device' ? (t.hosts||'全部') : ('iface ' + (t.iface||'1')) }}</td>
                  <td class="mono fs11 ellipsis" style="max-width:200px" :title="t.bpf">{{ t.bpf || '不过滤' }}</td>
                  <td class="mono fs11">{{ Number(t.intervalSec||0) }}s / {{ Number(t.pcapSize||0) }}MB</td>
                  <td class="mono fs11">{{ Number(t.seconds||0) }}s</td>
                  <td class="mono fs11">{{ Number(t.retainHours||0) }}h</td>
                  <td><span class="tag" :style="statusStyle(t)">{{ statusText(t) }}</span></td>
                  <td class="row gap6">
                    <button class="btn sm" @click="runTask(t)" v-html="ic('play',13)"></button>
                    <button class="btn sm" @click="toggle(t)">{{ t.enabled?'停用':'启用' }}</button>
                    <button class="btn sm" @click="edit(t)">{{ ic('edit',13) }}</button>
                    <button class="btn sm" @click="del(t)">{{ ic('trash',13) }}</button>
                  </td>
                </tr>
                <tr v-if="!tasks.length"><td colspan="9" class="tbl-empty">还没有采集任务，点右上角「新建任务」开始旁路持续采集</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ==================== 抓包文件 ==================== -->
      <div v-show="tab==='files'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('camera',15)"></span><span>抓包文件</span>
            <div class="grow"></div><button class="btn sm" @click="loadFiles" v-html="ic('refresh',13)"></button></div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:260px">文件</th><th style="width:110px">大小</th><th style="width:80px">报文</th><th style="width:80px">会话</th><th style="width:110px">引擎</th><th style="width:180px">开始时间</th><th style="width:130px">操作</th></tr></thead>
              <tbody>
                <tr v-for="f in files" :key="f.id">
                  <td class="mono ellipsis" style="max-width:260px" :title="f.path">{{ f.name || f.id }}<div class="fs11 muted">{{ f.filter || '不过滤' }}</div></td>
                  <td class="mono">{{ fmt.bytes(f.size) }}</td>
                  <td class="mono-num">{{ fmt.num(f.packets) }}</td>
                  <td class="mono-num">{{ f.sessions ?? '-' }}</td>
                  <td class="fs11 muted">{{ f.engine || f.source || '-' }}</td>
                  <td class="mono fs11 muted">{{ fmt.time(f.startedAt) }}</td>
                  <td class="row gap6">
                    <button class="btn sm" @click="go('/flow?tab=sessions')" title="到会话回溯查看">回溯</button>
                    <a class="btn sm" :href="'/api/capture/' + f.id + '/download'">下载</a>
                  </td>
                </tr>
                <tr v-if="!files.length"><td colspan="7" class="tbl-empty">暂无抓包文件</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ==================== 新建 / 编辑 ==================== -->
      <NcModal v-if="form" :title="form.id ? '编辑采集任务' : '新建采集任务'" wide ok-text="保存任务" @close="form=null" @ok="save">
        <div class="col gap12">
          <div class="row gap12">
            <div class="field" style="flex:2"><label>任务名称</label>
              <input class="inp" v-model.trim="form.name" placeholder="如：核心区旁路采集"></div>
            <div class="field" style="flex:1"><label>采集类型</label>
              <select class="inp" v-model="form.kind" @change="onKind">
                <option v-for="k in TASK_KIND" :key="k.v" :value="k.v">{{ k.n }}</option>
              </select></div>
          </div>
          <div class="hint-line" v-if="kindDesc"><span v-html="ic('info',13)"></span><span>{{ kindDesc }}</span></div>

          <div class="row gap12" v-if="form.kind==='pcap'">
            <div class="field" style="flex:1"><label>网卡</label>
              <select class="inp" v-model="form.iface">
                <option value="1">默认第一个可用网卡</option>
                <option v-for="i in ifaces" :key="i.name" :value="i.name">{{ i.name }} · {{ i.address }}</option>
              </select></div>
            <div class="field" style="flex:2"><label>BPF 过滤（可选）</label>
              <input class="inp mono" v-model.trim="form.bpf" placeholder="如：port 80 or port 443 or host 10.252.28.99"></div>
          </div>
          <div class="field" v-if="form.kind==='device'"><label>目标设备（逗号分隔，留空为全部纳管设备）</label>
            <input class="inp" v-model.trim="form.hosts" placeholder="sw-core-01,sw-acc-02"></div>

          <div class="row gap12">
            <div class="field" style="flex:1"><label>{{ form.kind==='device' ? '巡检间隔（秒）' : '单次抓包时长（秒）' }}</label>
              <input class="inp" type="number" min="1" v-model.number="form.seconds"></div>
            <div class="field" style="flex:1"><label>{{ form.kind==='device' ? '单文件上限（MB）' : '轮转间隔（秒）' }}</label>
              <input class="inp" type="number" min="1" v-model.number="form.intervalSec"></div>
            <div class="field" style="flex:1"><label>{{ form.kind==='device' ? '轮转间隔（秒）' : '单文件大小（MB）' }}</label>
              <input class="inp" type="number" min="1" v-model.number="form.pcapSize"></div>
            <div class="field" style="flex:1"><label>保留时长（小时）</label>
              <input class="inp" type="number" min="1" v-model.number="form.retainHours"></div>
          </div>

          <label class="checkbox"><input type="checkbox" v-model="form.enabled"> 启用（服务启动时自动周期执行）</label>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>本地抓包由平台自动选择 TShark + Npcap 或 Windows PktMon，无需单独安装；设备侧采集依赖已配置的 SSH 凭据。引擎每 5 秒巡检一次到点任务，并按保留时长自动清理。</span></div>
        </div>
        <template #foot>
          <button class="btn" @click="form=null">取消</button>
        </template>
      </NcModal>
    </div>`,
    setup() {
      const TABS_ = TABS, TASK_KIND_ = TASK_KIND;
      const tab = ref('tasks');
      const tasks = ref([]), files = ref([]);
      const env = reactive({ engine: '', bin: '', ready: false, ifaces: [] });
      const ifaces = computed(() => env.ifaces || []);
      const form = ref(null);
      const saving = ref(false);

      const ic = (n, s) => icon(n, s);
      const enabledCount = computed(() => tasks.value.filter(t => t.enabled).length);
      const kindDesc = computed(() => (TASK_KIND_.find(k => k.v === form.value?.kind) || {}).d || '');
      const kindText = (k) => (TASK_KIND_.find(x => x.v === k) || { n: k }).n;
      const statusText = (t) => !t.enabled ? '已停用' : (t.status === 'running' ? '执行中' : (Number(t.runs) ? '空闲' : '未执行'));
      const statusStyle = (t) => !t.enabled ? { color: '#94a3b8' } : t.status === 'running' ? { color: '#16a34a' } : { color: '#2563eb' };

      function onKind() { const k = TASK_KIND_.find(x => x.v === form.value.kind); if (k && k.v === 'device') { form.value.seconds = 60; form.value.intervalSec = 300; } }

      async function loadAll() {
        try {
          const r = await api.get('/capture/tasks');
          tasks.value = r.rows || [];
          Object.assign(env, { engine: r.env?.engine || '', bin: r.env?.bin || '', ready: !!r.env?.ready, ifaces: r.env?.ifaces || [] });
        } catch (e) { toast(e.message, 'err'); }
      }
      async function loadFiles() {
        try { const r = await api.get('/capture/list?limit=200'); files.value = r.rows || []; } catch (e) { }
      }
      const refresh = async () => { await loadAll(); await loadFiles(); };

      function edit(t) {
        form.value = t ? JSON.parse(JSON.stringify(t)) : {
          name: '', kind: 'pcap', iface: '1', bpf: '', hosts: '', credentialId: '',
          pcapSize: 100, retainHours: 72, intervalSec: 300, seconds: 30, enabled: true, status: 'idle', runs: 0
        };
      }
      async function save() {
        const f = form.value;
        if (!f.name) return toast('任务名称必填', 'warn');
        saving.value = true;
        try {
          const r = f.id ? await api.put('/capture/tasks/' + f.id, f) : await api.post('/capture/tasks', f);
          toast('任务已保存', 'ok');
          form.value = null;
          await loadAll();
        } catch (e) { toast(e.message, 'err'); } finally { saving.value = false; }
      }
      async function runTask(t) {
        try {
          const r = await api.post('/capture/tasks/' + t.id + '/run', {});
          toast(r.error ? r.error : `已执行：${r.packets ?? 0} 包 / ${r.sessions ?? 0} 会话`, r.error ? 'err' : 'ok');
          await loadAll();
        } catch (e) { toast(e.message, 'err'); }
      }
      async function toggle(t) {
        try { const r = await api.post('/capture/tasks/' + t.id + '/toggle', { enabled: !t.enabled }); toast(r.task?.enabled ? '已启用' : '已停用', 'ok'); await loadAll(); }
        catch (e) { toast(e.message, 'err'); }
      }
      async function del(t) {
        if (!confirm(`确定删除任务「${t.name}」？`)) return;
        try { await api.del('/capture/tasks/' + t.id); toast('已删除', 'ok'); await loadAll(); }
        catch (e) { toast(e.message, 'err'); }
      }

      watch(tab, (t) => { if (t === 'files') loadFiles(); });
      onMounted(refresh);

      return {
        TABS: TABS_, tab, tasks, files, env, ifaces, form, saving, ic, go, fmt,
        enabledCount, kindDesc, kindText, statusText, statusStyle, onKind,
        loadAll, loadFiles, refresh, edit, save, runTask, toggle, del
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.CapturePage = CapturePage;
  NC.route('/capture', { title: '旁路采集任务', comp: 'CapturePage' });
})();
