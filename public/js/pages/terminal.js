/* =========================================================================
   Web 终端 · 命令模板 · 批量配置下发 · 会话录制回放
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick, watch } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  /* --------------------------- ANSI 转义渲染 --------------------------- */
  const ANSI_RE = /\x1b\[([0-9;]*)m/g;
  const ANSI_FG = {
    30: '#7f8fa6', 31: '#ff6b6b', 32: '#4ade80', 33: '#fbbf24', 34: '#60a5fa',
    35: '#c084fc', 36: '#22d3ee', 37: '#e2e8f0', 90: '#64748b', 91: '#fca5a5',
    92: '#86efac', 93: '#fde047', 94: '#93c5fd', 95: '#d8b4fe', 96: '#67e8f9', 97: '#ffffff'
  };
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  function ansiToHtml(text) {
    const base = '#cfe3ff';
    let out = '', last = 0, m, bold = false, fg = base;
    ANSI_RE.lastIndex = 0;
    while ((m = ANSI_RE.exec(String(text)))) {
      out += esc(text.slice(last, m.index));
      let reset = false;
      for (const c of m[1].split(';').map(Number)) {
        if (c === 0) reset = true;
        else if (c === 1) bold = true;
        else if (ANSI_FG[c]) fg = ANSI_FG[c];
      }
      if (reset) { bold = false; fg = base; }
      out += `<span style="color:${fg};font-weight:${bold ? 600 : 400}">`;
      last = m.index + m[0].length;
    }
    out += esc(text.slice(last));
    return out;
  }

  /* --------------------------- 常用快捷命令 --------------------------- */
  const QUICK = [
    { n: 'show version', v: 'show version', d: '版本' },
    { n: '接口摘要', v: 'show interface status', d: '' },
    { n: 'IP 摘要', v: 'show ip int brief', d: '' },
    { n: 'MAC 表', v: 'display mac-address', d: '' },
    { n: 'ARP 表', v: 'show ip arp', d: '' },
    { n: '会话表', v: 'show session', d: '' },
    { n: 'CPU', v: 'show cpu', d: '' },
    { n: '内存', v: 'show memory', d: '' },
    { n: 'running-config', v: 'show running-config', d: '' },
    { n: '错误包统计', v: 'show interface counters errors', d: '' }
  ];

  /* ============================ 主页面 ============================ */
  const TerminalPage = {
    name: 'TerminalPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <!-- 工具栏 -->
      <div class="card">
        <div class="filter-bar" style="flex-wrap:wrap">
          <span class="fs13 fw5">新建会话</span>
          <select class="inp" v-model="newHost" style="max-width:230px">
            <option value="">选择设备…</option>
            <option v-for="d in devices" :key="d.host" :value="d.host">{{ d.name }} · {{ d.ip }}<span v-if="!d.status" style="color:var(--danger)">（离线）</span></option>
          </select>
          <select class="inp" v-model="newCred" style="max-width:220px">
            <option value="">演示模式（内置模拟器）</option>
            <option v-for="c in creds" :key="c.id" :value="c.id">{{ c.name }} · {{ c.username }}@{{ c.host }}</option>
          </select>
          <button class="btn primary" :disabled="!newHost" @click="newSession" v-html="ic('plus',15)+'<span>连接</span>'"></button>
          <div class="grow"></div>
          <button class="btn" @click="openTpl" v-html="ic('clipboard',15)+'<span>命令模板</span>'"></button>
          <button class="btn" @click="openDeploy" v-html="ic('zap',15)+'<span>配置下发</span>'"></button>
          <button class="btn" @click="openRecs" v-html="ic('eye',15)+'<span>会话录像</span>'"></button>
          <button class="btn" @click="openDeploys" v-html="ic('list',15)+'<span>下发记录</span>'"></button>
          <button class="btn" @click="load()" v-html="ic('refresh',15)"></button>
        </div>
        <div class="hint-line mt8">
          <span v-html="ic('shield',13)"></span>
          <span class="grow"></span>
          <span class="pill" :class="recOn?'up':'gray'">{{ recOn ? '会话录制已开启（可回放与审计）' : '会话录制已关闭' }}</span>
          <span class="fs12 muted" style="margin-left:8px">危险命令（reload / erase / format / write erase / reboot）会被自动拦截并要求二次确认</span>
        </div>
      </div>

      <!-- 会话区 -->
      <div v-if="!tabs.length" class="card">
        <div class="empty">
          <div style="font-size:30px;margin-bottom:10px" v-html="ic('terminal',30)"></div>
          <div class="fs13 fw5">暂无会话</div>
          <div class="fs12 muted mt8">在上方选择设备后点击「连接」，即可打开 Web 终端。未配置真机凭据时为演示模式，由内置 CLI 模拟器应答。</div>
          <button class="btn primary mt8" @click="go('/devices')">去设备管理查看设备</button>
        </div>
      </div>

      <div v-else class="col gap8">
        <div class="term-tabs">
          <div v-for="t in tabs" :key="t.id" class="term-tab" :class="{on: t.id===activeId}" @click="activeId=t.id">
            <span class="dot" :style="{width:6,height:6,borderRadius:'50%',background: t.connected?'#22c55e':'#f59e0b',display:'inline-block'}"></span>
            <span>{{ t.title }}</span>
            <span class="x" @click.stop="closeTab(t.id)" v-html="ic('close',12)"></span>
          </div>
          <div class="grow"></div>
        </div>

        <div class="term-wrap" style="height: calc(100vh - 330px); min-height: 380px; display:flex; flex-direction:column">
          <div ref="scroller" class="term scroll-y" style="flex:1" v-html="htmlLog(active)"></div>
          <div class="term-input" v-if="active">
            <span class="prompt mono">{{ active.promptText }}</span>
            <input ref="ipt" v-model="active.line" class="mono" :placeholder="active.connected? '输入命令后回车（支持 Backspace）' : '连接中…'"
                   :disabled="!active.connected" @keydown.enter="submit" @keydown.up="histUp" @keydown.down="histDown">
            <button class="btn sm" @click="submit" v-html="ic('send',14)"></button>
            <button class="btn sm ghost" :title="active.recording ? '正在录像' : '未录像'" @click="toggleRec(active)"
                    :style="{color: active.recording?'var(--success)':'var(--text-3)'}">{{ active.recording?'● REC':'○' }}</button>
            <button class="btn sm ghost" @click="active.connected&&wsSend(active,'close')" v-html="ic('power',14)"></button>
          </div>
        </div>

        <div v-if="active" class="card tight" style="padding:10px 12px">
          <div class="fs12 muted mb8">快捷命令（点击直接执行）</div>
          <div class="flex" style="gap:6px;flex-wrap:wrap">
            <button v-for="q in QUICK" :key="q.n" class="btn sm" :title="q.v" @click="runQuick(q.v)">{{ q.n }}</button>
          </div>
        </div>
      </div>

      <!-- 命令模板 -->
      <NcDrawer :title="'命令模板库（' + templates.length + '）'" wide v-if="tplOpen" @close="tplOpen=false">
        <div class="col gap12">
          <div class="filter-bar">
            <div class="search-box"><span v-html="ic('search',15)"></span>
              <input class="inp" v-model.trim="tplKw" placeholder="搜索模板 / 命令"></div>
            <select class="inp" v-model="tplCat"><option value="">全部分类</option><option v-for="c in tplCats" :key="c">{{ c }}</option></select>
            <div class="grow"></div>
            <button class="btn primary" @click="editTpl(null)" v-html="ic('plus',15)+'<span>新建</span>'"></button>
          </div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:150px">名称</th><th style="width:80px">厂商</th><th style="width:90px">分类</th><th>命令</th><th style="width:210px">操作</th></tr></thead>
              <tbody>
                <tr v-for="t in shownTpls" :key="t.id">
                  <td class="fw5">{{ t.name }}<div class="fs11 muted">{{ t.description||'' }}</div></td>
                  <td><span class="tag">{{ t.vendor }}</span></td>
                  <td><span class="tag blue">{{ t.category }}</span></td>
                  <td class="mono ellipsis" style="max-width:420px">{{ t.commands.slice(0,3).join(' ; ') }}<span v-if="t.commands.length>3">…</span></td>
                  <td>
                    <button class="btn sm" @click="useTpl(t)">打开</button>
                    <button class="btn sm" @click="editTpl(t)">编辑</button>
                    <button class="btn sm" @click="copyTpl(t)">复制</button>
                    <button class="btn sm danger" @click="delTpl(t)">删除</button>
                  </td>
                </tr>
                <tr v-if="!shownTpls.length"><td colspan="5" class="tbl-empty">暂无模板</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <template #foot>
          <button class="btn" @click="tplOpen=false">关闭</button>
        </template>
      </NcDrawer>

      <!-- 模板编辑 -->
      <NcModal title="命令模板" v-if="tplEdit" wide @close="tplEdit=null" @ok="saveTpl" ok-text="保存">
        <div class="form-grid">
          <label>名称<input class="inp" v-model="tplForm.name" placeholder="如：接入端口划入 VLAN 10"></label>
          <label>厂商<select class="inp" v-model="tplForm.vendor"><option>通用</option><option>Cisco</option><option>华为</option><option>H3C</option><option>Fortinet</option><option>Palo Alto</option></select></label>
          <label>分类<select class="inp" v-model="tplForm.category"><option>查询</option><option>配置</option><option>故障处理</option><option>安全</option><option>巡检</option></select></label>
          <label>备注说明<input class="inp" v-model="tplForm.description" placeholder="用途说明，便于团队协作"></label>
        </div>
        <label class="checkbox mt8" style="align-items:center;gap:6px">
          <input type="checkbox" v-model="tplForm.danger"> 标记为高风险（下发时必须二次确认）
        </label>
        <label class="mt8">命令列表（每行一条）
          <textarea class="inp mono" rows="9" v-model="tplForm.text" placeholder="interface GigabitEthernet1/0/5&#10; switchport mode access&#10; switchport access vlan 10&#10; no shutdown"></textarea>
        </label>
        <div class="hint-line mt8"><span v-html="ic('alert',13)"></span><span>支持换行输入；下发时按行顺序在设备上执行。</span></div>
      </NcModal>

      <!-- 配置下发 -->
      <NcDrawer title="批量配置下发" wide v-if="depOpen" @close="depOpen=false">
        <div class="col gap12">
          <div class="fs13 fw5">1. 选择目标设备</div>
          <div class="table-wrap" style="max-height:190px;overflow:auto">
            <table class="ntable">
              <thead><tr><th style="width:34px"></th><th>设备</th><th>地址</th><th>厂商</th><th>角色</th></tr></thead>
              <tbody>
                <tr v-for="d in devices" :key="d.host" :style="d.selected?{background:'var(--primary-weak)'}:{}" @click="d.selected=!d.selected" style="cursor:pointer">
                  <td><input type="checkbox" :checked="d.selected" @click.stop></td>
                  <td class="fw5">{{ d.name }}</td><td class="mono">{{ d.ip }}</td><td>{{ d.vendor }}</td><td>{{ d.role }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="fs13 fw5">2. 选择凭据</div>
          <div class="filter-bar">
            <select class="inp" v-model="depCred"><option value="">演示模式（模拟器）</option>
              <option v-for="c in creds" :key="c.id" :value="c.id">{{ c.name }} · {{ c.username }}@{{ c.host }}:{{ c.port }}</option></select>
            <div class="grow"></div>
            <button class="btn sm" @click="openTpl">从模板导入</button>
          </div>

          <div class="fs13 fw5">3. 执行命令 <span class="fs12 muted fw4">（已选 {{ depHosts.length }} 台设备，{{ depCmds.length }} 条命令）</span></div>
          <textarea class="inp mono" rows="8" v-model="depText" placeholder="interface GigabitEthernet1/0/5&#10; switchport access vlan 10&#10; no shutdown"></textarea>
          <div class="filter-bar">
            <input class="inp" v-model="depReason" placeholder="操作事由（会写入审计日志，如：二季度端口调整）" style="max-width:340px">
            <div class="grow"></div>
            <button class="btn" @click="depDry" v-html="ic('search',15)+'<span>预检（dryRun）</span>'"></button>
            <button class="btn primary" :disabled="depBusy" @click="depRun">
              <span v-if="depBusy" class="typing"><span></span><span></span><span></span></span>
              <span v-else v-html="ic('send',15)+'<span>执行下发</span>'"></span>
            </button>
          </div>

          <div v-if="dryInfo" class="card tight">
            <div class="card-head"><span class="fs12 fw5">预检查结果</span><button class="btn sm ghost" @click="dryInfo=null">关闭</button></div>
            <div class="col gap4 fs12">
              <div class="mono">目标：{{ dryInfo.preview.hosts.join(', ') }}</div>
              <div class="mono">命令：{{ dryInfo.preview.commands.join(' ; ') }}</div>
              <div v-if="dryInfo.preview.dangerHits.length" class="row" style="color:var(--danger)">
                <span v-html="ic('alert',14)"></span>命中高风险规则：{{ dryInfo.preview.dangerHits.join(' / ') }}
              </div>
              <div v-else class="row" style="color:var(--success)"><span v-html="ic('check',14)"></span>未发现高风险命令</div>
            </div>
          </div>

          <div v-if="depDanger" class="card" style="border-color:var(--danger)">
            <div class="card-head" style="color:var(--danger)"><span v-html="ic('alert',15)"></span><span class="fs13 fw5">高风险操作确认</span></div>
            <div class="col gap8 fs12">
              <div class="mono" style="color:var(--danger)">命中规则：{{ depDanger.join(' / ') }}</div>
              <div class="muted">此操作可能中断业务或导致设备重启。请填写下方确认文本后再执行，操作全程会被录像并记录到审计日志。</div>
              <input class="inp" v-model="depConfirm" placeholder="输入原因以确认执行：端口割接、故障恢复等">
            </div>
          </div>

          <div v-if="depResult" class="col gap8">
            <div class="fs13 fw5">执行结果</div>
            <div class="table-wrap">
              <table class="ntable">
                <thead><tr><th style="width:150px">设备</th><th style="width:80px">状态</th><th style="width:90px">耗时</th><th>输出</th></tr></thead>
                <tbody>
                  <tr v-for="r in depResult" :key="r.host">
                    <td class="fw5">{{ r.host }}<div class="fs11 muted" v-if="r.demo">演示模式</div></td>
                    <td><span class="pill" :class="r.ok?'up':'down'">{{ r.ok?'成功':'失败' }}</span></td>
                    <td class="mono-num">{{ (r.ms/1000).toFixed(1) }}s</td>
                    <td><button class="btn sm" @click="viewOut(r)">查看回显</button></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
        <template #foot>
          <button class="btn" @click="depOpen=false">关闭</button>
        </template>
      </NcDrawer>

      <!-- 下发回显 -->
      <NcModal title="设备回显" wide v-if="outView" @close="outView=null" hide-ok ok-text="关闭" @ok="outView=null">
        <pre class="code-block scroll-y" style="max-height:56vh;white-space:pre-wrap">{{ outView }}</pre>
      </NcModal>

      <!-- 会话录像 -->
      <NcDrawer title="会话录像回放" v-if="recOpen" @close="recOpen=false">
        <div class="col gap12">
          <div class="filter-bar">
            <div class="search-box"><span v-html="ic('search',15)"></span><input class="inp" v-model.trim="recKw" placeholder="设备 / 用户 / 命令"></div>
            <div class="grow"></div>
            <select class="inp" v-model="recLimit" style="max-width:110px">
              <option :value="20">最近 20</option><option :value="50">最近 50</option><option :value="100">最近 100</option>
            </select>
          </div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:70px">会话</th><th style="width:140px">设备</th><th style="width:80px">用户</th><th style="width:70px">方式</th><th style="width:130px">开始时间</th><th style="width:120px">事件 / 大小</th><th style="width:100px">操作</th></tr></thead>
              <tbody>
                <tr v-for="r in shownRecs" :key="r.id">
                  <td class="mono fs11">#{{ String(r.id).slice(-8) }}</td>
                  <td class="fw5">{{ r.host }}<div class="fs11 muted">{{ r.kind==='demo'?'演示会话':'真实会话' }}</div></td>
                  <td>{{ r.user }}</td>
                  <td><span class="tag" :class="r.kind==='demo'?'amber':'green'">{{ r.kind==='demo'?'演示':'真实' }}</span></td>
                  <td class="fs11 muted">{{ fmt.time(r.startedAt) }}<div class="fs11">{{ fmt.ago(r.startedAt) }}</div></td>
                  <td class="mono-num fs11">{{ r.events }} 帧<div class="fs11 muted">{{ fmt.bytes(r.bytes) }}</div></td>
                  <td><button class="btn sm" @click="playRec(r)">回放</button><button class="btn sm danger" @click="delRec(r)">删除</button></td>
                </tr>
                <tr v-if="!shownRecs.length"><td colspan="7" class="tbl-empty">暂无录像</td></tr>
              </tbody>
            </table>
          </div>
          <div class="fs12 muted">录像以 JSON 行方式落盘（输入/输出/时间戳），可用于事故复盘与合规审计。</div>
        </div>
        <template #foot><button class="btn" @click="recOpen=false">关闭</button></template>
      </NcDrawer>

      <!-- 录像播放器 -->
      <NcModal title="会话回放" wide v-if="playing" @close="closePlay" :hide-ok="true">
        <div class="col gap12">
          <div class="filter-bar">
            <span class="fs12 muted">{{ playMeta.host }} · {{ playMeta.user }} · {{ playMeta.kind }} · {{ fmt.time(playMeta.at) }}</span>
            <div class="grow"></div>
            <select class="inp" v-model="playSpeed" style="max-width:90px"><option :value="0.5">0.5x</option><option :value="1">1x</option><option :value="2">2x</option><option :value="4">4x</option><option :value="8">8x</option></select>
            <button class="btn sm" @click="playToggle">{{ playing.paused ? '播放' : '暂停' }}</button>
            <button class="btn sm" @click="playBack">上一段</button>
            <button class="btn sm" @click="playEnd">跳到末尾</button>
            <label class="fs12 muted nowrap">跟随<input type="checkbox" v-model="playFollow" style="margin-left:4px"></label>
          </div>
          <div class="term-wrap" style="height:52vh">
            <div ref="playBox" class="term scroll-y" v-html="ansiToHtml(playBuf)"></div>
          </div>
          <div class="fs12 muted">共 {{ playTotal }} 帧，当前第 {{ playIdx + 1 }} 帧 · <span class="mono">{{ playNow }}</span></div>
        </div>
      </NcModal>

      <!-- 下发记录 -->
      <NcDrawer title="配置下发记录" v-if="dep2Open" @close="dep2Open=false">
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr><th style="width:110px">时间</th><th style="width:70px">用户</th><th style="width:170px">目标</th><th>命令</th><th>结果</th></tr></thead>
            <tbody>
              <tr v-for="r in deploys" :key="r.id">
                <td class="fs11 muted">{{ fmt.time(r.at) }}</td>
                <td>{{ r.user }}</td>
                <td class="mono fs11">{{ (r.hosts||[]).join(',') }}</td>
                <td class="mono ellipsis fs11" style="max-width:320px" :title="(r.commands||[]).join(' ; ')">{{ (r.commands||[]).join(' ; ') }}</td>
                <td><span class="pill" :class="(r.results||[]).every(x=>x.ok)?'up':'warn'">{{ (r.results||[]).filter(x=>x.ok).length }}/{{ (r.results||[]).length }} 成功</span></td>
              </tr>
              <tr v-if="!deploys.length"><td colspan="5" class="tbl-empty">暂无记录</td></tr>
            </tbody>
          </table>
        </div>
        <template #foot><button class="btn" @click="dep2Open=false">关闭</button></template>
      </NcDrawer>
    </div>`,
    setup() {
      const devices = ref([]), creds = ref([]), templates = ref([]), tabs = ref([]), deploys = ref([]), recs = ref([]);
      const activeId = ref(''), newHost = ref(''), newCred = ref('');
      const tplOpen = ref(false), tplEdit = ref(null), tplForm = reactive({ name: '', vendor: '通用', category: '查询', description: '', danger: false, text: '' });
      const tplKw = ref(''), tplCat = ref('');
      const depOpen = ref(false), dep2Open = ref(false), recOpen = ref(false);
      const depCred = ref(''), depText = ref(''), depReason = ref(''), depConfirm = ref(''), depBusy = ref(false);
      const dryInfo = ref(null), depDanger = ref(null), depResult = ref(null);
      const outView = ref('');
      const recKw = ref(''), recLimit = ref(50);
      const scroller = ref(null), ipt = ref(null);
      /* 回放播放器 */
      const playing = ref(null), playBuf = ref(''), playIdx = ref(-1), playTotal = ref(0),
        playSpeed = ref(1), playFollow = ref(true), playNow = ref('-'),
        playMeta = reactive({ host: '-', user: '-', kind: '-', at: '', cols: 0, rows: 0 });
      const playBox = ref(null);
      let playTimer = null;
      const QUICK_ = QUICK;

      const active = computed(() => tabs.value.find(t => t.id === activeId.value) || null);
      const recOn = ref(false);
      const htmlLog = (t) => (t ? ansiToHtml(t.log) : '');

      /* --------------------------- 数据加载 --------------------------- */
      async function load() {
        try {
          const [d, c, t] = await Promise.all([
            api.get('/devices'),
            api.get('/system/credentials'),
            api.get('/terminal/templates')
          ]);
          devices.value = (d.rows || []).map(x => ({ ...x, selected: false }));
          creds.value = c.rows || [];
          templates.value = t.rows || [];
          recOn.value = true;
        } catch (e) { toast('加载失败：' + e.message, 'err'); }
      }

      /* --------------------------- 会话管理 --------------------------- */
      function newSession() {
        if (!newHost.value) return toast('请先选择设备', 'warn');
        const cred = creds.value.find(c => c.id === newCred.value);
        const dev = devices.value.find(d => d.host === newHost.value);
        if (tabs.value.some(t => t.host === newHost.value && t.credId === newCred.value)) {
          activeId.value = tabs.value.find(t => t.host === newHost.value && t.credId === newCred.value).id;
          return toast('该会话已存在', 'info');
        }
        const id = 's' + Date.now() + Math.random().toString(36).slice(2, 5);
        const tab = {
          id, host: newHost.value, credId: newCred.value || '',
          title: (dev ? dev.name : newHost.value) + (cred ? ' · ' + cred.name : ' · 演示'),
          log: '', line: '', connected: false, recording: true, promptText: (dev ? dev.name : newHost.value) + '>',
          hist: [], hIdx: -1, ws: null, dev, cred
        };
        tabs.value.push(tab); activeId.value = id;
        connect(tab);
      }

      function connect(tab) {
        try {
          const url = NC.wsUrl('/ws/terminal', {
            host: tab.host, credId: tab.credId,
            cols: Math.max(60, Math.floor((tab.dev || {})._w || 150)), rows: 40
          });
          const ws = new WebSocket(url);
          tab.ws = ws;
          ws.onopen = () => { tab.connected = true; toast('已连接 ' + tab.title, 'ok'); scrollBottom(); };
          ws.onmessage = (ev) => {
            const d = ev.data;
            if (typeof d !== 'string') return;
            if (d.startsWith('{')) { try { const m = JSON.parse(d); if (m.t === 'ready') tab.connected = true; } catch { } return; }
            tab.log += d;
            if (tab.log.length > 200000) tab.log = tab.log.slice(-160000);
            if (activeId.value === tab.id) scrollBottom();
          };
          ws.onclose = () => { tab.connected = false; tab.log += '\r\n\x1b[90m[会话已断开]\x1b[0m\r\n'; };
          ws.onerror = () => { tab.log += '\r\n\x1b[31m连接错误，请检查服务端状态。\x1b[0m\r\n'; };
        } catch (e) { toast('连接失败：' + e.message, 'err'); }
      }

      function wsSend(tab, text) {
        if (!tab || !tab.ws || tab.ws.readyState !== 1) { toast('会话未连接', 'warn'); return; }
        tab.ws.send(JSON.stringify({ t: 'i', d: text }));
      }
      function submit() {
        const t = active.value; if (!t || !t.connected) return;
        const cmd = t.line; if (!cmd) return;
        t.hist.push(cmd); t.histIdx = -1;
        t.log += t.promptText + ' ' + cmd + '\r\n';
        t.line = '';
        wsSend(t, cmd + '\r');
        scrollBottom();
      }
      function histUp() { const t = active.value; if (!t) return; if (!t.hist.length) return; t.histIdx = (t.histIdx < 0 ? t.hist.length - 1 : Math.max(0, t.histIdx - 1)); t.line = t.hist[t.histIdx] || ''; }
      function histDown() { const t = active.value; if (!t || t.histIdx < 0) return; t.histIdx++; if (t.histIdx >= t.hist.length) { t.histIdx = -1; t.line = ''; } else t.line = t.hist[t.histIdx]; }
      function runQuick(v) {
        const t = active.value; if (!t) return toast('请先打开会话', 'warn');
        if (!t.connected) return toast('会话未连接，请稍候', 'warn');
        if (t.credId) { wsSend(t, v + '\r'); return; }
        // 演示模式：模拟器会自动做字符回显，这里补一行本地提示
        t.log += t.promptText + ' ' + v + '\r\n';
        wsSend(t, v + '\r'); scrollBottom();
      }
      function toggleRec(t) { t.recording = !t.recording; toast(t.recording ? '该会话后续将被录像' : '已停止录像', 'info'); }
      function closeTab(id) {
        const t = tabs.value.find(x => x.id === id); if (!t) return;
        if (t.ws) { try { t.ws.send(JSON.stringify({ t: 'close' })); t.ws.close(); } catch { } }
        tabs.value = tabs.value.filter(x => x.id !== id);
        if (activeId.value === id) activeId.value = tabs.value.length ? tabs.value[tabs.value.length - 1].id : '';
      }
      function scrollBottom() { nextTick(() => { const el = scroller.value; if (el) el.scrollTop = el.scrollHeight; }); }
      watch(() => activeId.value, () => nextTick(scrollBottom));

      /* --------------------------- 模板 --------------------------- */
      const tplCats = computed(() => [...new Set(templates.value.map(t => t.category))]);
      const shownTpls = computed(() => {
        const k = tplKw.value.toLowerCase();
        return templates.value.filter(t => {
          if (tplCat.value && t.category !== tplCat.value) return false;
          if (!k) return true;
          return (t.name + t.description + t.commands.join(' ')).toLowerCase().includes(k);
        });
      });
      function openTpl() { load().then(() => { tplCat.value = ''; tplOpen.value = true; }); }
      function editTpl(t) {
        tplEdit.value = true;
        Object.assign(tplForm, t ? {
          id: t.id, name: t.name, vendor: t.vendor, category: t.category, description: t.description,
          danger: t.danger, text: Array.isArray(t.commands) ? t.commands.join('\n') : (t.commands || '')
        } : { id: '', name: '', vendor: '通用', category: '配置', description: '', danger: false, text: '' });
      }
      async function saveTpl() {
        try {
          const body = {
            name: tplForm.name, vendor: tplForm.vendor, category: tplForm.category,
            description: tplForm.description, danger: tplForm.danger,
            commands: String(tplForm.text).split(/\r?\n/).map(s => s.trim()).filter(Boolean)
          };
          if (!body.name) return toast('请填写模板名称', 'warn');
          if (!body.commands.length) return toast('命令不能为空', 'warn');
          const r = tplForm.id ? await api.put('/terminal/templates/' + tplForm.id, body) : await api.post('/terminal/templates', body);
          templates.value = (await api.get('/terminal/templates')).rows;
          tplEdit.value = null; tplOpen.value = false;
          toast(tplForm.id ? '模板已更新' : '模板已创建', 'ok');
        } catch (e) { toast(e.message, 'err'); }
      }
      async function delTpl(t) {
        if (!confirm('确定删除模板「' + t.name + '」？')) return;
        try { await api.del('/terminal/templates/' + t.id); templates.value = (await api.get('/terminal/templates')).rows; toast('已删除', 'ok'); } catch (e) { toast(e.message, 'err'); }
      }
      function useTpl(t) {
        depText.value = Array.isArray(t.commands) ? t.commands.join('\n') : t.commands;
        tplOpen.value = false; depOpen.value = true;
        toast('已导入「' + t.name + '」到下发命令', 'ok');
      }
      async function copyTpl(t) {
        try { await navigator.clipboard.writeText(Array.isArray(t.commands) ? t.commands.join('\n') : t.commands); toast('命令已复制', 'ok'); } catch { toast('浏览器不支持剪贴板', 'warn'); }
      }

      /* --------------------------- 配置下发 --------------------------- */
      const depHosts = computed(() => devices.value.filter(d => d.selected).map(d => d.host));
      const depCmds = computed(() => String(depText.value).split(/\r?\n/).map(s => s.trim()).filter(Boolean));
      function openDeploy() { if (!devices.value.length) load().then(() => depOpen.value = true); depOpen.value = true; }
      async function depDry() {
        try {
          const r = await api.post('/terminal/deploy', { hosts: depHosts.value, commands: depCmds.value, dryRun: true });
          dryInfo.value = r; depDanger.value = r.preview.dangerHits.length ? r.preview.dangerHits : null;
        } catch (e) { toast(e.message, 'err'); }
      }
      async function depRun() {
        if (!depHosts.value.length) return toast('请至少选择一台设备', 'warn');
        if (!depCmds.value.length) return toast('请填写执行命令', 'warn');
        if (depDanger.value.length && !depConfirm.value.trim()) return toast('请先填写确认原因', 'warn');
        depBusy.value = true; depResult.value = null;
        try {
          const r = await api.post('/terminal/deploy', {
            hosts: depHosts.value, commands: depCmds.value, credentialId: depCred.value,
            confirmText: depConfirm.value, reason: depReason.value
          });
          if (r.requiresConfirm) { depDanger.value = r.dangerHits; return toast(r.message, 'warn'); }
          depResult.value = r.results || [];
          const okN = depResult.value.filter(x => x.ok).length;
          toast(`下发完成：${okN}/${depResult.value.length} 台成功`, okN === depResult.value.length ? 'ok' : 'warn');
          await loadDeploys();
        } catch (e) { toast(e.message, 'err'); } finally { depBusy.value = false; }
      }
      function openDeploys() { loadDeploys().then(() => dep2Open.value = true); }
      async function loadDeploys() { try { deploys.value = (await api.get('/terminal/deploys?limit=50')).rows || []; } catch (e) { } }
      const viewOut = (r) => { outView.value = (r.output || '') + (r.error ? '\n[错误] ' + r.error : '') || '（无输出）'; };

      /* --------------------------- 录像 --------------------------- */
      const shownRecs = computed(() => {
        const k = recKw.value.toLowerCase();
        return recs.value.filter(r => !k || (r.host + (r.user || '') + (r.commands || '')).toLowerCase().includes(k));
      });
      function openRecs() { api.get('/terminal/records?limit=' + recLimit.value).then(r => { recs.value = r.rows || []; recOpen.value = true; }).catch(e => toast(e.message, 'err')); }
      async function delRec(r) {
        if (!confirm('确定删除录像 #' + r.id + '？')) return;
        try { await api.del('/terminal/records/' + r.id); recs.value = (await api.get('/terminal/records?limit=' + recLimit.value)).rows; toast('已删除', 'ok'); } catch (e) { toast(e.message, 'err'); }
      }
      async function playRec(r) {
        closePlay();
        try {
          const d = await api.get('/terminal/records/' + r.id);
          Object.assign(playMeta, {
            host: d.meta.host || '-', user: d.meta.user || '-', kind: d.meta.kind || '-',
            at: d.meta.startedAt || '', cols: d.meta.cols || 0, rows: d.meta.rows || 0
          });
          playing.value = { paused: true, events: d.events || [] };
          playIdx.value = -1; playBuf.value = ''; playNow.value = '-'; playTotal.value = 0;
          nextTick(() => { applyPlay(); startPlay(); });
        } catch (e) { toast(e.message, 'err'); }
      }
      const playFrames = computed(() => {
        const evs = playing.value ? (playing.value.events || []) : [];
        return evs.map((e, i) => ({ i, t: e.t, d: e.d || '', at: e.at })).filter(x => x.t === 'i' || x.t === 'o');
      });
      function applyPlay() {
        const f = playFrames.value;
        const upto = f.filter(x => x.i <= playIdx.value);
        playBuf.value = upto.map(x => x.d).join('');
        playTotal.value = f.length;
        if (playFollow.value) nextTick(() => { if (playBox.value) playBox.value.scrollTop = playBox.value.scrollHeight; });
      }
      function startPlay() {
        stopPlay();
        playTimer = setInterval(tick, Math.max(30, 260 / Number(playSpeed.value || 1)));
      }
      function stopPlay() { if (playTimer) clearInterval(playTimer); playTimer = null; }
      function tick() {
        if (playIdx.value >= lastIdx()) { stopPlay(); if (playing.value) playing.value.paused = true; playNow.value = '结束'; return; }
        playIdx.value++;
        const f = playFrames.value.find(x => x.i === playIdx.value);
        playNow.value = f ? fmt.time(f.at || Date.now()) : '-';
        applyPlay();
      }
      function lastIdx() { const f = playFrames.value; return f.length ? f[f.length - 1].i : 0; }
      function playToggle() {
        if (!playing.value) return;
        if (playTimer) { stopPlay(); playing.value.paused = true; }
        else { playing.value.paused = false; startPlay(); }
      }
      function playBack() { playIdx.value = Math.max(0, playIdx.value - 1); playNow.value = '快退'; applyPlay(); if (!playTimer) { playing.value.paused = true; } }
      function playEnd() { playIdx.value = lastIdx(); const f = playFrames.value[playFrames.value.length - 1]; playNow.value = f ? fmt.time(f.at || Date.now()) : '-'; applyPlay(); stopPlay(); if (playing.value) playing.value.paused = true; }
      function closePlay() { stopPlay(); playing.value = null; playBuf.value = ''; }

      const ic = (n, s) => icon(n, s);
      onMounted(load);
      onBeforeUnmount(() => {
        tabs.value.forEach(t => { if (t.ws) { try { t.ws.close(); } catch { } } });
        stopPlay();
      });

      return {
        devices, creds, templates, tabs, activeId, newHost, newCred, active,
        tplOpen, tplEdit, tplForm, tplKw, tplCat, shownTpls, tplCats,
        depOpen, dep2Open, recOpen, depCred, depText, depReason, depConfirm, depBusy,
        dryInfo, depDanger, depResult, depHosts, depCmds, outView, viewOut,
        recKw, recLimit, shownRecs, deploys,
        playing, playBuf, playIdx, playTotal, playFrames, playSpeed, playFollow, playNow, playMeta, playBox,
        QUICK: QUICK_, recOn, htmlLog, ansiToHtml,
        load, newSession, wsSend, submit, histUp, histDown, runQuick, toggleRec, closeTab,
        openTpl, editTpl, saveTpl, delTpl, useTpl, copyTpl,
        openDeploy, depDry, depRun, openDeploys, loadDeploys,
        openRecs, delRec, playRec, playToggle, playBack, playEnd, closePlay,
        scroller, ipt, ic, go, fmt
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.TerminalPage = TerminalPage;
  NC.route('/terminal', { title: 'Web 终端', comp: 'TerminalPage' });
})();
