/* =========================================================================
   应用外壳：登录 / 侧边导航 / 顶栏 / 路由渲染 / AI 助手
   ========================================================================= */
(function () {
  const { createApp, ref, reactive, computed, watch, onMounted, nextTick } = Vue;
  const NC = window.NC;
  const { state: S, api, fmt, icon, toast, currentRoute, routes, go } = NC;

  /* ------------------------------- 登录页 ------------------------------- */
  const Login = {
    template: `
    <div class="login-wrap">
      <div class="login-grid"></div>
      <div class="login-card">
        <div class="login-brand">
          <div class="row gap12">
            <div style="width:38px;height:38px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(135deg,#2563eb,#22d3ee);box-shadow:0 6px 20px rgba(37,99,235,.5)">
              <span v-html="ic('layers',20)" style="color:#fff;display:block"></span>
            </div>
            <div>
              <div style="color:#fff;font-size:15px;font-weight:600">NETOPS CONSOLE</div>
              <div class="sub" style="font-size:10.5px;letter-spacing:2px">Network Operations Platform</div>
            </div>
          </div>
          <h1>网络分析与监控<br>运维控制台</h1>
          <div class="sub">Network Analysis & Monitoring</div>
          <div class="login-feats">
            <div><i></i> 大屏可视化 · 设备与端口实时态势</div>
            <div><i></i> Web 终端 · 配置下发与全程会话录像</div>
            <div><i></i> 会话定位 · IP/MAC 一键查到交换机端口</div>
            <div><i></i> 内网测速 · 带宽 / 延迟 / 丢包 / 抖动</div>
            <div><i></i> 告警联动 · Zabbix 数据源 + 多渠道推送</div>
          </div>
        </div>
        <div class="login-form">
          <h2>登录</h2>
          <div class="hint">请输入运维账号，凭据由系统管理员分配</div>
          <form @submit.prevent="submit">
            <div class="field">
              <label>用户名</label>
              <input class="inp" v-model.trim="form.username" autocomplete="username" placeholder="请输入用户名">
            </div>
            <div class="field">
              <label>密码</label>
              <input class="inp" type="password" v-model="form.password" autocomplete="current-password" placeholder="请输入密码">
            </div>
            <div class="row-between mb12">
              <label class="checkbox"><input type="checkbox" v-model="form.remember"> 记住用户名</label>
            </div>
            <button class="btn primary btn-block lg" :disabled="loading">
              <span v-if="loading" class="typing"><span></span><span></span><span></span></span>
              <span v-else>登 录</span>
            </button>
          </form>
          <div class="demo-accounts">
            <div class="row-between"><b>演示账号（首次可直接体验）</b><span class="tag green">演示模式</span></div>
            管理员 <b>admin / admin@123</b> <span @click="fill('admin','admin@123')">一键填入</span><br>
            运维员 <b>ops / ops@123</b> <span @click="fill('ops','ops@123')">一键填入</span><br>
            审计员 <b>audit / audit@123</b> <span @click="fill('audit','audit@123')">一键填入</span>
          </div>
        </div>
      </div>
    </div>`,
    setup() {
      const form = reactive({ username: localStorage.getItem('netops.lastUser') || '', password: '', remember: true });
      const loading = ref(false);
      const ic = (n) => icon(n);
      const fill = (u, p) => { form.username = u; form.password = p; };
      const submit = async () => {
        if (!form.username || !form.password) return toast('请输入用户名和密码', 'warn');
        loading.value = true;
        try {
          const r = await api.post('/auth/login', { username: form.username, password: form.password });
          NC.setToken(r.token);
          S.user = r.user;
          if (form.remember) localStorage.setItem('netops.lastUser', form.username);
          toast(`欢迎回来，${r.user.displayName}`, 'ok', '登录成功');
          if (!location.hash) go('/screen');
        } catch (e) {
          toast(e.message || '登录失败', 'err');
        } finally { loading.value = false; }
      };
      return { form, loading, submit, fill, ic };
    }
  };

  /* ------------------------------ AI 助手 ------------------------------ */
  const AIAssistant = {
    props: { open: Boolean, host: String },
    emits: ['close'],
    template: `
    <div class="ai-panel" v-if="open">
      <div class="ai-head">
        <span v-html="ic('robot',20)" style="display:block"></span>
        <div class="grow">
          <div class="n">AI 运维助手</div>
          <div class="s">{{ providerText }}</div>
        </div>
        <button class="icon-btn" style="background:rgba(255,255,255,.14);border-color:transparent;color:#fff" @click="$emit('close')" v-html="ic('close',15)"></button>
      </div>
      <div class="ai-body" ref="bodyEl">
        <div v-if="!msgs.length" class="ai-msg bot">
我是这套网络运维控制台的 AI 助手。我已经读取到当前纳管设备的实时状态与告警，可以直接问我：

• 某台交换机某个端口为什么 down
• CPU / 内存 / 温度告警该怎么处理
• 帮我写一段 Cisco / 华为 / H3C 配置
• 这条告警要不要处理、怎么消
• Zabbix 数据为空的排查方法
        </div>
        <div v-for="(m,i) in msgs" :key="i" class="ai-msg" :class="m.role" v-html="m.html"></div>
        <div v-if="loading" class="ai-msg bot"><span class="typing"><span></span><span></span><span></span></span></div>
      </div>
      <div class="ai-quick">
        <button v-for="q in quick" :key="q" @click="ask(q)">{{ q }}</button>
      </div>
      <div class="ai-foot">
        <textarea v-model="input" rows="2" placeholder="描述你的问题，Enter 发送 / Shift+Enter 换行" @keydown.enter.exact.prevent="ask()"></textarea>
        <button class="btn primary" @click="ask()" :disabled="loading || !input.trim()" v-html="ic('send',16)"></button>
      </div>
    </div>`,
    setup(props) {
      const input = ref('');
      const loading = ref(false);
      const msgs = ref([]);
      const bodyEl = ref(null);
      const providerText = computed(() => {
        const ai = S.aiConfig || {};
        if (ai.provider === 'openai') return `已接入云端模型 ${ai.model || ''}`;
        if (ai.provider === 'ollama') return `本地 Ollama ${ai.model || ''}`;
        return '规则引擎专家模式（可在系统管理接入大模型）';
      });
      const quick = computed(() => props.host
        ? [`${props.host} 有什么异常`, `${props.host} 端口错包怎么看`, `${props.host} 健康度低的原因`]
        : ['当前有哪些严重告警', '端口 down 的排查顺序', '帮我写 VLAN 配置', 'CPU 高的常见原因']);
      const ic = (n, s) => icon(n, s);

      function md(t) {
        let s = String(t || '')
          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        s = s.replace(/\`\`\`([\s\S]*?)\`\`\`/g, (m, c) => '<pre>' + c.replace(/^\n/, '') + '</pre>');
        s = s.replace(/\`([^\`\n]+)\`/g, '<code>$1</code>');
        s = s.replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>');
        return s;
      }
      async function ask(preset) {
        const q = (preset || input.value).trim();
        if (!q || loading.value) return;
        input.value = '';
        msgs.value.push({ role: 'user', html: md(q) });
        loading.value = true;
        await nextTick(() => { if (bodyEl.value) bodyEl.value.scrollTop = bodyEl.value.scrollHeight; });
        try {
          const r = await api.post('/ai/chat', {
            messages: msgs.value.filter(m => m.role === 'user' || m.role === 'assistant')
              .map(m => ({ role: m.role, content: m.text || '' })).concat([{ role: 'user', content: q }]),
            host: props.host || ''
          });
          msgs.value.push({ role: 'bot', html: md(r.answer), text: r.answer });
        } catch (e) {
          msgs.value.push({ role: 'bot', html: '<b>请求失败：</b>' + md(e.message) });
        } finally {
          loading.value = false;
          await nextTick(() => { if (bodyEl.value) bodyEl.value.scrollTop = bodyEl.value.scrollHeight; });
        }
      }
      watch(() => props.open, v => { if (v) nextTick(() => { if (bodyEl.value) bodyEl.value.scrollTop = bodyEl.value.scrollHeight; }); });
      return { input, loading, msgs, bodyEl, providerText, quick, ask, ic };
    }
  };

  /* ------------------------------ 应用外壳 ------------------------------ */
  const NAV = [
    { group: '排障', items: [{ p: '/troubleshoot', t: '排障工作台', i: 'search' }, { p: '/deep-tools', t: '深度排障工具', i: 'toolbox' }] },
    {
      group: '设备运维', items: [
        { p: '/devices', t: '设备管理', i: 'server' },
        { p: '/terminal', t: '终端与配置下发', i: 'terminal' },
        { p: '/traffic', t: '会话与流量', i: 'activity' },
        { p: '/speed', t: '内网测速', i: 'zap' }
      ]
    },
    {
      group: '流量分析', items: [
        { p: '/flow', t: '全流量回溯', i: 'history' },
        { p: '/flow-metrics', t: '性能与协议报表', i: 'chart' },
        { p: '/flow-graph', t: '通信关系时序图', i: 'share' },
        { p: '/capture', t: '旁路采集任务', i: 'camera' },
        { p: '/custom-protocols', t: '自定义协议', i: 'layers' }
      ]
    },
    {
      group: '安全扫描', items: [
        { p: '/scan', t: '网络扫描', i: 'search' },
        { p: '/diag', t: '诊断工具箱', i: 'shield' },
        { p: '/toolbox', t: '网络运维工具箱', i: 'toolbox' },
        { p: '/wifi', t: '无线勘测', i: 'wifi' }
      ]
    },
    { group: '监控告警', items: [{ p: '/alarms', t: '告警管理', i: 'bell', badge: true }, { p: '/topology', t: '网络拓扑', i: 'share' }] },
    { group: '大屏展示', items: [{ p: '/screen', t: '大屏可视化', i: 'monitor' }] },
    { group: '系统', items: [{ p: '/system', t: '系统管理', i: 'settings' }] }
  ];

  const Shell = {
    components: { Login, AIAssistant },
    template: `
    <Login v-if="!S.user" />
    <div class="app" v-else>
      <aside class="sidebar" :class="{collapsed:S.sidebarCollapsed}">
        <div class="sidebar-brand">
          <div class="sidebar-logo">N</div>
          <div class="sidebar-title" v-if="!S.sidebarCollapsed">
            {{ S.site.name }}<small>NETOPS CONSOLE</small>
          </div>
        </div>
        <nav class="sidebar-nav">
          <div class="nav-group" v-for="g in NAV" :key="g.group">
            <div class="nav-group-title">{{ g.group }}</div>
            <div v-for="it in g.items" :key="it.p" class="nav-item"
                 :class="{active: isActive(it.p)}" @click="go(it.p)" :title="it.t">
              <span v-html="ic(it.i)"></span>
              <span class="lbl">{{ it.t }}</span>
              <span v-if="it.badge && S.alarmCount" class="badge">{{ S.alarmCount }}</span>
            </div>
          </div>
        </nav>
        <div class="sidebar-foot" v-if="!S.sidebarCollapsed">
          <div class="row-between">
            <span>{{ S.datasourceMode === 'zabbix' ? 'Zabbix 数据源' : '演示模式' }}</span>
            <span :class="S.datasourceMode==='zabbix' ? 'c-green' : 'c-amber'">●</span>
          </div>
          <div style="margin-top:2px">v1.0.0 · {{ S.user.roleName }}</div>
        </div>
      </aside>

      <div class="main">
        <header class="topbar" v-if="!isScreen">
          <button class="icon-btn" @click="toggleSb" v-html="ic('menu',17)"></button>
          <div class="crumb">
            {{ crumbTitle }}
            <small>{{ crumbSub }}</small>
          </div>
          <div class="grow"></div>
          <div class="search-box">
            <span v-html="ic('search',15)"></span>
            <input v-model.trim="kw" placeholder="搜索设备名 / IP / 型号，回车" @keydown.enter="doSearch">
          </div>
          <button class="icon-btn" @click="refreshAll" title="刷新数据" v-html="ic('refresh',17)"></button>
          <button class="icon-btn" @click="openAlarms" title="告警">
            <span v-html="ic('bell',17)"></span>
            <span v-if="S.alarmCount" class="dot">{{ S.alarmCount > 99 ? '99+' : S.alarmCount }}</span>
          </button>
          <button class="icon-btn" @click="toggleSb" title="切换导航" v-html="ic('eye',17)" style="display:none"></button>
          <div class="avatar" @click="menuOpen = !menuOpen" :title="S.user.displayName">{{ S.user.displayName.slice(0,1) }}</div>
          <div v-if="menuOpen" class="card" style="position:absolute;right:14px;top:52px;width:230px;z-index:40;box-shadow:var(--shadow-lg)">
            <div class="card-body" style="padding:12px">
              <div class="fw6">{{ S.user.displayName }}</div>
              <div class="fs12 muted">{{ S.user.username }} · {{ S.user.roleName }}</div>
              <div class="divider"></div>
              <div class="nav-item" style="color:var(--text);height:32px;padding:0 8px" @click="pwdOpen=true;menuOpen=false"><span v-html="ic('lock',15)"></span><span class="lbl">修改密码</span></div>
              <div class="nav-item" style="color:var(--danger);height:32px;padding:0 8px" @click="logout"><span v-html="ic('logout',15)"></span><span class="lbl">退出登录</span></div>
            </div>
          </div>
        </header>

        <div class="grow" :style="isScreen ? '' : 'overflow:auto;background:var(--bg)'">
          <component v-if="comp" :is="comp" v-bind="compProps" :key="routeKey" />
          <div v-else class="empty" style="padding-top:120px">
            <div v-html="ic('alert',42)"></div>
            <div class="mt12">功能开发中：{{ currentRoute.path }}</div>
          </div>
        </div>
      </div>

      <button class="fab" v-if="!isScreen" @click="aiOpen=!aiOpen" :title="'AI 运维助手'" v-html="ic('robot',25)"></button>
      <AIAssistant :open="aiOpen" @close="aiOpen=false" />

      <NcModal v-if="pwdOpen" title="修改密码" :loading="pwdLoading" ok-text="保存" @close="pwdOpen=false" @ok="savePwd">
        <div class="field"><label>原密码</label><input class="inp" type="password" v-model="pwd.oldPassword"></div>
        <div class="field"><label>新密码（至少 6 位）</label><input class="inp" type="password" v-model="pwd.newPassword"></div>
      </NcModal>

      <div class="toasts">
        <div v-for="t in S.toasts" :key="t.id" class="toast" :class="t.kind">
          <span v-html="ic(t.kind==='ok'?'check':t.kind==='err'?'alert':'bell',17)" :style="{color: t.kind==='ok'?'var(--success)':t.kind==='err'?'var(--danger)':'var(--warn)',marginTop:'1px'}"></span>
          <div class="grow"><b>{{ t.title }}</b><p>{{ t.msg }}</p></div>
        </div>
      </div>
    </div>`,
    setup() {
      const menuOpen = ref(false), aiOpen = ref(false), kw = ref('');
      const pwdOpen = ref(false), pwdLoading = ref(false);
      const pwd = reactive({ oldPassword: '', newPassword: '' });
      const routeKey = ref(0);
      const crumb = (p) => {
        const m = { '/screen': ['大屏可视化', '全网设备态势总览'], '/devices': ['设备管理', '纳管设备清单与运行状态'], '/terminal': ['终端与配置下发', 'Web CLI、命令模板、批量下发、会话录像'], '/traffic': ['会话与流量', 'IP/MAC 定位、地址表、会话分析、抓包'], '/flow': ['全流量回溯', '旁路采集的会话库：协议构成、会话检索与载荷特征'], '/capture': ['旁路采集任务', '旁路抓包 / 设备侧采集的滚动轮转任务'], '/scan': ['网络扫描', '本机存活发现、端口扫描、服务识别与风险判定'], '/speed': ['内网测速', '带宽吞吐 / 延迟丢包 / 链路质量'], '/alarms': ['告警管理', '实时告警与处置记录'], '/topology': ['网络拓扑', '设备层级与链路关系'], '/system': ['系统管理', '数据源、凭据库、用户权限、日志'] };
        const k = p.split('/').slice(0, 2).join('/');
        m['/diag'] = ['网络诊断工具箱', '摄像头扫描 / IP 冲突 / 环路 / 日志审计 / 外网测速 / DHCP 检测'];
        m['/toolbox'] = ['网络运维工具箱', '重定向链追踪 / HTTP 可用性 / SSL 证书 / Whois / DNS / Ping / MTR / 指纹 / 子网 / WoL'];
        return m[k] || ['网络运维控制台', ''];
      };
      const isScreen = computed(() => currentRoute.value.path === '/screen');
      const comp = computed(() => currentRoute.value.def && currentRoute.value.def.comp ? currentRoute.value.def.comp : null);
      const compProps = computed(() => {
        const c = currentRoute.value;
        return { params: c.params || {}, query: c.query || {} };
      });
      const crumbTitle = computed(() => crumb(currentRoute.value.path)[0]);
      const crumbSub = computed(() => currentRoute.value.path.includes('/device/') ? '设备详情与端口实时状态' : crumb(currentRoute.value.path)[1]);
      const isActive = (p) => S.route.startsWith(p) && (p !== '/devices' || !S.route.startsWith('/devices/') || p === '/devices');
      const ic = (n, s) => icon(n, s);
      const toggleSb = () => { S.sidebarCollapsed = !S.sidebarCollapsed; localStorage.setItem('netops.sb', S.sidebarCollapsed ? '1' : '0'); };
      const openAlarms = () => go('/alarms');
      const doSearch = () => { if (kw.value) go('/devices?keyword=' + encodeURIComponent(kw.value)); };
      const logout = async () => {
        try { await api.post('/auth/logout'); } catch (e) { }
        NC.clearToken(); S.user = null; menuOpen.value = false;
        toast('已安全退出', 'ok');
      };
      const savePwd = async () => {
        pwdLoading.value = true;
        try {
          await api.post('/auth/password', { ...pwd });
          toast('密码已修改，请重新登录', 'ok');
          pwdOpen.value = false;
          await api.post('/auth/logout').catch(() => { });
          NC.clearToken(); S.user = null;
        } catch (e) { toast(e.message, 'err'); } finally { pwdLoading.value = false; }
      };
      const refreshAll = () => { routeKey.value++; toast('已刷新当前页面数据', 'ok'); };

      let timer = null;
      async function boot() {
        if (!S.token) return;
        try {
          const me = await api.get('/auth/me');
          S.user = me.user; S.site = me.site || S.site;
          await pollStatus();
          timer = setInterval(pollStatus, 30000);
        } catch (e) { NC.clearToken(); }
      }
      async function pollStatus() {
        try {
          const r = await api.get('/alarms');
          S.alarmCount = r.rows.filter(a => a.status !== 'resolved' && a.status !== 'closed').length;
          S.criticalCount = (r.stats.disaster || 0) + (r.stats.high || 0);
        } catch (e) { }
        try { const s = await api.get('/system/settings'); S.aiConfig = s.settings.ai; S.datasourceMode = s.settings.datasource.mode; } catch (e) { }
      }
      onMounted(boot);
      watch(() => S.user, v => { if (v && !timer) timer = setInterval(pollStatus, 30000); });
      return {
        S, NAV, currentRoute, comp, compProps, routeKey, crumbTitle, crumbSub, isActive, isScreen,
        menuOpen, aiOpen, kw, doSearch, openAlarms, logout, toggleSb, refreshAll, ic, go,
        pwdOpen, pwd, pwdLoading, savePwd
      };
    }
  };

  /* ------------------------------ 全局注册 ------------------------------ */
  const app = createApp(Shell);
  app.config.globalProperties.$fmt = fmt;
  for (const [name, comp] of Object.entries(NC.components)) app.component(name, comp);
  for (const [name, comp] of Object.entries(window.PAGES || {})) app.component(name, comp);
  app.mount('#app');
  window.__APP__ = app;
})();
