/* =========================================================================
   告警管理 · 确认/关闭 · 通知推送 · 手动告警
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, onBeforeUnmount, watch } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const AlarmsPage = {
    name: 'AlarmsPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="kpi">
        <div class="kpi-card">
          <div class="kpi-icon i-red" v-html="ic('alert')"></div>
          <div><div class="kpi-val" style="color:var(--danger)">{{ stats.disaster }}</div><div class="kpi-lbl">灾难</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-amber" v-html="ic('alert')"></div>
          <div><div class="kpi-val" style="color:var(--warn)">{{ stats.high }}</div><div class="kpi-lbl">严重</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-blue" v-html="ic('bell')"></div>
          <div><div class="kpi-val">{{ stats.average }}</div><div class="kpi-lbl">一般</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-cyan" v-html="ic('bell')"></div>
          <div><div class="kpi-val">{{ stats.warning }}</div><div class="kpi-lbl">警告</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-purple" v-html="ic('shield')"></div>
          <div><div class="kpi-val" style="color:var(--purple)">{{ unack }}</div><div class="kpi-lbl">待确认</div>
            <div class="kpi-sub" v-if="auto">每 20 秒自动刷新</div></div>
        </div>
      </div>

      <div class="card">
        <div class="filter-bar">
          <div class="search-box" style="min-width:240px">
            <span v-html="ic('search',15)"></span>
            <input class="inp" v-model.trim="f.keyword" placeholder="设备 / 标题 / 描述" @keydown.enter="reload(1)">
          </div>
          <select class="inp" v-model="f.severity" @change="reload(1)">
            <option value="">全部级别</option>
            <option value="disaster">灾难</option><option value="high">严重</option>
            <option value="average">一般</option><option value="warning">警告</option><option value="information">信息</option>
          </select>
          <select class="inp" v-model="f.status" @change="reload(1)">
            <option value="">全部状态</option>
            <option value="problem">未确认</option><option value="acknowledged">已确认</option><option value="closed">已关闭</option><option value="resolved">已恢复</option>
          </select>
          <select class="inp" v-model="f.host" @change="reload(1)"><option value="">全部设备</option><option v-for="h in hosts" :key="h" :value="h">{{ h }}</option></select>
          <button class="btn" @click="reload(1)" v-html="ic('search',15)"></button>
          <button class="btn" @click="reset">重置</button>
          <div class="grow"></div>
          <label class="checkbox nowrap"><input type="checkbox" v-model="auto"> 自动刷新</label>
          <button class="btn" :class="{primary: auto}" @click="toggleAuto" v-html="ic(auto?'pause':'play',15)"></button>
          <button class="btn" @click="reload()" v-html="ic('refresh',15)"></button>
        </div>

        <div class="table-wrap">
          <table class="ntable">
            <thead>
              <tr>
                <th style="width:92px">级别</th>
                <th style="width:150px">设备</th>
                <th>告警内容</th>
                <th style="width:130px">发生时间</th>
                <th style="width:110px">状态</th>
                <th style="width:210px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="a in rows" :key="a.eventid || a.id" :style="a.severity==='disaster'?{background:'rgba(220,38,38,.045)'}:''">
                <td><span class="sev-dot" :class="a.severity"></span> <span class="fs12 fw5" :style="{color:sevColor(a.severity)}">{{ sevText(a.severity) }}</span></td>
                <td class="fw5 ellipsis" :title="a.host">
                  <span @click="go('/device/'+encodeURIComponent(a.host))" style="cursor:pointer;color:var(--primary)">{{ a.host }}</span>
                </td>
                <td>
                  <div class="ellipsis" :title="a.title">{{ a.title }}</div>
                  <div class="fs11 muted ellipsis" style="max-width:620px" v-if="a.message">{{ a.message }}</div>
                </td>
                <td class="fs12 muted">{{ fmt.time(a.clock) }}<div class="fs11">{{ fmt.ago(a.clock) }}</div></td>
                <td>
                  <span class="pill" :class="stateClass(a)">{{ stateText(a) }}</span>
                  <div class="fs11 muted" v-if="a.ackBy">确认人 {{ a.ackBy }}</div>
                </td>
                <td>
                  <template v-if="!isClosed(a)">
                    <button class="btn sm" :disabled="a.acknowledged" @click="ack(a)">{{ a.acknowledged?'已确认':'确认' }}</button>
                    <button class="btn sm danger" @click="close(a)">关闭</button>
                  </template>
                  <button v-else class="btn sm" @click="reopen(a)">重开</button>
                  <button class="btn sm" @click="detail(a)">详情</button>
                  <button class="btn sm" @click="ask(a)">AI 处置</button>
                </td>
              </tr>
              <tr v-if="!rows.length"><td colspan="6" class="tbl-empty">没有符合条件的告警</td></tr>
            </tbody>
          </table>
        </div>

        <div class="pager">
          <div>共 <b>{{ total }}</b> 条告警<span class="muted" v-if="total>w.size">（显示最近 {{ w.size }} 条）</span></div>
          <div class="pages">
            <button :disabled="w.page<=1" @click="w.page=1">首页</button>
            <button :disabled="w.page<=1" @click="w.page--">上一页</button>
            <button :disabled="w.page*w.size>=total" @click="w.page++">下一页</button>
          </div>
          <div>
            <select class="inp" v-model.number="w.size" style="width:96px">
              <option :value="20">20/页</option><option :value="50">50/页</option><option :value="100">100/页</option>
            </select>
          </div>
        </div>
      </div>

      <div class="grid" style="grid-template-columns:1fr 1fr;gap:16px">
        <div class="card">
          <div class="card-head"><span v-html="ic('bell',15)"></span><span>通知推送测试</span></div>
          <div class="fs12 muted mb8">配置见「系统管理 → 通知推送」。可先发送一条测试消息，确认企业微信 / 钉钉 / 邮件通道打通。</div>
          <div class="flex gap8">
            <button class="btn" @click="testNotify('')" v-html="ic('send',15)+'<span>全通道测试</span>'"></button>
            <button class="btn" @click="testNotify('wecom')">企业微信</button>
            <button class="btn" @click="testNotify('dingtalk')">钉钉</button>
            <button class="btn" @click="testNotify('smtp')">邮件</button>
            <button class="btn" @click="testNotify('webhook')">Webhook</button>
          </div>
          <div v-if="notifyRes" class="mt8">
            <pre class="code-block" style="max-height:150px">{{ notifyRes }}</pre>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('plus',15)"></span><span>手动创建告警</span></div>
          <div class="fs12 muted mb8">用于把非 Zabbix 来源的故障（如巡检脚本、人工发现）纳入同一处置流程，并触发通知推送。</div>
          <div class="form-grid">
            <label>设备 / 对象<input class="inp" v-model="newA.host" placeholder="SW-ACC-03"></label>
            <label>级别<select class="inp" v-model="newA.severity">
              <option value="disaster">灾难</option><option value="high">严重</option>
              <option value="average" selected>一般</option><option value="warning">警告</option><option value="information">信息</option>
            </select></label>
            <label style="grid-column:1/-1">标题<input class="inp" v-model="newA.title" placeholder="如：接入交换机 24 口集体 Up/Down 抖动"></label>
            <label style="grid-column:1/-1">详细描述<textarea class="inp" rows="3" v-model="newA.message" placeholder="补充背景、影响范围、已做的处置"></textarea></label>
          </div>
          <button class="btn primary mt8" :disabled="creating" @click="createAlarm" v-html="ic('plus',15)+'<span>创建并推送</span>'"></button>
          <div v-if="created.length" class="mt8">
            <div class="fs12 fw5 mb4">已推送记录</div>
            <div class="mini-log">{{ created.join('\\n') }}</div>
          </div>
        </div>
      </div>

      <!-- 告警详情 -->
      <NcModal title="告警详情" v-if="cur" wide @close="cur=null" hide-ok ok-text="关闭" @ok="cur=null">
        <div class="col gap12">
          <div class="row-between">
            <div class="row" style="gap:8px">
              <span class="sev-dot" :class="cur.severity"></span>
              <span class="fs15 fw5" :style="{color:sevColor(cur.severity)}">{{ sevText(cur.severity) }}</span>
              <span class="tag">{{ stateText(cur) }}</span>
            </div>
            <span class="fs12 muted">{{ fmt.time(cur.clock) }}（{{ fmt.ago(cur.clock) }}）</span>
          </div>
          <div class="fs15 fw5">{{ cur.title }}</div>
          <div class="form-grid">
            <label>设备<div class="inp mono" style="background:var(--surface-2)">{{ cur.host }}</div></label>
            <label>事件 ID<div class="inp mono" style="background:var(--surface-2)">{{ cur.eventid || cur.id || '-' }}</div></label>
            <label>来源<div class="inp" style="background:var(--surface-2)">{{ cur.source || (cur.eventid ? 'Zabbix' : '本地') }}</div></label>
            <label>确认<div class="inp" style="background:var(--surface-2)">{{ cur.ackBy ? cur.ackBy + ' / ' + fmt.time(cur.ackAt) : '未确认' }}</div></label>
          </div>
          <div v-if="cur.message">
            <div class="fs12 fw5 mb4">告警详情</div>
            <pre class="code-block" style="max-height:240px;white-space:pre-wrap">{{ cur.message }}</pre>
          </div>
          <div v-if="cur._detail">
            <div class="fs12 fw5 mb4">补充信息</div>
            <pre class="code-block" style="max-height:200px;white-space:pre-wrap">{{ cur._detail }}</pre>
          </div>
          <div class="card tight" v-if="advice">
            <div class="card-head" style="margin-bottom:4px"><span v-html="ic('robot',14)"></span><span>处置建议</span></div>
            <div class="fs12 muted" style="line-height:1.8">{{ advice }}</div>
          </div>
          <div class="flex gap8">
            <button class="btn primary" v-if="!cur.acknowledged" @click="ack(cur, true)">确认告警</button>
            <button class="btn danger" @click="close(cur, true)">关闭告警</button>
          </div>
        </div>
      </NcModal>
    </div>`,
    setup(props) {
      const rows = ref([]), total = ref(0), stats = reactive({ disaster: 0, high: 0, average: 0, warning: 0, information: 0 });
      const f = reactive({ severity: '', status: '', host: String((props.query && props.query.host) || ''), keyword: '' });
      const w = reactive({ page: 1, size: 20 });
      const hosts = ref([]), auto = ref(false), unack = ref(0);
      const cur = ref(null), advice = ref('');
      const notifyRes = ref(''), creating = ref(false), created = ref([]);
      const newA = reactive({ host: '', severity: 'average', title: '', message: '' });

      const ic = (n, s) => icon(n, s);
      const sevColor = (s) => ({ disaster: '#dc2626', critical: '#dc2626', high: '#ea580c', average: '#f59e0b', warning: '#eab308', information: '#3b82f6' }[s] || '#64748b');
      const sevText = (s) => NC.SEV_CN[s] || s || '-';
      const isClosed = (a) => a.status === 'closed' || a.status === 'resolved';
      const stateText = (a) => ({ problem: '未确认', acknowledged: '已确认', closed: '已关闭', resolved: '已恢复' }[a.status] || a.status || '-');
      const stateClass = (a) => a.status === 'closed' || a.status === 'resolved' ? 'neutral' : a.acknowledged ? 'warn' : (a.severity === 'disaster' || a.severity === 'high') ? 'down' : 'warn';

      async function load() {
        try {
          const q = new URLSearchParams();
          if (f.severity) q.set('severity', f.severity);
          if (f.status) q.set('status', f.status);
          if (f.host) q.set('host', f.host);
          if (f.keyword) q.set('keyword', f.keyword);
          q.set('limit', '500');
          const r = await api.get('/alarms?' + q.toString());
          const list = r.rows || [];
          const start = (w.page - 1) * w.size;
          rows.value = list.slice(start, start + w.size);
          total.value = list.length;
          Object.assign(stats, r.stats || {});
          unack.value = list.filter(a => a.status !== 'closed' && !isClosed(a) && !a.acknowledged).length;
          
          // 级别分布饼图数据备用：这里用统计卡
          if (!hosts.value.length) {
            const d = await api.get('/devices');
            hosts.value = [...new Set((d.rows || []).map(x => x.host))];
          }
        } catch (e) { toast('加载告警失败：' + e.message, 'err'); }
      }
      function reload(p) { if (p) w.page = p; load(); }
      function reset() { Object.assign(f, { severity: '', status: '', host: '', keyword: '' }); w.page = 1; load(); }

      async function ack(a, fromModal) {
        try {
          await api.post('/alarms/' + encodeURIComponent(a.eventid || a.id) + '/ack', { message: '通过控制台确认' });
          toast('已确认：' + (a.title || a.host), 'ok');
          if (fromModal) cur.value = null;
          load();
        } catch (e) { toast(e.message, 'err'); }
      }
      async function close(a, fromModal) {
        try {
          await api.post('/alarms/' + encodeURIComponent(a.eventid || a.id) + '/close');
          toast('已关闭告警', 'ok');
          if (fromModal) cur.value = null;
          load();
        } catch (e) { toast(e.message, 'err'); }
      }
      async function reopen(a) {
        try {
          await api.post('/alarms', {
            host: a.host, title: '【重开】' + (a.title || ''), message: a.message || '',
            severity: a.severity || 'warning', source: 'manual'
          });
          toast('已重新创建告警', 'ok'); load();
        } catch (e) { toast(e.message, 'err'); }
      }

      function detail(a) {
        cur.value = a; advice.value = suggest(a);
        if (a.host) {
          api.get('/devices/' + encodeURIComponent(a.host)).then(d => {
            cur.value = { ...a, _detail: `设备：${d.host.name}（${d.host.ip}）\n型号：${d.host.vendor} ${d.host.model}\n区域：${d.host.zone} 角色：${d.host.role}\n运行时长：${fmt.dur(d.host.uptimeSec)}\n在线：${d.host.status ? '是' : '否'}，健康度 ${d.host.health}` };
          }).catch(() => { });
        }
      }
      /* 简易处置建议（本地规则，接入 AI 助手后可获得更完整分析） */
      function suggest(a) {
        const t = ((a.title || '') + ' ' + (a.message || '')).toLowerCase();
        const host = a.host || '';
        if (/down|link|端口/.test(t)) return `1) 登录 ${host} 执行 display interface brief / show interface status，定位物理层与协议层状态；\n2) 检查该端口线缆、模块、对端设备是否断电；\n3) 若是误下线，进入配置模式 no shutdown；\n4) 全程可在「Web 终端」操作，操作会被录像与审计。`;
        if (/cpu/.test(t)) return `CPU 偏高时先确认是否为周期性问题：\n1) display cpu-usage 查看各进程占用；\n2) 结合 Zabbix 历史曲线判断是否持续升高；\n3) 若为单端口环路，用 spanning-tree / 端口 shutdown 隔离。`;
        if (/crc|error|discard/.test(t)) return `错包说明物理层或光模块存在问题：\n1) 检查端口错包计数是否持续增长；\n2) 更换线缆 / 光模块；\n3) 检查对端速率与双工是否强制不一致。`;
        if (/温度|temp|风扇|fan/.test(t)) return `1) 确认机房空调与进风温度；\n2) display environment 查看进风口/出风口温度；\n3) 清理防尘网，检查风扇模块状态。`;
        if (/带宽|traffic|出口/.test(t)) return `出口带宽告警：\n1) 查看 Top 会话定位流量来源（会话分析页）；\n2) 判断是否异常下载或环路；\n3) 必要时做限速或 ACL 策略。`;
        if (/会话|session/.test(t)) return `会话数接近上限：\n1) 定位 Top 会话；\n2) 检查是否存在主机病毒外联；\n3) 调整 nat 会话数上限或加装 ACL。`;
        return `可点击右侧悬浮的 AI 助手进行逐条追问，或在「AI 助手」中粘贴设备输出获得完整分析。`;
      }

      async function testNotify(channel) {
        notifyRes.value = '发送中…';
        try { const r = await api.post('/system/notify/test', { channel }); notifyRes.value = JSON.stringify(r, null, 2); toast('已发送测试通知', 'ok'); }
        catch (e) { toast(e.message, 'err'); }
      }
      async function createAlarm() {
        if (!newA.title.trim()) return toast('请填写告警标题', 'warn');
        creating.value = true;
        try {
          const r = await api.post('/alarms', {
            host: newA.host || '-', title: newA.title, message: newA.message, severity: newA.severity, source: 'manual'
          });
          created.value.unshift(`${fmt.time(Date.now())} [${sevText(newA.severity)}] ${newA.title} → 已推送`);
          if (created.value.length > 8) created.value.pop();
          newA.title = ''; newA.message = '';
          toast('告警已创建并触发推送', 'ok'); load();
        } catch (e) { toast(e.message, 'err'); } finally { creating.value = false; }
      }

      async function ask(a) {
        cur.value = a; advice.value = suggest(a);
        toast('已生成处置建议，可在 AI 助手中继续追问', 'ok');
      }

      let timer = null;
      function toggleAuto() { auto.value = !auto.value; if (auto.value) timer = setInterval(load, 20000); else clearInterval(timer); }
      onMounted(load);
      onBeforeUnmount(() => clearInterval(timer));
      watch(() => [w.page, w.size], () => load());

      return {
        rows, total, stats, f, w, hosts, auto, unack, cur, advice, notifyRes, creating, created, newA,
        ic, sevColor, sevText, stateText, stateClass, isClosed, load, reload, reset,
        ack, close, reopen, detail, ask, testNotify, createAlarm, toggleAuto, go, fmt
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.AlarmsPage = AlarmsPage;
  NC.route('/alarms', { title: '告警中心', comp: 'AlarmsPage' });
})();
