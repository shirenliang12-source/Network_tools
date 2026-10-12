/* =========================================================================
   系统管理：数据源 / 用户分权 / 凭据库 / AI / 通知 / 审计 / 运行状态
   ========================================================================= */
(function () {
  const { ref, reactive, computed, watch, onMounted, onBeforeUnmount } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const TABS = [
    { k: 'ds', n: '数据源', i: 'database' },
    { k: 'user', n: '用户与分权', i: 'user' },
    { k: 'cred', n: '凭据库', i: 'lock' },
    { k: 'ai', n: 'AI 助手', i: 'robot' },
    { k: 'notify', n: '通知推送', i: 'bell' },
    { k: 'term', n: '终端与测速', i: 'terminal' },
    { k: 'audit', n: '审计日志', i: 'clipboard' },
    { k: 'tls', n: '安全证书', i: 'shield' },
    { k: 'health', n: '运行状态', i: 'activity' }
  ];

  const SystemPage = {
    name: 'SystemPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
      </div>

      <!-- ===================== 数据源 ===================== -->
      <div v-show="tab==='ds'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('database',15)"></span><span>站点信息</span></div>
          <div class="form-grid">
            <label>站点名称<input class="inp" v-model="s.site.name"></label>
            <label>副标题<input class="inp" v-model="s.site.subtitle"></label>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('share',15)"></span><span>数据来源</span></div>
          <div class="fs12 muted mb8">未配置 Zabbix 时使用内置演示数据（13 台多厂商设备，含端口、流量、告警），可完整体验全部功能；配置后自动切换为 Zabbix 真实数据。</div>
          <div class="flex gap8 mb8">
            <label class="checkbox" style="display:flex;align-items:center;gap:6px">
              <input type="radio" value="demo" v-model="s.datasource.mode"> 演示数据（内置多厂商模拟器）</label>
            <label class="checkbox" style="display:flex;align-items:center;gap:6px">
              <input type="radio" value="zabbix" v-model="s.datasource.mode"> Zabbix API</label>
          </div>
          <div class="form-grid" v-if="s.datasource.mode==='zabbix'">
            <label style="grid-column:1/-1">API 地址
              <input class="inp mono" v-model="s.datasource.zabbix.url" placeholder="http://10.252.28.99/api_jsonrpc.php 或 http://10.252.28.99"></label>
            <label>用户名<input class="inp mono" v-model="s.datasource.zabbix.username" placeholder="Admin"></label>
            <label>密码<input class="inp mono" type="password" v-model="s.datasource.zabbix.password" :placeholder="s.datasource.zabbix.password ? '已配置，留空表示不修改' : ''" autocomplete="new-password"></label>
            <label>请求超时（毫秒）<input class="inp" type="number" v-model="s.datasource.zabbix.timeoutMs"></label>
            <label>忽略 HTTPS 证书验证
              <select class="inp" v-model="s.datasource.zabbix.tlsVerify"><option value="false">忽略</option><option value="true">校验</option></select></label>
            <div class="result-box" style="grid-column:1/-1">
              <div class="row gap8" style="align-items:center">
                <b class="fs13">Zabbix 主机组同步范围</b>
                <span class="tag">{{ selectedGroupCount ? '仅同步已选 '+selectedGroupCount+' 个组' : '同步全部有权限的组' }}</span>
                <div class="grow"></div>
                <input v-if="dsGroups.length" class="inp sm" style="width:180px" v-model.trim="groupKeyword" placeholder="搜索主机组">
                <button class="btn sm" :disabled="loadingGroups" @click="loadGroups">{{ loadingGroups?'读取中...':'读取主机组' }}</button>
              </div>
              <div v-if="filteredDsGroups.length" class="grid" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr));max-height:220px;overflow:auto;margin-top:10px">
                <label v-for="g in filteredDsGroups" :key="g.id" class="checkbox" style="display:flex;align-items:center;gap:7px">
                  <input type="checkbox" :value="String(g.id)" v-model="s.datasource.zabbix.groupIds">
                  <span>{{ g.name }}</span><span class="mono fs11 muted">#{{ g.id }}</span>
                </label>
              </div>
              <div v-else class="fs12 muted" style="margin-top:10px">保存 Zabbix 地址和账号后点击“读取主机组”。未勾选任何组表示同步该账号有权读取的全部受监控主机。</div>
              <div v-if="selectedGroupCount" class="row gap8 mt8">
                <button class="btn xs" @click="s.datasource.zabbix.groupIds=[]">清空选择（同步全部）</button>
                <span class="fs11 muted">同一设备属于多个组时只同步一次，并在设备资产中保留全部组名。</span>
              </div>
            </div>
          </div>
          <div class="flex gap8">
            <button class="btn primary" :disabled="testing" @click="testDs">
              <span v-if="testing" class="typing"><span></span><span></span><span></span></span>
              <span v-else v-html="ic('zap',15)+'<span>测试连接</span>'"></span>
            </button>
            <button class="btn" @click="save">保存配置</button>
            <button v-if="s.datasource.mode==='zabbix'" class="btn" :disabled="syncing" @click="syncDs" v-html="syncing ? '<span>同步中...</span>' : ic('refresh',15)+'<span>立即同步</span>'"></button>
            <div class="grow"></div>
            <span class="fs12 muted" v-if="dsRes">{{ dsRes }}</span>
          </div>
          <div v-if="dsErr" class="row mt8" style="color:var(--danger)"><span v-html="ic('alert',14)"></span><span class="fs12">{{ dsErr }}</span></div>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>切换数据源后会自动清空本地缓存并重新拉取。Zabbix 侧请确保该用户有「读取」权限，且监控项中带有 cpu.utilization / mem.utilization / 端口类 Key。</span></div>
        </div>
      </div>

      <!-- ===================== 用户 ===================== -->
      <div v-show="tab==='user'" class="col gap16">
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">
          <div class="card tight"><div class="l fs12 muted fw5">管理员 admin</div>
            <div class="fs12 muted" style="line-height:1.7">全部权限，含系统配置、用户与凭据、配置下发、删除录像。</div></div>
          <div class="card tight"><div class="l fs12 muted fw5">运维 ops</div>
            <div class="fs12 muted" style="line-height:1.7">终端、配置下发、抓包、测速、告警处置、AI 助手。</div></div>
          <div class="card tight"><div class="l fs12 muted fw5">审计 audit</div>
            <div class="fs12 muted" style="line-height:1.7">只读设备与流量，可看会话录像与审计日志，不能修改配置。</div></div>
        </div>

        <div class="card">
          <div class="filter-bar">
            <div class="fs13 fw5">用户列表（{{ users.length }}）</div>
            <div class="grow"></div>
            <button class="btn primary" @click="editUser(null)" v-html="ic('plus',15)+'<span>新建用户</span>'"></button>
          </div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:130px">用户名</th><th style="width:130px">显示名</th><th style="width:80px">角色</th><th style="width:70px">状态</th><th style="width:170px">最近登录</th><th style="width:230px">权限</th><th style="width:230px">操作</th></tr></thead>
              <tbody>
                <tr v-for="u in users" :key="u.id">
                  <td class="fw5">{{ u.username }}<div class="fs11 muted" style="font-family:var(--mono)">{{ u.id }}</div></td>
                  <td>{{ u.displayName }}</td>
                  <td><span class="tag" :class="u.role==='admin'?'red':(u.role==='ops'?'blue':'green')">{{ u.roleName }}</span></td>
                  <td><span class="pill" :class="u.enabled?'up':'neutral'">{{ u.enabled?'启用':'禁用' }}</span></td>
                  <td class="fs12 muted">{{ fmt.time(u.lastLoginAt) }}</td>
                  <td class="fs11 muted ellipsis" :title="(u.perms||[]).join(', ')">{{ (u.perms||[]).length>6 ? (u.perms||[]).slice(0,6).join(', ')+' …' : (u.perms||[]).join(', ') }}</td>
                  <td>
                    <button class="btn sm" @click="editUser(u)">编辑</button>
                    <button class="btn sm" @click="resetPwd(u)">改密</button>
                    <button class="btn sm danger" :disabled="u.id===myId" @click="delUser(u)">删除</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ===================== 凭据库 ===================== -->
      <div v-show="tab==='cred'" class="col gap16">
        <div class="card">
          <div class="filter-bar">
            <div class="fs13 fw5">凭据</div>
            <span class="fs12 muted">用于 Web 终端、配置下发、设备表查询与设备侧抓包；主密钥保存在	data/.masterkey</span>
            <div class="grow"></div>
            <button class="btn primary" @click="editCred(null)" v-html="ic('plus',15)+'<span>新增凭据</span>'"></button>
          </div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:150px">名称</th><th style="width:80px">类型</th><th style="width:130px">账号</th><th style="width:140px">地址</th><th style="width:80px">密码</th><th style="width:70px">Enable</th><th style="width:190px">操作</th></tr></thead>
              <tbody>
                <tr v-for="c in creds" :key="c.id">
                  <td class="fw5">{{ c.name }}<div class="fs11 muted">{{ c.note || '' }}</div></td>
                  <td><span class="tag" :class="c.kind==='ssh'?'green':(c.kind==='telnet'?'amber':'blue')">{{ c.kind }}</span></td>
                  <td class="mono">{{ c.username || '-' }}</td>
                  <td class="mono">{{ c.host }} <span class="muted">:{{ c.port }}</span></td>
                  <td>{{ c.hasSecret ? '******' : '未设置' }}</td>
                  <td>{{ c.hasEnable ? '有' : '-' }}</td>
                  <td>
                    <button class="btn sm" :disabled="testingCredId===c.id" @click="testCred(c)">{{ testingCredId===c.id?'测试中':'测试' }}</button>
                    <button class="btn sm" @click="editCred(c)">编辑</button>
                    <button class="btn sm danger" @click="delCred(c)">删除</button>
                  </td>
                </tr>
                <tr v-if="!creds.length"><td colspan="7" class="tbl-empty">暂无凭据，新增后 Web 终端将直连真实设备</td></tr>
              </tbody>
            </table>
          </div>
          <div v-if="credTest" class="mt8"><pre class="code-block" style="max-height:130px">{{ credTest }}</pre></div>
        </div>
      </div>

      <!-- ===================== AI ===================== -->
      <div v-show="tab==='ai'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('robot',15)"></span><span>AI 助手配置</span></div>
          <div class="fs12 muted mb8">未配置模型时使用内置规则引擎（覆盖端口不通、CPU 高、错包、环路、告警处置、测速、VLAN 配置、Zabbix 对接等高频问答）。配置 OpenAI 兼容接口（DeepSeek / 通义 / 本地 Ollama）即可获得自由问答。</div>
          <div class="form-grid">
            <label>启用 AI
              <select class="inp" v-model="s.ai.enabled"><option value="true">启用</option><option value="false">关闭</option></select></label>
            <label>模型来源
              <select class="inp" v-model="s.ai.provider">
                <option value="none">规则引擎（无需接口）</option>
                <option value="openai">OpenAI 兼容接口（DeepSeek / 通义 / Moonshot）</option>
                <option value="ollama">本地 Ollama</option>
              </select></label>
            <label style="grid-column:1/-1">接口地址
              <input class="inp mono" v-model="s.ai.baseUrl" placeholder="https://api.deepseek.com/v1  或  http://127.0.0.1:11434/v1"></label>
            <label>API Key
              <input class="inp mono" type="password" v-model="s.ai.apiKey" :placeholder="s.ai.apiKey ? '已配置，留空表示不修改' : 'sk-...'" autocomplete="new-password"></label>
            <label>模型名称<input class="inp mono" v-model="s.ai.model" placeholder="deepseek-chat / llama3.1:8b"></label>
            <label>温度<input class="inp" type="number" min="0" max="1" step="0.05" v-model="s.ai.temperature"></label>
            <label>最大 Token<input class="inp" type="number" min="256" max="8192" v-model="s.ai.maxTokens"></label>
          </div>
          <label class="mt8">系统提示词
            <textarea class="inp" rows="3" v-model="s.ai.systemPrompt"></textarea></label>
          <div class="flex gap8 mt8">
            <button class="btn primary" @click="save">保存配置</button>
            <button class="btn" @click="askAi">问一句「接入交换机端口 down 怎么查」</button>
          </div>
        </div>
      </div>

      <!-- ===================== 通知 ===================== -->
      <div v-show="tab==='notify'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('bell',15)"></span><span>告警通知推送</span></div>
          <div class="form-grid">
            <label>最小推送级别
              <select class="inp" v-model="s.notify.minSeverity">
                <option value="information">信息</option><option value="warning">警告</option><option value="average">一般</option><option value="high">严重</option><option value="disaster">灾难</option>
              </select></label>
            <label>同标题冷却（秒）<input class="inp" type="number" min="0" max="3600" v-model="s.notify.cooldownSec"></label>
          </div>

          <div class="col gap12 mt12">
            <div class="card tight">
              <div class="row-between"><span class="fs13 fw5">企业微信机器人</span>
                <label class="checkbox"><input type="checkbox" v-model="s.notify.wecom.enabled"> 启用</label></div>
              <input class="inp mono mt8" v-model="s.notify.wecom.url" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=">
            </div>
            <div class="card tight">
              <div class="row-between"><span class="fs13 fw5">钉钉机器人</span>
                <label class="checkbox"><input type="checkbox" v-model="s.notify.dingtalk.enabled"> 启用</label></div>
              <input class="inp mono mt8" v-model="s.notify.dingtalk.url" placeholder="https://oapi.dingtalk.com/robot/send?access_token=">
              <input class="inp mono mt8" v-model="s.notify.dingtalk.secret" placeholder="加签密钥（可选）">
            </div>
            <div class="card tight">
              <div class="row-between"><span class="fs13 fw5">通用 Webhook</span>
                <label class="checkbox"><input type="checkbox" v-model="s.notify.webhook.enabled"> 启用</label></div>
              <input class="inp mono mt8" v-model="s.notify.webhook.url" placeholder="POST JSON 的任意地址">
            </div>
            <div class="card tight">
              <div class="row-between"><span class="fs13 fw5">邮件 SMTP</span>
                <label class="checkbox"><input type="checkbox" v-model="s.notify.smtp.enabled"> 启用</label></div>
              <div class="form-grid mt8">
                <label>服务器<input class="inp mono" v-model="s.notify.smtp.host" placeholder="smtp.exmail.qq.com"></label>
                <label>端口<input class="inp mono" v-model="s.notify.smtp.port"></label>
                <label>账号<input class="inp mono" v-model="s.notify.smtp.user"></label>
                <label>密码<input class="inp mono" type="password" v-model="s.notify.smtp.pass" :placeholder="s.notify.smtp.pass ? '已配置，留空表示不修改' : ''" autocomplete="new-password"></label>
                <label>发件人<input class="inp mono" v-model="s.notify.smtp.from"></label>
                <label>收件人<input class="inp mono" v-model="s.notify.smtp.to" placeholder="多个用逗号分隔"></label>
              </div>
              <label class="checkbox mt8"><input type="checkbox" v-model="s.notify.smtp.secure"> SSL/TLS（465 端口通常勾选）</label>
            </div>
          </div>

          <div class="flex gap8 mt12">
            <button class="btn primary" @click="save">保存配置</button>
            <button class="btn" @click="testNotify('')">全通道测试</button>
            <button class="btn" @click="testNotify('wecom')">测试企业微信</button>
            <button class="btn" @click="testNotify('dingtalk')">测试钉钉</button>
            <button class="btn" @click="testNotify('smtp')">测试邮件</button>
          </div>
          <div v-if="ntRes" class="mt8"><pre class="code-block" style="max-height:150px">{{ ntRes }}</pre></div>
        </div>
      </div>

      <!-- ===================== 终端/测速 ===================== -->
      <div v-show="tab==='term'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('terminal',15)"></span><span>终端与危险命令防护</span></div>
          <div class="form-grid">
            <label>空闲断开（秒）<input class="inp" type="number" min="60" max="7200" v-model="s.terminal.idleTimeoutSec"></label>
            <label>录制会话
              <select class="inp" v-model="s.terminal.recordSessions"><option value="true">开启（可回放/审计）</option><option value="false">关闭</option></select></label>
          </div>
          <label class="mt8">危险命令规则（正则，命中后终端与下发均需二次确认）
            <textarea class="inp mono" rows="5" v-model="dangerText"></textarea></label>
          <div class="fs12 muted mt8">提示：<span class="mono">undo </span>、<span class="mono">shutdown</span>、<span class="mono">reload</span> 默认在列，误操作会直接中断业务，保留拦截即可。</div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('camera',15)"></span><span>抓包引擎</span></div>
          <div class="form-grid">
            <label>默认模式
              <select class="inp" v-model="s.capture.engine"><option value="auto">自动</option><option value="tshark">tshark</option><option value="device">设备侧</option></select></label>
            <label>tshark / dumpcap 路径
              <input class="inp mono" v-model="s.capture.tsharkPath" placeholder="留空则自动查找"></label>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('activity',15)"></span><span>测速</span></div>
          <div class="form-grid">
            <label>iperf3 路径<input class="inp mono" v-model="s.speed.iperfPath" placeholder="留空则自动查找"></label>
            <label>吞吐端口<input class="inp mono" v-model="s.speed.serverPort"></label>
            <label>HTTP 测速端口<input class="inp mono" v-model="s.speed.httpPort"></label>
            <label>最大并发流<input class="inp" type="number" min="1" max="32" v-model="s.speed.maxParallel"></label>
          </div>
          <div class="flex gap8 mt8"><button class="btn primary" @click="save">保存配置</button></div>
        </div>
      </div>

      <!-- ===================== 审计 ===================== -->
      <div v-show="tab==='audit'" class="col gap16">
        <div class="card">
          <div class="filter-bar">
            <div class="search-box" style="min-width:220px">
              <span v-html="ic('search',15)"></span>
              <input class="inp" v-model.trim="af.keyword" placeholder="动作关键字过滤，如 terminal.cmd / config.deploy" @keydown.enter="loadAudit">
            </div>
            <select class="inp" v-model="af.user"><option value="">全部用户</option><option v-for="u in userNames" :key="u" :value="u">{{ u }}</option></select>
            <select class="inp" v-model="af.action"><option value="">全部动作</option><option v-for="a in actionNames" :key="a" :value="a">{{ a }}</option></select>
            <input class="inp" type="date" v-model="af.from" style="max-width:150px">
            <input class="inp" type="date" v-model="af.to" style="max-width:150px">
            <button class="btn primary" @click="loadAudit" v-html="ic('search',15)"></button>
            <div class="grow"></div>
            <button class="btn" @click="exportAudit" v-html="ic('download',15)+'<span>导出</span>'"></button>
          </div>
          <div class="table-wrap" style="max-height:620px;overflow:auto">
            <table class="ntable">
              <thead><tr><th style="width:150px">时间</th><th style="width:80px">用户</th><th style="width:150px">动作</th><th style="width:160px">目标</th><th style="width:110px">结果</th><th>详情</th></tr></thead>
              <tbody>
                <tr v-for="(r,i) in auditRows" :key="i">
                  <td class="fs11 muted">{{ fmt.time(r.ts) }}</td>
                  <td>{{ r.user }}</td>
                  <td class="mono fs11">{{ r.action }}</td>
                  <td class="mono fs11 ellipsis" :title="r.target">{{ r.target || '-' }}</td>
                  <td><span class="pill" :class="r.result==='fail'||r.result==='deny'?'down':(r.result==='ok'?'up':'neutral')">{{ r.result || '-' }}</span></td>
                  <td class="fs11 muted ellipsis" :title="r.detail">{{ r.detail || '-' }}</td>
                </tr>
                <tr v-if="!auditRows.length"><td colspan="6" class="tbl-empty">暂无审计记录</td></tr>
              </tbody>
            </table>
          </div>
          <div class="hint-line"><span v-html="ic('shield',13)"></span><span>审计日志为追加写入（NDJSON），包含登录、终端命令、配置下发、凭据使用、告警处置、会话回放等，不可篡改。</span></div>
        </div>
      </div>

      <!-- ===================== 运行状态 ===================== -->
      <div v-show="tab==='health'" class="col gap16">
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
          <div class="result-box"><div class="l fs12 muted">数据源</div>
            <div class="big" :style="{fontSize:18, color: health.datasource && health.datasource.mode==='zabbix' ? 'var(--success)':'var(--warn)'}">{{ (health.datasource||{}).mode }}</div>
            <div class="fs11 muted">最近联通：{{ fmt.time((health.datasource||{}).lastOkAt) }}</div></div>
          <div class="result-box"><div class="l fs12 muted">运行时长</div><div class="big" style="font-size:20px">{{ fmt.dur(health.uptimeSec) }}</div><div class="fs11 muted">PID {{ health.pid }}</div></div>
          <div class="result-box"><div class="l fs12 muted">内存占用</div><div class="big lat">{{ health.rssMB }} MB</div><div class="fs11 muted">{{ health.platform }}</div></div>
          <div class="result-box"><div class="l fs12 muted">抓包引擎</div><div class="big" :style="{fontSize:17, color: health.capture && health.capture.ready ? 'var(--success)':'var(--warn)'}">{{ health.capture && health.capture.ready ? '可用' : ((health.runtime||{}).elevated===false ? '需管理员权限' : '未就绪') }}</div><div class="fs11 muted ellipsis">{{ health.capture ? health.capture.engine || '—' : '—' }}</div></div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('server',15)"></span><span>网络工具运行时</span>
            <span class="pill" :class="(health.runtime||{}).busy ? 'blue':'up'">{{ (health.runtime||{}).busy ? '后台部署中' : '自动管理' }}</span>
            <div class="grow"></div><button class="btn sm" :disabled="(health.runtime||{}).busy" @click="installRuntime">检测并补装</button></div>
          <div class="fs12 muted mb8">Nmap、TShark、iperf3 由平台后台静默部署；MTR 与 Net-SNMP 已内置。无需单独下载安装。</div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr><th style="width:170px">组件</th><th style="width:95px">状态</th><th style="width:110px">版本</th><th>运行位置 / 回退能力</th></tr></thead>
              <tbody>
                <tr v-for="t in ((health.runtime||{}).tools||[])" :key="t.id">
                  <td><b>{{ t.name }}</b><div class="fs11 muted">{{ t.kind==='builtin'?'平台内置':t.kind==='system'?'系统组件':t.kind==='external-license'?'外部驱动':'平台托管' }}</div></td>
                  <td><span class="tag" :class="t.ready?'green':''">{{ t.ready ? '已就绪' : (t.fallback ? '已回退' : '待部署') }}</span></td>
                  <td class="mono fs11">{{ t.version || '—' }}</td>
                  <td class="fs11"><div class="ellipsis" :title="t.path">{{ t.path || '—' }}</div><div v-if="!t.ready && t.fallback" class="muted">回退：{{ t.fallback }}</div></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="hint-line mt8"><span v-html="ic('info',13)"></span><span>Npcap 免费版不支持静默再分发；平台会使用已安装的 Npcap，未安装时自动切换 Windows PktMon，不影响集成抓包。第三方组件从官网或 Windows Package Manager 获取并校验。</span></div>
          <div v-if="(health.runtime||{}).message" class="fs11 muted mt8 mono">{{ health.runtime.message }}</div>
        </div>

        <div class="grid" style="grid-template-columns:1fr 1fr;gap:16px">
          <div class="card tight">
            <div class="card-head" style="margin-bottom:6px"><span class="fs13 fw5">数据概况</span></div>
            <div class="col gap4 fs12">
              <div v-for="v in countRows" :key="v.k"><span class="muted">{{ v.k }}：</span><span class="fw5">{{ v.v }}</span></div>
            </div>
          </div>
          <div class="card tight">
            <div class="card-head" style="margin-bottom:6px"><span class="fs13 fw5">存储占用</span></div>
            <div class="col gap4 fs12">
              <div v-for="v in storageRows" :key="v.k"><span class="muted">{{ v.k }}：</span><span class="fw5">{{ v.v }}</span></div>
            </div>
            <div class="fs11 muted mt8">版本 {{ health.node }}</div>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><span v-html="ic('list',15)"></span><span>最近 30 条操作</span></div>
          <div class="mini-log">{{ recentAudit }}</div>
        </div>
      </div>

      <!-- ===================== 安全证书 ===================== -->
      <div v-show="tab==='tls'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('shield',15)"></span><span>传输层安全（HTTPS）</span></div>
          <div class="fs12 muted mb8">将 CA 签发的证书上传到本程序后，重启即自动在 8787 端口启用 HTTPS，浏览器与终端/实时推送（wss）均走加密通道。</div>
          <div class="flex gap8 mb8">
            <span class="pill" :class="certStatus.running ? 'up':'neutral'">{{ certStatus.running ? '当前连接 HTTPS 🔒' : '当前连接 HTTP' }}</span>
            <span class="pill" :class="certStatus.onDisk ? 'up':'neutral'">{{ certStatus.onDisk ? '已存有证书（重启后生效）' : '未配置证书' }}</span>
            <span v-if="certStatus.chainOnDisk" class="pill blue">含中间证书</span>
          </div>
          <div v-if="certStatus.cert && !certStatus.cert.error" class="col gap4 fs12 mb8">
            <div><span class="muted">主题：</span><span class="mono">{{ certStatus.cert.subject }}</span></div>
            <div><span class="muted">颁发者：</span><span class="mono">{{ certStatus.cert.issuer }}</span></div>
            <div><span class="muted">SAN：</span><span class="mono ellipsis" :title="(certStatus.cert.san||[]).join(', ')">{{ (certStatus.cert.san||[]).join(', ') || '（无 / 需人工确认）' }}</span></div>
            <div><span class="muted">有效期至：</span><span class="mono">{{ fmt.time(certStatus.cert.validTo) }}（剩余 {{ certStatus.cert.daysLeft }} 天）</span></div>
          </div>
          <div v-if="certStatus.cert && certStatus.cert.error" class="fs12" style="color:var(--danger)">{{ certStatus.cert.error }}</div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('upload',15)"></span><span>上传证书</span></div>
          <div class="fs12 muted mb8">支持 PEM 格式（.pem/.crt/.key）。证书与私钥需配对，否则会被拒绝。</div>
          <div class="form-grid">
            <label class="file-field">证书 (cert.pem)
              <input class="inp" type="file" accept=".pem,.crt,.cer,.der" @change="onCertPick('cert',$event)">
              <span class="fs11 muted">{{ files.cert || '未选择' }}</span>
            </label>
            <label class="file-field">私钥 (key.pem)
              <input class="inp" type="file" accept=".pem,.key" @change="onCertPick('key',$event)">
              <span class="fs11 muted">{{ files.key || '未选择' }}</span>
            </label>
            <label class="file-field">中间证书 (chain.pem，可选)
              <input class="inp" type="file" accept=".pem,.crt" @change="onCertPick('chain',$event)">
              <span class="fs11 muted">{{ files.chain || '未选择' }}</span>
            </label>
          </div>
          <div class="flex gap8 mt8">
            <button class="btn primary" :disabled="uploading || !files.cert || !files.key" @click="uploadCert">
              <span v-if="uploading" class="typing"><span></span><span></span><span></span></span>
              <span v-else v-html="ic('upload',15)+'<span>上传并保存</span>'"></span>
            </button>
            <button class="btn danger" :disabled="!certStatus.onDisk" @click="removeCert">移除证书</button>
          </div>
          <div v-if="certMsg" class="row mt8"><span v-html="ic(certMsgOk?'check':'alert',14)"></span><span class="fs12" :style="{color: certMsgOk?'var(--success)':'var(--danger)'}">{{ certMsg }}</span></div>
          <div v-if="certMsgOk" class="hint-line"><span v-html="ic('info',13)"></span><span>证书已落盘。请关闭并重新运行程序（双击 exe），启动后将自动以 HTTPS 方式监听 8787；如 SAN 未覆盖你的访问地址，浏览器会提示证书名不匹配。</span></div>
        </div>
      </div>

      <!-- 用户编辑 -->
      <NcModal :title="uEdit ? '编辑用户' : '新建用户'" v-if="uEdit" @close="uEdit=null" @ok="saveUser" ok-text="保存">
        <div class="form-grid">
          <label>用户名<input class="inp" :disabled="!!uEdit" v-model="uForm.username" placeholder="登录名"></label>
          <label>显示名<input class="inp" v-model="uForm.displayName" placeholder="中文名/工号"></label>
          <label>角色<select class="inp" v-model="uForm.role"><option v-for="r in roles" :key="r.key" :value="r.key">{{ r.name }}({{ r.key }})</option></select></label>
          <label>密码<input class="inp" type="password" v-model="uForm.password" :placeholder="uEdit ? '留空表示不修改' : '至少 6 位'" autocomplete="new-password"></label>
          <label class="checkbox" style="align-items:center;gap:6px"><input type="checkbox" v-model="uForm.enabled"> 启用该账号</label>
          <label class="checkbox" style="align-items:center;gap:6px"><input type="checkbox" v-model="uForm.resetPwd"> 强制下次登录改密</label>
        </div>
      </NcModal>

      <!-- 凭据编辑 -->
      <NcModal :title="cEdit ? '编辑凭据' : '新增凭据'" v-if="cEdit" wide @close="cEdit=null" @ok="saveCred" ok-text="保存">
        <div class="form-grid">
          <label>名称<input class="inp" v-model="cForm.name" placeholder="如：核心交换机 SSH"></label>
          <label>类型<select class="inp" v-model="cForm.kind">
            <option value="ssh">SSH</option><option value="telnet">Telnet</option><option value="snmp">SNMP</option><option value="zabbix">Zabbix</option></select></label>
          <label>厂商<select class="inp" v-model="cForm.vendor">
            <option>通用</option><option>Cisco</option><option>华为</option><option>H3C</option><option>Fortinet</option><option>Palo Alto</option></select></label>
          <label>地址<input class="inp mono" v-model="cForm.host" placeholder="10.252.28.1"></label>
          <label>端口<input class="inp mono" v-model="cForm.port" placeholder="22"></label>
          <label>用户名<input class="inp mono" v-model="cForm.username" placeholder="admin"></label>
          <label>密码<input class="inp mono" type="password" v-model="cForm.secret" placeholder="留空表示不修改" autocomplete="new-password"></label>
          <label>Enable 密码<input class="inp mono" type="password" v-model="cForm.enable" placeholder="部分厂商需要" autocomplete="new-password"></label>
          <label style="grid-column:1/-1">备注<input class="inp" v-model="cForm.note" placeholder="用途、变更联系方式等"></label>
        </div>
      </NcModal>
    </div>`,
    setup(props) {
      const initialTab = TABS.some(x => x.k === props.query?.tab) ? props.query.tab : 'ds';
      const tab = ref(initialTab);
      watch(() => props.query?.tab, v => { if (TABS.some(x => x.k === v)) tab.value = v; });
      // 后端 settings 可能缺子键（旧版本存档），此处补齐默认值，避免模板读 undefined 炸渲染
      const DEF = {
        notify: {
          webhook: { enabled: false, url: '', secret: '' },
          wecom: { enabled: false, url: '' },
          dingtalk: { enabled: false, url: '', secret: '' },
          smtp: { enabled: false, host: '', port: 465, secure: true, user: '', pass: '', from: '', to: '' },
          minSeverity: 'high', cooldownSec: 300
        },
        ai: {
          enabled: true, provider: 'none', baseUrl: '', apiKey: '', model: '',
          temperature: 0.2, maxTokens: 1024,
          systemPrompt: '你是一名资深企业网络运维工程师，精通 Cisco IOS/NX-OS、华为 VRP、H3C Comware、Palo Alto PAN-OS、Fortinet FortiOS 的排障与配置。'
        },
        terminal: { dangerPatterns: [] },
        capture: {}, speed: {}
      };
      const mergeDeep = (dst, src) => {
        for (const k of Object.keys(src || {})) {
          const v = src[k];
          const cur = dst[k];
          if (v && typeof v === 'object' && !Array.isArray(v) && cur && typeof cur === 'object') mergeDeep(cur, v);
          else if (v !== undefined) dst[k] = v;
        }
        return dst;
      };
      const clone = (o) => JSON.parse(JSON.stringify(o));
      const s = reactive(Object.assign({ site: {}, datasource: {} },
        { notify: clone(DEF.notify), ai: clone(DEF.ai), terminal: clone(DEF.terminal), capture: clone(DEF.capture), speed: clone(DEF.speed) }));
      const users = ref([]), creds = ref([]), roles = ref([]), myId = ref('');
      const auditRows = ref([]), health = reactive({});
      const testing = ref(false), syncing = ref(false), loadingGroups = ref(false), dsRes = ref(''), dsErr = ref(''), testingCredId = ref(''), credTest = ref(''), ntRes = ref('');
      const dsGroups = ref([]), groupKeyword = ref('');
      const uEdit = ref(null), uForm = reactive({ username: '', displayName: '', role: 'ops', password: '', enabled: true, resetPwd: false });
      const cEdit = ref(null), cForm = reactive({ name: '', kind: 'ssh', vendor: '通用', host: '', port: 22, username: '', secret: '', enable: '', note: '' });
      const af = reactive({ keyword: '', user: '', action: '', from: '', to: '' });
      const dangerText = ref('');

      /* 安全证书 */
      const certStatus = reactive({ running: false, onDisk: false, chainOnDisk: false, cert: null });
      const files = reactive({ cert: '', key: '', chain: '' });
      const fileBuf = reactive({ cert: null, key: null, chain: null });
      const uploading = ref(false);
      const certMsg = ref('');
      const certMsgOk = ref(false);

      const TABS_ = TABS;
      const ic = (n, s) => icon(n, s);

      const userNames = computed(() => [...new Set(auditRows.value.map(r => r.user).filter(Boolean))]);
      const actionNames = computed(() => [...new Set(auditRows.value.map(r => r.action).filter(Boolean))]);
      const selectedGroupCount = computed(() => Array.isArray(s.datasource?.zabbix?.groupIds) ? s.datasource.zabbix.groupIds.length : 0);
      const filteredDsGroups = computed(() => {
        const k = groupKeyword.value.toLowerCase();
        return dsGroups.value.filter(g => !k || `${g.name} ${g.id}`.toLowerCase().includes(k));
      });
      const countRows = computed(() => [
        ['用户', (health.counts || {}).users], ['凭据', (health.counts || {}).credentials],
        ['命令模板', (health.counts || {}).templates], ['告警', (health.counts || {}).alarms],
        ['会话录像', (health.counts || {}).recordings]
      ].map(([k, v]) => ({ k, v: v ?? '-' })));
      const storageRows = computed(() => Object.entries(health.storageBytes || {}).map(([k, v]) => ({ k, v: fmt.bytes(v) })));
      const recentAudit = computed(() => auditRows.value.slice(0, 30).map(r =>
        `[${fmt.time(r.ts)}] ${r.user} ${r.action} ${r.target || ''} ${r.result || ''} ${(r.detail || '').slice(0, 60)}`).join('\n') || '暂无记录');

      /* ------------------------ 通用 ------------------------ */
      async function load() {
        try {
          const [r, u, c] = await Promise.all([
            api.get('/system/settings'), api.get('/system/users'), api.get('/system/credentials')
          ]);
          loadSettings(r.settings);
          users.value = u.rows || []; roles.value = u.roles || [];
          creds.value = c.rows || [];
          myId.value = (NC.state.user || {}).id || '';
          const me = await api.get('/auth/me').catch(() => ({ user: null }));
          myId.value = (me.user || {}).id || myId.value;
          if (s.datasource.mode === 'zabbix') loadGroups().catch(() => {});
        } catch (e) { toast('加载系统配置失败：' + e.message, 'err'); }
      }
      function loadSettings(st) {
        st = st || {};
        Object.assign(s.site, st.site || {});
        Object.assign(s.datasource, st.datasource || {});
        s.datasource.zabbix = s.datasource.zabbix || {};
        if (!Array.isArray(s.datasource.zabbix.groupIds)) s.datasource.zabbix.groupIds = [];
        mergeDeep(s.notify, st.notify); mergeDeep(s.ai, st.ai);
        mergeDeep(s.terminal, st.terminal);
        Object.assign(s.capture, st.capture || {});
        Object.assign(s.speed, st.speed || {});
        dangerText.value = (Array.isArray(s.terminal.dangerPatterns) ? s.terminal.dangerPatterns : (st.terminal || {}).dangerPatterns || []).join('\n');
      }
      async function persistSettings(quiet = false) {
        try {
          s.terminal.dangerPatterns = dangerText.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
          const b = {
            site: s.site, datasource: s.datasource, notify: s.notify, ai: s.ai,
            terminal: s.terminal, capture: s.capture, speed: s.speed
          };
          const r = await api.put('/system/settings', b);
          loadSettings(r.settings);
          if (!quiet) toast('系统配置已保存', 'ok');
          return true;
        } catch (e) { toast(e.message, 'err'); return false; }
      }
      const save = () => persistSettings(false);

      /* ------------------------ 数据源 ------------------------ */
      async function loadGroups() {
        loadingGroups.value = true; dsErr.value = '';
        try {
          const r = await api.get('/system/datasource/groups');
          dsGroups.value = r.rows || [];
          if (!Array.isArray(s.datasource.zabbix.groupIds)) s.datasource.zabbix.groupIds = r.selected || [];
          if (r.mode !== 'zabbix') dsErr.value = '请先保存并启用 Zabbix 数据源';
        } catch (e) { dsErr.value = e.message; }
        finally { loadingGroups.value = false; }
      }
      async function testDs() {
        testing.value = true; dsRes.value = ''; dsErr.value = '';
        try {
          if (!(await persistSettings(true))) return;
          const r = await api.get('/system/datasource/test');
          dsRes.value = `模式 ${r.mode} · 版本 ${r.version || '-'} · 主机组 ${r.groupCount || 0} 个 · 当前范围设备 ${r.hostCount} 台`;
          if (r.mode === 'zabbix') await loadGroups();
        } catch (e) { dsErr.value = e.message; } finally { testing.value = false; }
      }
      async function syncDs() {
        syncing.value = true; dsRes.value = ''; dsErr.value = '';
        try {
          if (!(await persistSettings(true))) return;
          const r = await api.post('/system/datasource/sync', {});
          dsRes.value = `同步完成 · ${r.hostCount} 台设备 · ${r.groups.join('、')} · ${fmt.time(r.syncedAt)}`;
          toast('Zabbix 数据同步完成', 'ok');
        } catch (e) { dsErr.value = e.message; }
        finally { syncing.value = false; }
      }

      /* ------------------------ 用户 ------------------------ */
      function editUser(u) {
        uEdit.value = u ? true : false;
        Object.assign(uForm, u ? {
          id: u.id, username: u.username, displayName: u.displayName, role: u.role,
          password: '', enabled: u.enabled, resetPwd: false
        } : { id: '', username: '', displayName: '', role: 'ops', password: '', enabled: true, resetPwd: false });
      }
      async function saveUser() {
        try {
          if (uForm.id) await api.put('/system/users/' + uForm.id, {
            displayName: uForm.displayName, role: uForm.role, enabled: uForm.enabled,
            password: uForm.password || undefined
          });
          else await api.post('/system/users', {
            username: uForm.username, displayName: uForm.displayName, role: uForm.role,
            password: uForm.password, enabled: uForm.enabled
          });
          toast('用户已保存', 'ok'); uEdit.value = null; load();
        } catch (e) { toast(e.message, 'err'); }
      }
      async function resetPwd(u) {
        const p = prompt('为 ' + u.username + ' 设置新密码（至少 6 位）：', '');
        if (!p) return;
        if (p.length < 6) return toast('密码至少 6 位', 'warn');
        try { await api.put('/system/users/' + u.id, { password: p }); toast('密码已更新，原 token 立即失效', 'ok'); }
        catch (e) { toast(e.message, 'err'); }
      }
      async function delUser(u) {
        if (!confirm('确定删除用户 ' + u.username + '？')) return;
        try { await api.del('/system/users/' + u.id); toast('已删除', 'ok'); load(); } catch (e) { toast(e.message, 'err'); }
      }

      /* ------------------------ 凭据 ------------------------ */
      function editCred(c) {
        cEdit.value = c ? true : false;
        Object.assign(cForm, c ? {
          id: c.id, name: c.name, kind: c.kind, vendor: c.vendor, host: c.host,
          port: c.port, username: c.username, secret: '', enable: '', note: c.note || ''
        } : { id: '', name: '', kind: 'ssh', vendor: '通用', host: '', port: 22, username: '', secret: '', enable: '', note: '' });
      }
      async function saveCred() {
        try {
          const body = {
            name: cForm.name, kind: cForm.kind, vendor: cForm.vendor, host: cForm.host,
            port: Number(cForm.port) || 22, username: cForm.username, secret: cForm.secret, enable: cForm.enable, note: cForm.note
          };
          if (cForm.id) await api.put('/system/credentials/' + cForm.id, body);
          else await api.post('/system/credentials', body);
          toast('凭据已保存（AES-256-GCM 加密存储）', 'ok'); cEdit.value = null; load();
        } catch (e) { toast(e.message, 'err'); }
      }
      async function testCred(c) {
        testingCredId.value = c.id; credTest.value = '正在测试 ' + c.name + ' …';
        try {
          const r = await api.post('/system/credentials/' + c.id + '/test');
          credTest.value = JSON.stringify(r, null, 2);
          toast(r.ok ? '凭据可用（' + (r.ms || 0) + 'ms）' : '连接失败：' + (r.error || ''), r.ok ? 'ok' : 'err');
        } catch (e) { credTest.value = e.message; toast(e.message, 'err'); } finally { testingCredId.value = ''; }
      }
      async function delCred(c) {
        if (!confirm('确定删除凭据「' + c.name + '」？')) return;
        try { await api.del('/system/credentials/' + c.id); toast('已删除', 'ok'); load(); } catch (e) { toast(e.message, 'err'); }
      }

      /* ------------------------ 通知 ------------------------ */
      async function testNotify(channel) {
        ntRes.value = '发送中…';
        try { const r = await api.post('/system/notify/test', { channel }); ntRes.value = JSON.stringify(r, null, 2); toast('已发送测试通知', 'ok'); }
        catch (e) { toast(e.message, 'err'); }
      }

      /* ------------------------ AI ------------------------ */
      async function askAi() {
        try {
          const r = await api.post('/ai/chat', { message: '接入交换机端口 down 了怎么快速定位原因？', scope: {} });
          const a = r.answer || r.reply || '';
          if (a) { toast('AI 已回答，详见「AI 助手」面板', 'ok'); setTimeout(() => document.querySelector('.fab')?.click(), 400); }
          else toast('未获取到回答', 'warn');
        } catch (e) { toast(e.message, 'err'); }
      }

      /* ------------------------ 审计 ------------------------ */
      async function loadAudit() {
        try {
          const q = new URLSearchParams();
          for (const k of ['user', 'action', 'from', 'to']) if (af[k]) q.set(k, af[k]);
          if (af.keyword) { q.set('action', af.keyword); }
          q.set('limit', '500');
          const r = await api.get('/system/audit?' + q.toString());
          auditRows.value = r.rows || [];
        } catch (e) { toast(e.message, 'err'); }
      }
      function exportAudit() {
        const head = ['时间', '用户', '动作', '目标', '结果', '详情'];
        const csv = '\ufeff' + [head, ...auditRows.value.map(r => [fmt.time(r.ts), r.user, r.action, r.target || '', r.result || '', r.detail || ''])]
          .map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\r\n');
        const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
        const a = document.createElement('a'); a.href = url; a.download = `audit-${new Date().toISOString().slice(0, 10)}.csv`; a.click(); URL.revokeObjectURL(url);
      }

      /* ------------------------ 安全证书 ------------------------ */
      async function loadCert() {
        try {
          const r = await api.get('/system/cert');
          certStatus.running = r.running; certStatus.onDisk = r.onDisk;
          certStatus.chainOnDisk = r.chainOnDisk; certStatus.cert = r.cert;
        } catch (e) { }
      }
      function onCertPick(kind, e) {
        const f = e.target.files && e.target.files[0];
        e.target.value = '';
        if (!f) return;
        files[kind] = f.name; fileBuf[kind] = f;
      }
      async function uploadCert() {
        if (!fileBuf.cert || !fileBuf.key) return toast('请先选择证书与私钥', 'warn');
        uploading.value = true; certMsg.value = ''; certMsgOk.value = false;
        try {
          const fd = new FormData();
          fd.append('cert', fileBuf.cert);
          fd.append('key', fileBuf.key);
          if (fileBuf.chain) fd.append('chain', fileBuf.chain);
          const r = await api.raw('/system/cert', { method: 'POST', body: fd });
          const j = await r.json();
          certMsgOk.value = j.ok;
          certMsg.value = j.message || (j.ok ? '证书已保存' : j.error);
          if (j.ok) { files.cert = files.key = files.chain = ''; fileBuf.cert = fileBuf.key = fileBuf.chain = null; await loadCert(); }
          else toast(j.error || '证书校验失败', 'err');
        } catch (e) { certMsgOk.value = false; certMsg.value = '上传失败：' + e.message; toast(e.message, 'err'); }
        finally { uploading.value = false; }
      }
      async function removeCert() {
        if (!confirm('确定移除证书？移除后重启服务将回退为 HTTP。')) return;
        try {
          const r = await api.del('/system/cert');
          certMsgOk.value = r.ok; certMsg.value = r.message || (r.ok ? '已移除' : r.error);
          await loadCert();
        } catch (e) { toast(e.message, 'err'); }
      }

      /* ------------------------ 健康 ------------------------ */
      async function loadHealth() { try { const r = await api.get('/system/health'); Object.assign(health, r); } catch (e) { } }
      async function installRuntime() {
        try {
          const r = await api.post('/system/runtime/install', {});
          if (r.runtime) health.runtime = r.runtime;
          toast(r.message || '已开始后台补装', 'ok');
          setTimeout(loadHealth, 1500);
        } catch (e) { toast(e.message, 'err'); }
      }

      onMounted(async () => { await load(); loadAudit(); loadHealth(); loadCert(); });
      let t = setInterval(loadHealth, 30000);
      onBeforeUnmount(() => clearInterval(t));

      return {
        TABS: TABS_, tab, s, users, creds, roles, myId, auditRows, health,
        testing, syncing, loadingGroups, dsGroups, groupKeyword, dsRes, dsErr, testingCredId, credTest, ntRes,
        uEdit, uForm, editUser, saveUser, resetPwd, delUser,
        cEdit, cForm, editCred, saveCred, testCred, delCred,
        af, loadAudit, exportAudit, userNames, actionNames,
        selectedGroupCount, filteredDsGroups,
        dangerText, save, testDs, loadGroups, syncDs, testNotify, askAi,
        countRows, storageRows, recentAudit, loadHealth, installRuntime,
        certStatus, files, uploading, certMsg, certMsgOk, onCertPick, uploadCert, removeCert,
        ic, fmt, go
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.SystemPage = SystemPage;
  NC.route('/system', { title: '系统管理', comp: 'SystemPage' });
})();
