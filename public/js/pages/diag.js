/* =========================================================================
   网络诊断工具箱：摄像头扫描 / IP 冲突 / 环路 / 日志审计 / 外网测速 / DHCP
   六种工具共用一套「目标范围 → 执行 → 问题清单 → 告警」流程
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, watch } = Vue;
  const NC = window.NC, { api, fmt, icon, toast } = NC;

  const TABS = [
    { k: 'workbench', n: '诊断工作台', i: 'zap' },
    { k: 'findings', n: '问题清单', i: 'shield' },
    { k: 'hosts', n: '诊断主机', i: 'server' },
    { k: 'logs', n: '审计日志', i: 'clipboard' },
    { k: 'tasks', n: '诊断任务', i: 'list' },
    { k: 'runs', n: '历史记录', i: 'history' }
  ];

  const LEVEL_COLOR = {
    critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#0891b2', info: '#64748b'
  };

  const DiagPage = {
    name: 'DiagPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
        <div class="grow"></div>
        <span class="fs12 muted">单次上限 {{ env.maxHosts }} 个地址 · 诊断在控制台本机执行</span>
      </div>

      <!-- ==================== 诊断工作台 ==================== -->
      <div v-show="tab==='workbench'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('filter',15)"></span><span>诊断范围</span>
            <div class="grow"></div>
            <button class="btn sm" :disabled="scopeing" @click="loadScope"
              v-html="ic('refresh',13)+'<span>预览范围</span>'"></button></div>
          <div class="row gap12" style="flex-wrap:wrap">
            <label class="radio-box" :class="{on: scope.mode==='local'}">
              <input type="radio" value="local" v-model="scope.mode"><span>本机所在网段</span></label>
            <label class="radio-box" :class="{on: scope.mode==='range'}">
              <input type="radio" value="range" v-model="scope.mode"><span>指定网段</span></label>
            <input v-if="scope.mode==='range'" class="inp mono sm" style="width:280px"
              v-model="scope.targets" placeholder="10.252.28.0/24 或 192.168.1.1-50">
          </div>
          <div v-if="scopeInfo" class="hint-line" style="margin-top:10px">
            <span v-html="ic('info',13)"></span>
            <span>{{ scopeInfo.note }}<template v-if="scopeInfo.gateways"> · 默认网关 {{ scopeInfo.gateways }}</template></span>
          </div>
          <div v-if="scopeErr" class="hint-line"><span v-html="ic('alert',13)"></span><span class="c-red">{{ scopeErr }}</span></div>
        </div>

        <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(300px,1fr))">
          <div v-for="t in tools" :key="t.key" class="card" style="margin:0">
            <div class="card-head">
              <span v-html="ic(t.icon,15)"></span><span>{{ t.name }}</span>
              <div class="grow"></div>
              <span v-if="busy[t.key]" class="tag" style="color:#16a34a">执行中</span>
            </div>
            <div class="fs12 muted" style="line-height:1.6">{{ t.desc }}</div>
            <div class="fs11 muted" style="margin-top:6px">{{ t.risk }}</div>
            <div class="row gap6" style="margin-top:10px">
              <button class="btn primary sm" :disabled="busy[t.key]" @click="openTool(t)">
                <span v-html="ic('play',13)"></span><span>{{ busy[t.key] ? '执行中...' : '开始诊断' }}</span></button>
              <button class="btn sm" @click="openTool(t, true)">{{ ic('settings',13) }}</button>
            </div>
          </div>
        </div>

        <div v-if="last" class="card">
          <div class="card-head"><span v-html="ic('activity',15)"></span><span>最近一次诊断结果</span>
            <div class="grow"></div>
            <span class="fs12 muted">{{ toolName(last.tool) }} · {{ fmt.ago(last.endedAt || last.startedAt) }}</span>
            <button class="btn sm" @click="exportCsv" v-html="ic('download',13)+'<span>导出 CSV</span>'"></button></div>
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
            <div class="result-box">
              <div class="l fs12 muted">健康评分</div>
              <div class="big" :style="{color: scoreColor(last.score)}">{{ last.score }}</div>
              <div class="fs11 muted">满分 100，扣分制</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">风险等级</div>
              <div class="big" style="font-size:17px" :style="{color: levelColor(last.level)}">
                {{ LEVEL_TEXT[last.level] || last.level }}</div>
              <div class="fs11 muted">{{ (last.findings||[]).length }} 条问题</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">检查目标</div>
              <div class="big" style="font-size:17px">{{ last.targets || '-' }}</div>
              <div class="fs11 muted">{{ last.mode === 'range' ? '指定网段' : '本机网段' }}</div>
            </div>
            <div class="result-box">
              <div class="l fs12 muted">耗时</div>
              <div class="big" style="font-size:17px">{{ ((last.durationMs||0)/1000).toFixed(1) }}s</div>
              <div class="fs11 muted">设备 {{ (last.hosts||[]).length }} 台</div>
            </div>
          </div>
          <div v-if="(last.findings||[]).length" style="margin-top:12px">
            <table class="ntable">
              <thead><tr><th style="width:90px">等级</th><th style="width:150px">目标</th><th style="width:200px">问题</th><th>处置建议</th></tr></thead>
              <tbody>
                <tr v-for="(f,i) in (last.findings||[]).slice(0,6)" :key="i">
                  <td><span class="tag" :style="{color: levelColor(f.level)}">{{ LEVEL_TEXT[f.level]||f.level }}</span></td>
                  <td class="mono fs11">{{ f.target || '—' }}</td>
                  <td class="ellipsis" :title="f.title">{{ f.title }}</td>
                  <td class="fs11 ellipsis" :title="f.advice">{{ f.advice || '—' }}</td>
                </tr>
              </tbody>
            </table>
            <div v-if="(last.findings||[]).length>6" class="fs11 muted" style="margin-top:6px">
              仅显示前 6 条，完整清单见「问题清单」页签</div>
          </div>
          <div v-else class="tbl-empty">本次诊断没有发现明显问题</div>
        </div>
      </div>

      <!-- ==================== 问题清单 ==================== -->
      <div v-show="tab==='findings'" class="card">
        <div class="card-head"><span v-html="ic('shield',15)"></span><span>问题清单</span>
          <div class="grow"></div>
          <select class="inp sm" style="width:150px" v-model="findFilter.tool">
            <option value="">全部工具</option>
            <option v-for="t in tools" :key="t.key" :value="t.key">{{ t.name }}</option>
          </select>
          <select class="inp sm" style="width:110px" v-model="findFilter.level">
            <option value="">全部等级</option>
            <option v-for="(v,k) in LEVEL_TEXT" :key="k" :value="k">{{ v }}</option>
          </select>
          <input class="inp sm" style="width:150px" v-model="findFilter.target" placeholder="按目标过滤">
          <button class="btn sm" @click="loadFindings" v-html="ic('refresh',13)"></button>
          <button class="btn sm" @click="exportCsv" v-html="ic('download',13)"></button>
        </div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr>
              <th style="width:90px">等级</th><th style="width:110px">工具</th><th style="width:140px">分类</th>
              <th style="width:150px">目标</th><th style="width:220px">问题</th><th>处置建议</th><th style="width:150px">发生时间</th>
            </tr></thead>
            <tbody>
              <tr v-for="f in findings.rows" :key="f.id" style="cursor:pointer" @click="toggleFind(f)">
                <td><span class="tag" :style="{color: levelColor(f.level)}">{{ LEVEL_TEXT[f.level]||f.level }}</span></td>
                <td class="fs11">{{ toolName(f.tool) }}</td>
                <td class="fs11 ellipsis" :title="f.category">{{ f.category }}</td>
                <td class="mono fs11">{{ f.target || '—' }}</td>
                <td class="ellipsis" :title="f.title">{{ f.title }}</td>
                <td class="fs11 ellipsis" :title="f.advice">{{ f.advice || '—' }}</td>
                <td class="fs11 muted">{{ fmt.ago(f.createdAt) }}</td>
              </tr>
              <tr v-if="!findings.rows.length"><td colspan="7" class="tbl-empty">没有符合条件的问题记录。跑一次诊断或调整过滤条件再试</td></tr>
            </tbody>
          </table>
        </div>
        <div class="row-between" style="padding:8px 12px">
          <span class="fs11 muted">共 {{ findings.total }} 条{{ findings.total>(findings.rows||[]).length ? '，已分页展示前 '+(findings.rows||[]).length+' 条' : '' }}</span>
          <button class="btn sm" v-if="findings.total>(findings.rows||[]).length" @click="findings.offset+=300; loadFindings()">加载更多</button>
        </div>
      </div>

      <!-- ==================== 诊断主机 ==================== -->
      <div v-show="tab==='hosts'" class="card">
        <div class="card-head"><span v-html="ic('server',15)"></span><span>诊断发现的设备</span>
          <div class="grow"></div>
          <select class="inp sm" style="width:170px" v-model="hostFilter.tool">
            <option value="">全部工具</option>
            <option v-for="t in tools" :key="t.key" :value="t.key">{{ t.name }}</option>
          </select>
          <input class="inp sm" style="width:150px" v-model="hostFilter.ip" placeholder="按 IP 过滤">
          <select class="inp sm" style="width:110px" v-model="hostFilter.risk">
            <option value="">全部风险</option>
            <option v-for="(v,k) in LEVEL_TEXT" :key="k" :value="k">{{ v }}</option>
          </select>
        </div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr>
              <th style="width:140px">IP 地址</th><th style="width:160px">MAC</th>
              <th style="width:140px">厂商</th><th style="width:130px">型号/指纹</th>
              <th style="width:90px">风险</th><th>识别到的服务</th>
            </tr></thead>
            <tbody>
              <tr v-for="h in hosts.rows" :key="h.id">
                <td class="mono">{{ h.ip }}</td>
                <td class="mono fs11">{{ h.mac || '—' }}</td>
                <td class="fs11 ellipsis" :title="h.vendor">{{ h.vendor || '—' }}</td>
                <td class="fs11 ellipsis" :title="h.model">{{ h.model || '—' }}</td>
                <td><span class="tag" :style="{color: levelColor(h.riskLevel)}">{{ LEVEL_TEXT[h.riskLevel]||h.riskLevel }}</span></td>
                <td class="fs11 ellipsis" :title="hostDetail(h)">{{ hostDetail(h) || '—' }}</td>
              </tr>
              <tr v-if="!hosts.rows.length"><td colspan="6" class="tbl-empty">还没有诊断主机记录</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ==================== 审计日志 ==================== -->
      <div v-show="tab==='logs'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('wifi',15)"></span><span>Syslog 接收</span>
            <div class="grow"></div>
            <button class="btn sm" @click="loadLogs" v-html="ic('refresh',13)+'<span>刷新</span>'"></button></div>
          <div class="row gap12" style="flex-wrap:wrap;align-items:flex-end">
            <label class="checkbox"><input type="checkbox" v-model="syslog.enabled"> 启用接收</label>
            <div class="field" style="width:130px"><label>监听端口</label>
              <input class="inp mono" type="number" min="1" max="65535" v-model.number="syslog.port"></div>
            <div class="field" style="width:110px"><label>协议</label>
              <select class="inp" v-model="syslog.proto"><option value="udp">UDP</option><option value="tcp">TCP</option></select></div>
            <button class="btn primary sm" :disabled="savingSyslog" @click="saveSyslog">
              {{ savingSyslog ? '保存中...' : '保存并生效' }}</button>
            <div class="grow"></div>
            <span v-if="slStatus.error" class="fs12 c-red">{{ slStatus.error }}</span>
          </div>
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin-top:12px">
            <div class="result-box"><div class="l fs12 muted">接收状态</div>
              <div class="big" style="font-size:17px;color: slStatus.running ? 'var(--success)' : '#94a3b8'">
                {{ slStatus.running ? '监听中' : '已停止' }}</div>
              <div class="fs11 muted">UDP {{ slStatus.port || 514 }}</div></div>
            <div class="result-box"><div class="l fs12 muted">已接收</div>
              <div class="big">{{ slStatus.received || 0 }}</div><div class="fs11 muted">条</div></div>
            <div class="result-box"><div class="l fs12 muted">丢弃</div>
              <div class="big">{{ slStatus.dropped || 0 }}</div><div class="fs11 muted">条（缓冲区上限）</div></div>
            <div class="result-box"><div class="l fs12 muted">最近收到</div>
              <div class="big" style="font-size:15px">{{ slStatus.lastAt ? fmt.ago(slStatus.lastAt) : '—' }}</div>
              <div class="fs11 muted">设备需指向 {{ slStatus.port || 514 }} 端口</div></div>
          </div>
          <div v-if="slStatus.error" class="hint-line" style="margin-top:10px">
            <span v-html="ic('alert',13)"></span><span class="c-red">{{ slStatus.error }}</span></div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('list',15)"></span><span>日志统计</span>
            <div class="grow"></div>
            <select class="inp sm" style="width:150px" v-model="logFilter.tool">
              <option value="">全部工具</option><option value="logaudit">仅日志审计</option></select>
            <span class="fs12 muted">近 {{ logDays }} 天</span></div>
          <div class="row gap12">
            <div v-for="b in logStats.byLevel || []" :key="b.level" class="result-box" style="flex:1;min-width:110px;cursor:pointer"
                 @click="logFilter.level=b.level; loadLogs()">
              <div class="l fs12 muted">{{ LEVEL_TEXT[b.level]||b.level }}</div>
              <div class="big" :style="{color: levelColor(b.level)}">{{ b.count }}</div>
              <div class="fs11 muted">条</div>
            </div>
            <div v-if="!(logStats.byLevel||[]).length" class="tbl-empty">暂无日志</div>
          </div>
          <div class="row gap12" style="margin-top:10px;flex-wrap:wrap">
            <div v-for="b in logStats.byRule || []" :key="b.rule" class="tag" style="cursor:pointer"
                 @click="logFilter.rule=b.rule; loadLogs()" :title="b.rule">{{ b.rule }} · {{ b.count }}</div>
            <span v-if="!(logStats.byRule||[]).length" class="fs11 muted">没有命中规则的日志（规则>{{ rules.length }} 条）</span>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('clipboard',15)"></span><span>日志明细</span>
            <div class="grow"></div>
            <input class="inp sm" style="width:150px" v-model="logFilter.host" placeholder="按来源主机过滤">
            <select class="inp sm" style="width:100px" v-model="logFilter.level">
              <option value="">全部等级</option>
              <option v-for="(v,k) in LEVEL_TEXT" :key="k" :value="k">{{ v }}</option>
            </select>
            <select class="inp sm" style="width:140px" v-model="logFilter.source">
              <option value="">全部来源</option><option value="syslog">Syslog</option><option value="local">本机事件</option></select>
            <button class="btn sm danger" @click="clearLogs" v-html="ic('trash',13)+'<span>清空</span>'"></button>
          </div>
          <div class="table-wrap">
            <table class="ntable">
              <thead><tr>
                <th style="width:100px">级别</th><th style="width:130px">来源主机</th><th style="width:110px">Facility</th>
                <th style="width:80px">Severity</th><th style="width:150px">标签</th><th>消息</th><th style="width:140px">时间</th>
              </tr></thead>
              <tbody>
                <tr v-for="l in logs.rows" :key="l.id">
                  <td><span class="tag" :style="{color: levelColor(l.level)}">{{ LEVEL_TEXT[l.level]||l.level }}</span></td>
                  <td class="ellipsis fs11" :title="l.host">{{ l.host || '—' }}</td>
                  <td class="fs11">{{ l.facility || '—' }}</td>
                  <td class="mono fs11">{{ l.severity ?? '—' }}</td>
                  <td class="fs11 ellipsis" :title="l.tag">{{ l.tag || '—' }}</td>
                  <td class="fs11 ellipsis" :title="l.message">{{ l.message || '—' }}</td>
                  <td class="fs11 muted">{{ fmt.ago(l.logAt || l.createdAt) }}</td>
                </tr>
                <tr v-if="!logs.rows.length"><td colspan="7" class="tbl-empty">没有日志。开启 Syslog 接收后，设备指向本控制台端口即可上报</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ==================== 诊断任务 ==================== -->
      <div v-show="tab==='tasks'" class="card">
        <div class="card-head"><span v-html="ic('list',15)"></span><span>诊断任务</span>
          <div class="grow"></div>
          <button class="btn primary sm" @click="editTask(null)" v-html="ic('plus',14)+'<span>新建任务</span>'"></button></div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr>
              <th style="width:190px">任务</th><th style="width:130px">工具</th><th style="width:180px">目标</th>
              <th style="width:80px">周期</th><th style="width:80px">保留</th><th style="width:110px">执行次数</th>
              <th style="width:100px">状态</th><th style="width:150px">操作</th>
            </tr></thead>
            <tbody>
              <tr v-for="t in tasks" :key="t.id">
                <td class="ellipsis" style="max-width:190px" :title="t.name"><b>{{ t.name }}</b>
                  <div class="fs11 muted">{{ fmt.ago(t.lastStartedAt) }}执行</div></td>
                <td class="fs11">{{ toolName(t.tool) }}</td>
                <td class="mono fs11 ellipsis" style="max-width:180px" :title="t.targets">{{ t.targets || '本机网段' }}</td>
                <td class="mono fs11">{{ Number(t.intervalSec||0) }}s</td>
                <td class="mono fs11">{{ Number(t.retainHours||0) }}h</td>
                <td class="mono fs11">{{ Number(t.runs||0) }}</td>
                <td><span class="tag" :style="taskStyle(t)">{{ t.enabled ? (taskBusy(t.tool)?'执行中':'启用中') : '已停用' }}</span></td>
                <td class="row gap6">
                  <button class="btn sm" @click="runTask(t)" :disabled="taskBusy(t.tool)" v-html="ic('play',13)"></button>
                  <button class="btn sm" @click="toggleTask(t)">{{ t.enabled ? '停用' : '启用' }}</button>
                  <button class="btn sm" @click="editTask(t)">{{ ic('edit',13) }}</button>
                  <button class="btn sm" @click="delTask(t)">{{ ic('trash',13) }}</button>
                </td>
              </tr>
              <tr v-if="!tasks.length"><td colspan="8" class="tbl-empty">还没有诊断任务，点右上角「新建任务」把常用检查固化成定时巡检</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ==================== 历史记录 ==================== -->
      <div v-show="tab==='runs'" class="card">
        <div class="card-head"><span v-html="ic('history',15)"></span><span>诊断历史</span>
          <div class="grow"></div>
          <select class="inp sm" style="width:150px" v-model="runFilter">
            <option value="">全部工具</option>
            <option v-for="t in tools" :key="t.key" :value="t.key">{{ t.name }}</option>
          </select></div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr>
              <th style="width:110px">工具</th><th style="width:200px">目标</th><th style="width:90px">状态</th>
              <th style="width:70px">评分</th><th style="width:90px">等级</th><th style="width:80px">问题</th>
              <th style="width:80px">设备</th><th style="width:90px">耗时</th><th style="width:140px">开始时间</th>
            </tr></thead>
            <tbody>
              <tr v-for="r in runs" :key="r.id">
                <td class="fs11">{{ toolName(r.tool) }}</td>
                <td class="mono fs11 ellipsis" style="max-width:200px" :title="r.targets">{{ r.targets || '—' }}</td>
                <td>{{ runStatus(r) }}</td>
                <td class="mono" :style="r.status==='error' ? {color:'#94a3b8'} : {color: scoreColor(r.score)}">{{ r.score ?? '—' }}</td>
                <td><span class="tag" :style="{color: levelColor(r.level)}">{{ LEVEL_TEXT[r.level]||r.level }}</span></td>
                <td class="mono">{{ r.findingsCount ?? 0 }}</td>
                <td class="mono">{{ r.targetsDone ?? r.targetsTotal ?? 0 }}</td>
                <td class="mono fs11">{{ r.status==='error' ? '—' : ((r.durationMs||0)/1000).toFixed(1)+'s' }}</td>
                <td class="fs11 muted">{{ fmt.ago(r.startedAt) }}</td>
              </tr>
              <tr v-if="!runs.length"><td colspan="9" class="tbl-empty">还没有诊断记录</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ==================== 执行弹窗 ==================== -->
      <NcModal v-if="form" :title="(form._tool ? form._tool.name : '诊断') + ' · 执行设置'" @close="form=null">
        <template #body>
          <div class="field"><label>诊断目标</label>
            <div class="row gap12">
              <label class="radio-box" :class="{on: form.mode==='local'}">
                <input type="radio" value="local" v-model="form.mode"><span>本机网段</span></label>
              <label class="radio-box" :class="{on: form.mode==='range'}">
                <input type="radio" value="range" v-model="form.mode"><span>指定网段</span></label>
            </div>
            <input v-if="form.mode==='range'" class="inp mono" style="margin-top:8px"
              :value="form.targets" @input="form.targets=$event.target.value"
              placeholder="10.252.28.0/24 或 192.168.1.1-50">
            <div class="fs11 muted" style="margin-top:6px">{{ scopeHint }}</div>
          </div>
          <div v-if="form._tool && form._tool.needsTargets && form.mode==='range' && !form.targets" class="hint-line">
            <span v-html="ic('alert',13)"></span><span class="c-red">指定网段模式下必须填写目标，否则无法执行</span></div>
          <div v-for="o in form._tool ? form._tool.options : []" :key="o.key" class="row gap12">
            <div class="field" style="flex:1"><label>{{ o.label }}</label>
              <select class="inp" v-if="o.type==='select'" v-model="form[o.key]">
                <option v-for="c in (o.choices||[])" :key="c.v" :value="c.v">{{ c.t }}</option></select>
              <input v-else class="inp mono" :type="o.type==='number'?'number':'text'" v-model="form[o.key]">
            </div>
          </div>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>{{ form._tool ? form._tool.risk : '' }}</span></div>
          <div class="hint-line"><span v-html="ic('alert',13)"></span>
            <span>这类检查会向目标网段主动发包，需要 scan 权限；问题会同步进告警中心。</span></div>
        </template>
        <template #foot>
          <button class="btn" @click="form=null">取消</button>
          <button class="btn primary" :disabled="running" @click="doRun">
            {{ running ? '诊断中...' : '开始诊断' }}</button>
        </template>
      </NcModal>

      <!-- ==================== 任务弹窗 ==================== -->
      <NcModal v-if="tform" :title="tform.id ? '编辑诊断任务' : '新建诊断任务'" @close="tform=null">
        <template #body>
          <div class="field"><label>任务名称</label>
            <input class="inp" v-model="tform.name" placeholder="例如：每周一安防摄像头巡检"></div>
          <div class="field"><label>诊断工具</label>
            <select class="inp" v-model="tform.tool">
              <option v-for="t in tools" :key="t.key" :value="t.key">{{ t.name }}</option>
            </select>
            <div class="fs11 muted" style="margin-top:4px">{{ toolMeta(tform.tool) }}</div></div>
          <div class="field"><label>诊断目标</label>
            <div class="row gap12">
              <label class="radio-box" :class="{on: tform.mode==='local'}">
                <input type="radio" value="local" v-model="tform.mode"><span>本机网段</span></label>
              <label class="radio-box" :class="{on: tform.mode==='range'}">
                <input type="radio" value="range" v-model="tform.mode"><span>指定网段</span></label>
            </div>
            <input v-if="tform.mode==='range'" class="inp mono" style="margin-top:8px" v-model="tform.targets"
              placeholder="10.252.28.0/24 或 192.168.1.1-50">
          </div>
          <div class="row gap12">
            <div class="field" style="flex:1"><label>巡检周期（秒）</label>
              <input class="inp" type="number" min="60" v-model.number="tform.intervalSec"></div>
            <div class="field" style="flex:1"><label>结果保留（小时）</label>
              <input class="inp" type="number" min="1" v-model.number="tform.retainHours"></div>
          </div>
          <label class="checkbox"><input type="checkbox" v-model="tform.enabled"> 启用（到点自动巡检）</label>
        </template>
        <template #foot>
          <button class="btn" @click="tform=null">取消</button>
          <button class="btn primary" :disabled="savingTask" @click="saveTask">
            {{ savingTask ? '保存中...' : '保存' }}</button>
        </template>
      </NcModal>
    </div>`,
    setup() {
      const TABS_ = TABS, LEVEL_TEXT_ = ref({ critical: '极高危', high: '高危', medium: '中危', low: '低危', info: '提示' }).value;
      const tab = ref('workbench');

      const tools = ref([]), rules = ref([]), env = reactive({ maxHosts: 1024 });
      const busy = reactive({});
      const scope = reactive({ mode: 'local', targets: '' });
      const scopeInfo = ref(null), scopeErr = ref(''), scopeing = ref(false);
      const last = ref(null), running = ref(false);

      const findings = reactive({ total: 0, rows: [], offset: 0 });
      const hosts = reactive({ total: 0, rows: [] });
      const logs = reactive({ total: 0, rows: [] });
      const logStats = reactive({ total: 0, byLevel: [], byRule: [] });
      const tasks = ref([]), runs = ref([]), runFilter = ref('');
      const rules_ = rules;

      const findFilter = reactive({ tool: '', level: '', target: '' });
      const hostFilter = reactive({ tool: '', ip: '', risk: '' });
      const logFilter = reactive({ tool: '', host: '', level: '', source: '', rule: '' });
      const logDays = ref(7);

      const syslog = reactive({ enabled: false, port: 5140, proto: 'udp' });
      const slStatus = reactive({ running: false, port: 514, received: 0, dropped: 0, lastAt: '', error: '' });
      const savingSyslog = ref(false);

      const form = ref(null), tform = ref(null);
      const savingTask = ref(false);

      const ic = (n, s) => icon(n, s);
      const levelColor = (l) => LEVEL_COLOR[l] || '#64748b';
      const scoreColor = (s) => {
        const n = Number(s);
        if (n >= 85) return '#16a34a'; if (n >= 60) return '#d97706'; if (n >= 30) return '#ea580c'; return '#dc2626';
      };
      const toolMeta = (k) => { const t = tools.value.find(x => x.key === k); return t ? `${t.name} · ${t.desc}` : ''; };
      const toolName = (k) => { const t = tools.value.find(x => x.key === k); return t ? t.name : (k || '—'); };
      const runStatus = (r) => r.status === 'done' ? '已完成' : (r.status === 'error' ? '失败' : (r.status || '—'));
      const taskStyle = (t) => !t.enabled ? { color: '#94a3b8' } : (t.status === 'running' ? { color: '#16a34a' } : { color: '#2563eb' });
      const taskBusy = (k) => !!busy[k];
      const hostDetail = (h) => {
        const d = h.data || {};
        const bits = [];
        if ((d.openPorts || []).length) bits.push('端口 ' + d.openPorts.slice(0, 6).join('/'));
        if (d.httpTitle) bits.push('HTTP：' + d.httpTitle);
        if (d.rtspServer) bits.push('RTSP：' + d.rtspServer);
        if ((d.rtspNoAuth || []).length) bits.push('RTSP 未鉴权 ' + d.rtspNoAuth.length + ' 路');
        if (d.onvif) bits.push('ONVIF');
        return bits.join(' · ');
      };
      const toggleFind = (f) => { f._open = !f._open; };
      const scopeHint = computed(() => {
        if (!scopeInfo.value) return '先在上方点「预览范围」，确认会扫哪些地址';
        return scopeInfo.value.note || '';
      });

      /* ------------------------------ 元数据 ------------------------------ */
      async function loadMeta() {
        try {
          const r = await api.get('/diag/tools');
          tools.value = r.tools || [];
          Object.assign(LEVEL_TEXT_, r.levels || {});
          rules.value = r.rules || [];
          if (r.env) {
            env.maxHosts = r.env.maxHosts || env.maxHosts;
            slStatus.port = r.env.syslog?.port || slStatus.port;
          }
        } catch (e) { toast(e.message, 'err'); }
      }
      async function loadScope() {
        scopeing.value = true; scopeErr.value = '';
        try {
          const q = scope.mode === 'range' ? '&targets=' + encodeURIComponent(scope.targets) : '';
          const r = await api.get('/diag/scope?mode=' + scope.mode + q);
          scopeInfo.value = r;
          if (scope.mode === 'range' && scope.targets) scope.targets = scope.targets;
        } catch (e) { scopeErr.value = e.message || String(e); scopeInfo.value = null; }
        finally { scopeing.value = false; }
      }
      async function loadSyslog() {
        try {
          const r = await api.get('/diag/syslog');
          Object.assign(slStatus, r.status || {});
          if (r.config) { syslog.enabled = !!r.config.enabled; syslog.port = r.config.port || syslog.port; syslog.proto = r.config.proto || 'udp'; }
        } catch { }
      }
      async function saveSyslog() {
        savingSyslog.value = true;
        try {
          const r = await api.post('/diag/syslog', { enabled: syslog.enabled, port: syslog.port, proto: syslog.proto });
          Object.assign(slStatus, r.status || {});
          toast(slStatus.error ? '已保存，但接收未启动：' + (slStatus.error || '') : 'Syslog 接收已生效', slStatus.error ? 'err' : 'ok');
          await loadLogs();
        } catch (e) { toast(e.message, 'err'); } finally { savingSyslog.value = false; }
      }

      /* ------------------------------ 列表加载 ------------------------------ */
      async function loadFindings() {
        try {
          const q = '/diag/findings?limit=300&offset=' + findings.offset
            + (findFilter.tool ? '&tool=' + encodeURIComponent(findFilter.tool) : '')
            + (findFilter.level ? '&level=' + encodeURIComponent(findFilter.level) : '')
            + (findFilter.target ? '&target=' + encodeURIComponent(findFilter.target) : '');
          const r = await api.get(q);
          findings.rows = r.rows || []; findings.total = r.total || 0;
        } catch (e) { toast(e.message, 'err'); }
      }
      async function loadHosts() {
        try {
          const q = '/diag/hosts?limit=500'
            + (hostFilter.tool ? '&tool=' + encodeURIComponent(hostFilter.tool) : '')
            + (hostFilter.ip ? '&ip=' + encodeURIComponent(hostFilter.ip) : '')
            + (hostFilter.risk ? '&risk=' + encodeURIComponent(hostFilter.risk) : '');
          const r = await api.get(q);
          hosts.rows = r.rows || []; hosts.total = r.total || 0;
        } catch (e) { toast(e.message, 'err'); }
      }
      async function loadLogs() {
        await loadSyslog();
        try {
          const q = '/diag/logs?limit=200'
            + (logFilter.tool ? '&tool=' + encodeURIComponent(logFilter.tool) : '')
            + (logFilter.host ? '&host=' + encodeURIComponent(logFilter.host) : '')
            + (logFilter.level ? '&level=' + encodeURIComponent(logFilter.level) : '')
            + (logFilter.source ? '&source=' + encodeURIComponent(logFilter.source) : '')
            + (logFilter.rule ? '&rule=' + encodeURIComponent(logFilter.rule) : '');
          const r = await api.get(q);
          logs.rows = r.rows || []; logs.total = r.total || 0;
        } catch (e) { toast(e.message, 'err'); }
        await loadLogStats();
      }
      async function loadLogStats() {
        try {
          Object.assign(logStats, await api.get('/diag/logs/stats?days=' + logDays
            + (logFilter.tool ? '&tool=' + encodeURIComponent(logFilter.tool) : '')
            + (logFilter.rule ? '&rule=' + encodeURIComponent(logFilter.rule) : '')));
        } catch { }
      }
      async function loadTasks() {
        try { const r = await api.get('/diag/tasks'); tasks.value = r.rows || []; }
        catch (e) { toast(e.message, 'err'); }
      }
      async function loadRuns() {
        try {
          const r = await api.get('/diag/runs?limit=50' + (runFilter.value ? '&tool=' + encodeURIComponent(runFilter.value) : ''));
          runs.value = r.rows || [];
        } catch { }
      }
      async function clearLogs() {
        if (!confirm('确定清空审计日志？执行诊断产生的日志不受影响。')) return;
        try {
          const r = await api.post('/diag/logs/clear', { tool: logFilter.tool || '' });
          toast('已清空 ' + (r.removed || 0) + ' 条', 'ok');
          await loadLogs();
        } catch (e) { toast(e.message, 'err'); }
      }
      function exportCsv() {
        if (!last.value) return toast('先跑一次诊断再导出', 'warn');
        window.location.href = '/api/diag/export?runId=' + last.value.runId;
      }

      /* ------------------------------ 执行 ------------------------------ */
      function openTool(t, withOpts) {
        const o = {};
        for (const x of (t.options || [])) o[x.key] = x.def;
        // 不需要目标的工具（测速/日志审计/DHCP）一律走本机，别把网段输入框留成脏值
        form.value = t.needsTargets
          ? Object.assign({ _tool: t, mode: scope.mode, targets: scope.targets }, o)
          : Object.assign({ _tool: t, mode: 'local', targets: '' }, o);
        if (withOpts) tab.value = 'workbench';
      }
      async function doRun() {
        const f = form.value;
        if (!f) return;
        if (f.mode === 'range' && !String(f.targets || '').trim()) return toast('指定网段模式下必须填写目标', 'warn');
        const tool = f._tool.key;
        running.value = true; busy[tool] = true;
        try {
          const r = await api.post('/diag/run', { tool, mode: f.mode, targets: f.targets, ...pickOpts(f) });
          form.value = null;
          last.value = r;
          toast(`诊断完成：${r.levelText} · ${r.score} 分 · ${(r.findings || []).length} 条问题`, r.findings && r.findings.length ? 'warn' : 'ok');
          await Promise.all([loadFindings(), loadHosts(), loadRuns(), loadTasks()]);
          if (tool === 'logaudit') await loadLogs();
          tab.value = (r.findings && r.findings.length) || tool === 'logaudit' ? 'findings' : 'workbench';
        } catch (e) { toast(e.message, 'err'); }
        finally { running.value = false; busy[tool] = false; }
      }
      /** 只透传该工具声明过的选项，防止把输入框里的脏数据塞进执行上下文 */
      function pickOpts(f) {
        const out = {};
        for (const x of ((f._tool || {}).options || [])) {
          if (f[x.key] === undefined || f[x.key] === '') continue;
          out[x.key] = x.type === 'number' ? Number(f[x.key]) : f[x.key];
        }
        if (f.iface) out.iface = f.iface;
        return out;
      }

      /* ------------------------------ 任务 ------------------------------ */
      function editTask(t) {
        tform.value = t ? JSON.parse(JSON.stringify(t))
          : { name: '', tool: (tools.value[0] || {}).key || 'camera', mode: 'local', targets: '', intervalSec: 3600, retainHours: 168, enabled: false };
      }
      async function saveTask() {
        const f = tform.value;
        if (!f.name) return toast('任务名称必填', 'warn');
        if (f.mode === 'range' && !String(f.targets || '').trim()) return toast('指定网段模式下必须填写目标', 'warn');
        savingTask.value = true;
        try {
          if (f.id) await api.put('/diag/tasks/' + f.id, f); else await api.post('/diag/tasks', f);
          toast('任务已保存', 'ok'); tform.value = null; await loadTasks();
        } catch (e) { toast(e.message, 'err'); } finally { savingTask.value = false; }
      }
      async function runTask(t) {
        if (busy[t.tool]) return toast('该工具正在执行，请稍候', 'warn');
        busy[t.tool] = true;
        try {
          const r = await api.post('/diag/tasks/' + t.id + '/run', {});
          toast(`任务执行完成：${r.score} 分 · ${(r.findings || []).length} 条问题`, (r.findings || []).length ? 'warn' : 'ok');
          last.value = r;
          await Promise.all([loadRuns(), loadTasks(), loadFindings(), loadHosts()]);
        } catch (e) { toast(e.message, 'err'); } finally { busy[t.tool] = false; }
      }
      async function toggleTask(t) {
        try { const r = await api.post('/diag/tasks/' + t.id + '/toggle', { enabled: !t.enabled }); toast(r.task?.enabled ? '已启用' : '已停用', 'ok'); await loadTasks(); }
        catch (e) { toast(e.message, 'err'); }
      }
      async function delTask(t) {
        if (!confirm(`确定删除诊断任务「${t.name}」？历史诊断记录会保留。`)) return;
        try { await api.del('/diag/tasks/' + t.id); toast('已删除', 'ok'); await loadTasks(); }
        catch (e) { toast(e.message, 'err'); }
      }

      watch(() => [findFilter.tool, findFilter.level, findFilter.target], () => { findings.offset = 0; loadFindings(); });
      watch(() => [hostFilter.tool, hostFilter.ip, hostFilter.risk], loadHosts);
      watch(() => [logFilter.tool, logFilter.host, logFilter.level, logFilter.source, logFilter.rule], loadLogs);
      watch(runFilter, loadRuns);
      watch(tab, (t) => {
        if (t === 'findings') loadFindings();
        if (t === 'hosts') loadHosts();
        if (t === 'logs') loadLogs();
        if (t === 'tasks') loadTasks();
        if (t === 'runs') loadRuns();
      });

      onMounted(async () => {
        await loadMeta();
        await loadScope();
        loadSyslog();
        await Promise.all([loadFindings(), loadHosts(), loadTasks(), loadRuns()]);
      });

      return {
        TABS: TABS_, LEVEL_TEXT: LEVEL_TEXT_, ic, fmt,
        tab, tools, env, busy, scope, scopeInfo, scopeErr, scopeing, last, running,
        findings, hosts, logs, logStats, logDays, tasks, runs, runFilter, rules: rules_,
        findFilter, hostFilter, logFilter, syslog, slStatus, savingSyslog,
        form, tform, savingTask,
        levelColor, scoreColor, toolMeta, toolName, runStatus, taskStyle, taskBusy, hostDetail,
        toggleFind, scopeHint,
        loadScope, loadFindings, loadHosts, loadLogs, loadLogStats, loadTasks, loadRuns, loadMeta,
        saveSyslog, clearLogs, exportCsv,
        openTool, doRun, editTask, saveTask, runTask, toggleTask, delTask
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.DiagPage = DiagPage;
  NC.route('/diag', { title: '网络诊断工具箱', comp: 'DiagPage' });
})();
