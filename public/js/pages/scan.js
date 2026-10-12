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
            <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(130px,1fr))">
              <div class="result-box"><div class="fs11 muted">目标地址</div><div class="big">{{ run.hostsTotal||0 }}</div><div class="fs11 muted">本次实际展开</div></div>
              <div class="result-box"><div class="fs11 muted">存活主机</div><div class="big" style="color:var(--success)">{{ run.hostsAlive||0 }}</div><div class="fs11 muted">可用率 {{ run.hostsTotal ? ((run.hostsAlive/run.hostsTotal)*100).toFixed(1) : 0 }}%</div></div>
              <div class="result-box"><div class="fs11 muted">未响应</div><div class="big">{{ Math.max(0,(run.hostsTotal||0)-(run.hostsAlive||0)) }}</div><div class="fs11 muted">需结合防火墙判断</div></div>
              <div class="result-box"><div class="fs11 muted">开放端口</div><div class="big" style="color:var(--primary)">{{ run.portsOpen||0 }}</div><div class="fs11 muted">TCP 可连接</div></div>
              <div class="result-box"><div class="fs11 muted">高危主机</div><div class="big" :style="{color:run.risks?'var(--danger)':'var(--success)'}">{{ run.risks||0 }}</div><div class="fs11 muted">高危或极高危</div></div>
            </div>
            <div class="result-box">
              <div class="row" style="align-items:center"><b class="fs12">执行参数</b><span v-if="run.data?.note" class="tag" style="margin-left:8px">{{ run.data.note }}</span></div>
              <div class="fs12 muted" style="margin-top:8px;line-height:1.8">
                扫描端口：<span class="mono">{{ (run.data?.ports||[]).join(', ')||'—' }}</span>；
                发现端口：<span class="mono">{{ (run.data?.discoveryPorts||[]).join(', ')||'默认' }}</span>；
                并发 {{ run.data?.concurrency||60 }}；超时 {{ run.data?.timeoutMs||1200 }}ms；重试 {{ run.data?.retries||0 }} 次；
                Banner {{ run.data?.banner===false?'关闭':'开启' }}；反向 DNS {{ run.data?.reverseDns===false?'关闭':'开启' }}
                <span v-if="run.data?.excludeTargets">；排除：<span class="mono">{{ run.data.excludeTargets }}</span></span>
              </div>
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
          <div class="result-box" style="margin-top:12px">
            <div class="row" style="align-items:center"><b class="fs13">自定义参数</b><span class="fs11 muted" style="margin-left:8px">安全参数化执行，不接收原始命令行</span></div>
            <div class="row gap12" style="margin-top:10px">
              <div class="field" style="flex:1"><label>自定义发现端口</label>
                <input class="inp mono" v-model="form.discoveryPorts" placeholder="22,80,443,445,3389"></div>
              <div class="field" style="width:130px"><label>失败重试</label>
                <input class="inp" type="number" min="0" max="3" v-model.number="form.retries"></div>
            </div>
            <div class="field"><label>排除目标</label>
              <input class="inp mono" v-model="form.excludeTargets" placeholder="例如：10.0.0.1,10.0.0.200-254"></div>
            <div class="field"><label>任务备注</label>
              <input class="inp" maxlength="200" v-model="form.note" placeholder="例如：变更窗口前基线检查"></div>
            <label class="checkbox"><input type="checkbox" v-model="form.reverseDns"> 反向解析主机名（目标不超过 64 台时执行）</label>
          </div>
          <div class="hint-line"><span v-html="ic('info',13)"></span><span>{{ modeDesc }}</span></div>
          <div class="hint-line"><span v-html="ic('alert',13)"></span><span>扫描结果会自动并入设备台账与告警中心；单次最多扫描 {{ env.maxHosts }} 个地址。</span></div>
        </template>
        <template #foot>
          <button class="btn" @click="form=null">取消</button>
          <button class="btn primary" :disabled="saving" @click="save">{{ saving?'保存中...':'保存' }}</button>
        </template>
      </NcModal>

      <!-- ==================== 快速扫描 ==================== -->
      <NcModal v-if="qform" wide title="快速扫描 · 参数与结果" @close="qform=null">
        <template #body>
          <div v-if="!qresult">
            <div class="hint-line" style="margin-top:0"><span v-html="ic('info',13)"></span>
              <span>扫描结果会保存到主机、端口、风险与报告页，并给出可用率、服务分布和处置建议。</span></div>
            <div class="field"><label>扫描目标 <span class="c-red">*</span></label>
              <input class="inp mono" v-model.trim="qform.targets" placeholder="单个 IP、主机名、CIDR 或区间；多个目标用逗号分隔">
              <div class="fs11 muted" style="margin-top:5px">示例：127.0.0.1、10.252.28.0/24、192.168.1.1-50</div></div>
            <div class="row gap12">
              <div class="field" style="flex:2"><label>扫描端口</label>
                <input class="inp mono" v-model.trim="qform.ports" placeholder="22,80,443 或 1-1024"></div>
              <div class="field" style="flex:1"><label>端口预设</label>
                <select class="inp" @change="applyQuickPreset($event)">
                  <option value="">选择预设</option>
                  <option v-for="p in meta.presets" :key="p.key" :value="p.ports.join(',')">{{ p.label }} · {{ p.ports.length }}项</option>
                </select></div>
            </div>
            <div class="row gap12">
              <div class="field" style="flex:1"><label>存活发现方式</label>
                <select class="inp" v-model="qform.discoverMode">
                  <option v-for="m in meta.modes" :key="m.key" :value="m.key">{{ m.label }}</option>
                </select>
                <div class="fs11 muted" style="margin-top:5px">{{ qModeDesc }}</div></div>
              <div class="field" style="width:150px"><label>并发连接</label>
                <input class="inp" type="number" min="1" max="400" v-model.number="qform.concurrency"></div>
              <div class="field" style="width:150px"><label>单连接超时</label>
                <div class="row"><input class="inp" type="number" min="200" max="10000" step="100" v-model.number="qform.timeoutMs"><span class="fs11 muted" style="padding:9px 0 0 6px">ms</span></div></div>
            </div>
            <div class="result-box" style="margin:4px 0 12px">
              <div class="row" style="align-items:center;cursor:pointer" @click="qadvanced=!qadvanced">
                <span v-html="ic('settings',14)"></span><b class="fs13" style="margin-left:7px">自定义参数</b>
                <span class="fs11 muted" style="margin-left:8px">排除范围、发现端口、重试、主机名与备注</span><div class="grow"></div>
                <span class="fs12">{{ qadvanced ? '收起' : '展开' }}</span></div>
              <div v-if="qadvanced" style="margin-top:12px">
                <div class="row gap12">
                  <div class="field" style="flex:1"><label>自定义发现端口</label>
                    <input class="inp mono" v-model.trim="qform.discoveryPorts" placeholder="22,80,443,445,3389"></div>
                  <div class="field" style="width:130px"><label>失败重试</label>
                    <input class="inp" type="number" min="0" max="3" v-model.number="qform.retries"></div>
                </div>
                <div class="field"><label>排除目标</label>
                  <input class="inp mono" v-model.trim="qform.excludeTargets" placeholder="IP、区间或 CIDR，例如 10.0.0.1,10.0.0.200-254"></div>
                <div class="field"><label>扫描备注</label>
                  <input class="inp" maxlength="200" v-model.trim="qform.note" placeholder="用途、工单号、变更窗口等"></div>
                <div class="row gap16">
                  <label class="checkbox"><input type="checkbox" v-model="qform.banner"> 抓取服务 Banner / 产品指纹</label>
                  <label class="checkbox"><input type="checkbox" v-model="qform.reverseDns"> 反向解析主机名</label>
                </div>
              </div>
            </div>
            <div class="hint-line"><span v-html="ic('activity',13)"></span>
              <span>本次配置：{{ quickPortCount }} 个扫描端口 · 并发 {{ qform.concurrency }} · 超时 {{ qform.timeoutMs }}ms · 重试 {{ qform.retries }} 次</span></div>
          </div>

          <div v-else class="col gap12">
            <div class="row" style="align-items:center"><span class="tag" style="color:var(--success)">扫描完成</span>
              <b style="margin-left:8px">{{ qresult.total }} 个目标，发现 {{ qresult.alive }} 台存活主机</b>
              <div class="grow"></div><span class="fs12 muted">耗时 {{ (qresult.ms/1000).toFixed(1) }}s</span></div>
            <div class="grid" style="grid-template-columns:repeat(5,1fr)">
              <div class="result-box"><div class="fs11 muted">可用率</div><div class="big">{{ qresult.availabilityRate }}%</div></div>
              <div class="result-box"><div class="fs11 muted">存活 / 离线</div><div class="big">{{ qresult.alive }} / {{ qresult.offline }}</div></div>
              <div class="result-box"><div class="fs11 muted">开放端口</div><div class="big">{{ qresult.openPorts }}</div></div>
              <div class="result-box"><div class="fs11 muted">高危主机</div><div class="big" :style="{color:qresult.riskHosts?'var(--danger)':'var(--success)'}">{{ qresult.riskHosts }}</div></div>
              <div class="result-box"><div class="fs11 muted">平均时延</div><div class="big">{{ qresult.avgRttMs==null?'—':qresult.avgRttMs+' ms' }}</div></div>
            </div>
            <div v-if="qresult.services?.length" class="result-box"><b class="fs12">服务分布</b>
              <div class="row gap6" style="margin-top:8px;flex-wrap:wrap"><span v-for="s in qresult.services" :key="s.service" class="tag">{{ s.service }} × {{ s.count }}</span></div></div>
            <div class="table-wrap" v-if="qresult.hostPreview?.length"><table class="ntable">
              <thead><tr><th>主机</th><th>主机名</th><th>时延</th><th>开放端口</th><th>风险</th></tr></thead>
              <tbody><tr v-for="h in qresult.hostPreview.slice(0,8)" :key="h.ip">
                <td class="mono">{{ h.ip }}</td><td>{{ h.hostname||'—' }}</td><td class="mono">{{ h.rttMs==null?'—':h.rttMs+' ms' }}</td>
                <td class="mono">{{ h.openPorts.join(', ')||'未发现' }}</td>
                <td><span class="tag" :style="{color:riskColor(h.riskLevel)}">{{ RISK_TEXT[h.riskLevel]||h.riskLevel }}</span></td>
              </tr></tbody></table></div>
            <div class="result-box"><b class="fs12">处置建议</b>
              <div v-for="(x,i) in qresult.recommendations" :key="i" class="fs12" style="margin-top:7px">{{ i+1 }}. {{ x }}</div></div>
          </div>
        </template>
        <template #foot>
          <button class="btn" @click="qform=null">取消</button>
          <button v-if="qresult" class="btn" @click="resetQuick">调整参数再扫</button>
          <button v-if="qresult" class="btn primary" @click="viewQuickResult">查看完整报告</button>
          <button v-else class="btn primary" :disabled="qrunning" @click="doQuick">{{ qrunning?'扫描中，请勿关闭...':'开始扫描' }}</button>
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
      const form = ref(null), qform = ref(null), qresult = ref(null), qadvanced = ref(false);
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
      const qModeDesc = computed(() => (meta.modes.find(m => m.key === qform.value?.discoverMode) || {}).desc || '');
      const quickPortCount = computed(() => {
        if (!qform.value) return 0;
        const set = new Set();
        for (const token of String(qform.value.ports || '').split(/[\s,;]+/)) {
          const m = token.match(/^(\d+)-(\d+)$/);
          if (m) {
            const a = Number(m[1]), b = Math.min(65535, Number(m[2]));
            if (a > 0 && a <= b && b - a <= 10000) for (let p = a; p <= b; p++) set.add(p);
          } else {
            const p = Number(token); if (Number.isInteger(p) && p > 0 && p <= 65535) set.add(p);
          }
        }
        return set.size;
      });

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
        if (t) {
          const copy = JSON.parse(JSON.stringify(t));
          form.value = { ...copy, ...(copy.data || {}) };
          delete form.value.data;
          if (form.value.reverseDns === undefined) form.value.reverseDns = true;
          if (form.value.discoveryPorts === undefined) form.value.discoveryPorts = '22,80,443,445,3389,5985,8080';
          if (form.value.retries === undefined) form.value.retries = 0;
        } else form.value = {
          name: '', targets: '', ports: '22,80,443,3389,445', discoverMode: 'tcp',
          concurrency: 60, timeoutMs: 1200, intervalSec: 3600, retainHours: 72,
          banner: true, enabled: false, status: 'idle', discoveryPorts: '22,80,443,445,3389,5985,8080',
          excludeTargets: '', retries: 0, reverseDns: true, note: ''
        };
      }
      function applyPreset(e) {
        const v = e.target.value;
        if (v) { form.value.ports = v; e.target.value = ''; }
      }
      function quickOpen() {
        qresult.value = null; qadvanced.value = false;
        qform.value = {
          targets: '', ports: '22,80,443,3389,445', discoverMode: 'tcp', concurrency: 60, timeoutMs: 1200,
          banner: true, discoveryPorts: '22,80,443,445,3389,5985,8080', excludeTargets: '',
          retries: 0, reverseDns: true, note: ''
        };
      }
      function applyQuickPreset(e) {
        if (e.target.value) { qform.value.ports = e.target.value; e.target.value = ''; }
      }
      function resetQuick() { qresult.value = null; }
      function viewQuickResult() { qform.value = null; tab.value = 'report'; }
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
            targets: f.targets, ports: f.ports, discoverMode: f.discoverMode, concurrency: f.concurrency,
            timeoutMs: f.timeoutMs, banner: f.banner, discoveryPorts: f.discoveryPorts,
            excludeTargets: f.excludeTargets, retries: f.retries, reverseDns: f.reverseDns, note: f.note
          });
          qresult.value = r;
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
        form, qform, qresult, qadvanced, saving, qrunning, hostFilter, portFilter, ic, go, fmt,
        enabledCount, lastRun, run, riskHosts, riskPorts, modeDesc, qModeDesc, quickPortCount,
        riskColor, modeText, portText, statusText, statusStyle, statusOf, portRisk, showHost,
        loadAll, loadRuns, refreshRunData, edit, applyPreset, quickOpen, applyQuickPreset, resetQuick, viewQuickResult, doQuick,
        save, runTask, toggle, del, exportCsv
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.ScanPage = ScanPage;
  NC.route('/scan', { title: '网络扫描', comp: 'ScanPage' });
})();
