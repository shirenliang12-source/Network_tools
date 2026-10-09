/* =========================================================================
   设备管理 / 设备详情
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, watch, nextTick } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  /* =========================== 设备列表 =========================== */
  const DevicesPage = {
    name: 'DevicesPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="kpi">
        <div class="kpi-card">
          <div class="kpi-icon i-blue" v-html="ic('server')"></div>
          <div><div class="kpi-val">{{ meta.total }}</div><div class="kpi-lbl">纳管设备</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-green" v-html="ic('check')"></div>
          <div><div class="kpi-val" style="color:var(--success)">{{ meta.online }}</div><div class="kpi-lbl">在线</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-red" v-html="ic('alert')"></div>
          <div><div class="kpi-val" style="color:var(--danger)">{{ meta.offline }}</div><div class="kpi-lbl">离线 / 不可达</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-amber" v-html="ic('cpu')"></div>
          <div><div class="kpi-val" :style="{color: meta.avgCpu>=70?'var(--warn)':'var(--text)'}">{{ meta.avgCpu }}<span class="fs13 fw5 muted">%</span></div><div class="kpi-lbl">平均 CPU</div></div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon i-cyan" v-html="ic('layers')"></div>
          <div><div class="kpi-val">{{ meta.avgHealth }}</div><div class="kpi-lbl">平均健康度</div></div>
        </div>
      </div>

      <div class="card">
        <div class="filter-bar">
          <div class="search-box">
            <span v-html="ic('search',15)"></span>
            <input class="inp" v-model.trim="f.keyword" placeholder="设备名 / IP / 型号 / 序列号" @keydown.enter="reload(1)">
          </div>
          <select class="inp" v-model="f.zone" @change="reload(1)"><option value="">全部区域</option><option v-for="z in opts.zones" :key="z">{{ z }}</option></select>
          <select class="inp" v-model="f.vendor" @change="reload(1)"><option value="">全部厂商</option><option v-for="v in opts.vendors" :key="v">{{ v }}</option></select>
          <select class="inp" v-model="f.role" @change="reload(1)"><option value="">全部角色</option><option v-for="r in opts.roles" :key="r">{{ r }}</option></select>
          <select class="inp" v-model="f.status" @change="reload(1)"><option value="">全部状态</option><option value="1">在线</option><option value="0">离线</option></select>
          <button class="btn" @click="reload(1)" v-html="ic('search',15)"></button>
          <button class="btn" @click="reset">重置</button>
          <div class="grow"></div>
          <span class="fs12 muted nowrap">共 {{ total }} 台</span>
          <button class="btn" @click="exportCsv" v-html="ic('download',15)+'<span>导出 CSV</span>'"></button>
          <button class="btn" @click="reload()" v-html="ic('refresh',15)"></button>
        </div>

        <div class="table-wrap">
          <table class="ntable">
            <thead>
              <tr>
                <th class="sortable" @click="sortBy('name')">设备名称 <span v-if="f.sort==='name'">{{ f.order==='asc'?'↑':'↓' }}</span></th>
                <th>管理地址</th>
                <th>厂商 / 型号</th>
                <th>区域</th>
                <th>角色</th>
                <th class="sortable" @click="sortBy('uptimeSec')">运行时长</th>
                <th class="sortable" @click="sortBy('cpu')">CPU</th>
                <th class="sortable" @click="sortBy('mem')">内存</th>
                <th class="sortable" @click="sortBy('temp')">温度</th>
                <th class="sortable" @click="sortBy('health')">健康度</th>
                <th>状态</th>
                <th style="width:190px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="loading"><td colspan="12"><div class="tbl-empty">加载中…</div></td></tr>
              <tr v-else-if="!rows.length"><td colspan="12"><div class="tbl-empty">没有匹配的设备</div></td></tr>
              <tr v-for="h in rows" :key="h.host" @click="detail(h)" style="cursor:pointer">
                <td>
                  <div class="row gap8">
                    <span class="pill" :class="h.status ? 'up' : 'down'" style="height:18px"></span>
                    <div>
                      <div class="fw6">{{ h.name }}</div>
                      <div class="fs11 dim mono">{{ h.host }}</div>
                    </div>
                  </div>
                </td>
                <td class="mono">{{ h.ip }}</td>
                <td>
                  <div>{{ h.vendor }}</div>
                  <div class="fs11 dim">{{ h.model }}</div>
                </td>
                <td><span class="tag">{{ h.zone }}</span></td>
                <td><span class="tag" :class="roleTag(h.role)">{{ h.role }}</span></td>
                <td class="fs12 muted nowrap">{{ fmt.dur(h.uptimeSec) }}</td>
                <td style="min-width:88px"><nc-bar :value="h.cpu" /></td>
                <td style="min-width:88px"><nc-bar :value="h.mem" /></td>
                <td class="mono" :style="{color: h.temp >= 55 ? 'var(--danger)' : h.temp >= 45 ? 'var(--warn)' : ''}">{{ h.temp==null?'-':h.temp+'℃' }}</td>
                <td style="min-width:104px">
                  <div class="row gap8">
                    <span class="mono fw6" :style="{color: h.status ? healthColor(h.health) : 'var(--danger)'}">{{ h.status ? h.health : '-' }}</span>
                    <div class="grow"><div class="bar" style="height:5px"><i :style="{width:(h.status?h.health:0)+'%',background:healthColor(h.health)}"></i></div></div>
                  </div>
                </td>
                <td><span class="pill" :class="h.status ? 'up' : 'down'">{{ h.status ? '在线' : '离线' }}</span></td>
                <td @click.stop>
                  <div class="btn-group">
                    <button class="btn sm" @click="detail(h)">详情</button>
                    <button class="btn sm" @click="openTerm(h)" v-html="ic('terminal',13)+'<span>终端</span>'"></button>
                    <button class="btn sm" @click="edit(h)" v-html="ic('edit',13)"></button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <nc-pager :page="page" :size="f.size" :total="total" @update:page="p => reload(p)" />
      </div>

      <nc-drawer v-if="editing" :title="'编辑设备补充信息 · ' + editing.name" @close="editing=null">
        <div class="form-grid">
          <div><label class="fs12 muted">区域 / 位置</label><input class="inp mt8" v-model="form.zone" placeholder="如：研发楼3F弱电间"></div>
          <div><label class="fs12 muted">设备角色</label>
            <select class="inp mt8" v-model="form.role"><option>核心</option><option>汇聚</option><option>接入</option><option>防火墙</option><option>路由器</option><option>其他</option></select>
          </div>
          <div><label class="fs12 muted">责任人</label><input class="inp mt8" v-model="form.owner" placeholder="责任人姓名"></div>
          <div><label class="fs12 muted">机柜位置</label><input class="inp mt8" v-model="form.rack" placeholder="如：A-12-03"></div>
          <div class="full"><label class="fs12 muted">备注</label><textarea class="inp mt8" rows="3" v-model="form.note"></textarea></div>
        </div>
        <div class="hint-line">补充信息保存在本系统（不写回 Zabbix），用于拓扑分组与责任归属。设备本身名称、IP、型号来自数据源。</div>
        <template #foot>
          <button class="btn" @click="editing=null">取消</button>
          <button class="btn primary" @click="saveInv">保存</button>
        </template>
      </nc-drawer>
    </div>`,
    setup(props) {
      const f = reactive({ keyword: props.query.keyword || '', zone: '', vendor: '', role: '', status: '', sort: 'name', order: 'asc', size: 20 });
      const rows = ref([]), total = ref(0), page = ref(1), loading = ref(true);
      const opts = reactive({ zones: [], vendors: [], roles: [] });
      const meta = reactive({ total: 0, online: 0, offline: 0, avgCpu: 0, avgHealth: 0 });
      const editing = ref(null), form = reactive({});
      const ic = (n) => icon(n);

      const roleTag = (r) => ({ '核心': 'violet', '汇聚': 'blue', '接入': 'green', '防火墙': 'amber' }[r] || '');
      const healthColor = (v) => v >= 80 ? 'var(--success)' : v >= 55 ? 'var(--warn)' : 'var(--danger)';

      async function reload(p) {
        if (p) page.value = p;
        loading.value = true;
        try {
          const q = new URLSearchParams({ ...f, page: page.value, size: f.size });
          const r = await api.get('/devices?' + q);
          rows.value = r.rows; total.value = r.total;
          Object.assign(opts, r.meta);
          meta.total = r.total;
          meta.online = r.rows.filter(h => h.status === 1).length;
          meta.offline = r.rows.length - meta.online;
          const on = r.rows.filter(h => h.status === 1);
          meta.avgCpu = on.length ? (on.reduce((a, h) => a + (Number(h.cpu) || 0), 0) / on.length).toFixed(1) : 0;
          meta.avgHealth = r.rows.length ? Math.round(r.rows.reduce((a, h) => a + h.health, 0) / r.rows.length) : 0;
        } catch (e) { toast('加载设备失败：' + e.message, 'err'); }
        finally { loading.value = false; }
      }
      const sortBy = (k) => { if (f.sort === k) f.order = f.order === 'asc' ? 'desc' : 'asc'; else { f.sort = k; f.order = 'asc'; } reload(); };
      const reset = () => { Object.assign(f, { keyword: '', zone: '', vendor: '', role: '', status: '' }); reload(1); };
      const detail = (h) => go('/device/' + encodeURIComponent(h.host));
      const openTerm = (h) => go('/terminal?host=' + encodeURIComponent(h.host));
      const edit = (h) => {
        editing.value = h;
        Object.assign(form, { zone: h.zone, role: h.role, owner: h.owner, rack: h.rack, note: h.note });
      };
      const saveInv = async () => {
        try {
          await api.post(`/devices/${encodeURIComponent(editing.value.host)}/inventory`, { ...form });
          toast('设备信息已更新', 'ok');
          editing.value = null; reload();
        } catch (e) { toast(e.message, 'err'); }
      };
      const exportCsv = () => { NC.setTokenToken || 0; window.open('/api/devices/export?token=' + encodeURIComponent(NC.state.token)); };

      onMounted(() => reload(1));
      watch(() => props.query.keyword, v => { if (v !== undefined) { f.keyword = v; reload(1); } });
      return { f, rows, total, page, loading, opts, meta, editing, form, reload, sortBy, reset, detail, openTerm, edit, saveInv, exportCsv, ic, roleTag, healthColor, fmt, go };
    }
  };

  /* =========================== 设备详情 =========================== */
  const DeviceDetailPage = {
    name: 'DeviceDetailPage',
    props: { params: Object },
    template: `
    <div class="col gap16" v-if="host">
      <div class="card">
        <div class="card-body">
          <div class="row gap16" style="flex-wrap:wrap">
            <div class="grow" style="min-width:320px">
              <div class="row gap12">
                <button class="icon-btn" @click="go('/devices')" v-html="ic('menu',16)"></button>
                <div>
                  <div class="row gap8">
                    <span class="fs17 fw7">{{ host.name }}</span>
                    <span class="pill" :class="host.status ? 'up' : 'down'">{{ host.status ? '在线' : '离线' }}</span>
                    <span class="tag" :class="roleTag(host.role)">{{ host.role }}</span>
                    <span class="tag">{{ host.zone }}</span>
                  </div>
                  <div class="fs12 muted mt8 mono">{{ host.host }} · {{ host.ip }} · {{ host.vendor }} {{ host.model }}</div>
                </div>
              </div>
              <div class="grid mt16" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
                <div><div class="fs11 dim">系统版本</div><div class="fs13 mono">{{ host.os || '-' }}</div></div>
                <div><div class="fs11 dim">序列号</div><div class="fs13 mono">{{ host.serial || '-' }}</div></div>
                <div><div class="fs11 dim">运行时长</div><div class="fs13">{{ fmt.dur(host.uptimeSec) }}</div></div>
                <div><div class="fs11 dim">责任 / 机柜</div><div class="fs13">{{ host.owner || '-' }} / {{ host.rack || '-' }}</div></div>
              </div>
              <div v-if="host.error" class="mt12" style="color:var(--danger);font-size:12.5px">采集异常：{{ host.error }}</div>
            </div>
            <div class="row gap16" style="align-items:center">
              <nc-gauge :value="host.cpu" label="CPU" :warn="70" :danger="85" />
              <nc-gauge :value="host.mem" label="内存" :warn="75" :danger="90" />
              <nc-gauge :value="host.temp" :max="100" unit="℃" label="进风温度" :warn="50" :danger="65" />
              <div class="col" style="align-items:center">
                <div class="gauge">
                  <svg width="78" height="78" viewBox="0 0 80 80" style="transform:rotate(-90deg)">
                    <circle class="g-bg" cx="40" cy="40" r="32" fill="none" stroke-width="7"/>
                    <circle class="g-fg" cx="40" cy="40" r="32" fill="none" stroke-width="7" stroke-linecap="round"
                      :stroke="healthColor(host.health)" :stroke-dasharray="201" :stroke-dashoffset="201*(1-host.health/100)"/>
                  </svg>
                  <div class="g-txt"><div class="g-val" :style="{color:healthColor(host.health)}">{{ host.health }}</div><div class="g-unit">健康度</div></div>
                </div>
                <div class="fs12 muted">综合健康度</div>
              </div>
              <div class="btn-group col" style="gap:8px">
                <button class="btn" @click="openTerm" v-html="ic('terminal',15)+'<span>打开终端</span>'"></button>
                <button class="btn" @click="go('/devices')" v-html="ic('list',15)+'<span>返回列表</span>'"></button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="kpi">
        <div class="kpi-card"><div class="kpi-icon i-green" v-html="ic('link')"></div><div><div class="kpi-val">{{ sum.up }}</div><div class="kpi-lbl">UP 端口</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-red" v-html="ic('close')"></div><div><div class="kpi-val">{{ sum.down }}</div><div class="kpi-lbl">DOWN 端口</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-amber" v-html="ic('alert')"></div><div><div class="kpi-val">{{ sum.errTotal }}</div><div class="kpi-lbl">累计错包</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-blue" v-html="ic('download')"></div><div><div class="kpi-val fs20">{{ fmt.bps(sum.inTotal) }}</div><div class="kpi-lbl">入向总带宽</div></div></div>
        <div class="kpi-card"><div class="kpi-icon i-cyan" v-html="ic('upload')"></div><div><div class="kpi-val fs20">{{ fmt.bps(sum.outTotal) }}</div><div class="kpi-lbl">出向总带宽</div></div></div>
      </div>

      <div class="card">
        <div class="tabs">
          <div class="tab" :class="{on: tab==='ports'}" @click="tab='ports'">端口状态 <span class="cnt">{{ ports.length }}</span></div>
          <div class="tab" :class="{on: tab==='traffic'}" @click="tab='traffic';loadHistory('traffic')">流量趋势</div>
          <div class="tab" :class="{on: tab==='res'}" @click="tab='res';loadHistory('res')">资源历史</div>
          <div class="tab" :class="{on: tab==='info'}" @click="tab='info'">设备信息</div>
        </div>

        <!-- 端口状态 -->
        <div v-show="tab==='ports'">
          <div class="filter-bar">
            <div class="search-box"><span v-html="ic('search',15)"></span><input class="inp" v-model.trim="pk" placeholder="端口名 / 描述 / VLAN"></div>
            <select class="inp" v-model="pState"><option value="">全部状态</option><option value="up">仅 UP</option><option value="down">仅 DOWN</option><option value="err">仅有错包</option></select>
            <select class="inp" v-model="pMode"><option value="">全部模式</option><option>Access</option><option>Trunk</option><option>Hybrid</option></select>
            <label class="checkbox fs12"><input type="checkbox" v-model="onlyTop"> 只看流量 Top 20</label>
            <div class="grow"></div>
            <span class="fs12 muted">{{ shownPorts.length }} / {{ ports.length }} 个端口</span>
            <button class="btn" @click="exportPorts" v-html="ic('download',15)+'<span>导出</span>'"></button>
          </div>
          <div class="table-wrap" style="max-height:640px">
            <table class="ntable">
              <thead>
                <tr>
                  <th>端口</th><th>描述</th><th>状态</th><th>速率 / 双工</th><th>模式</th><th>VLAN</th>
                  <th style="min-width:150px">入向流量</th><th style="min-width:150px">出向流量</th>
                  <th>入包速率</th><th>出包速率</th><th>错包</th><th>PoE</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="!shownPorts.length"><td colspan="12"><div class="tbl-empty">没有匹配的端口</div></td></tr>
                <tr v-for="p in shownPorts" :key="p.index" :class="{sel: p.operStatus!==1}">
                  <td class="mono fw5 nowrap">{{ p.name }}</td>
                  <td class="fs12">{{ p.alias || '-' }}</td>
                  <td><span class="pill" :class="p.operStatus===1 ? 'up' : 'down'">{{ p.operStatus===1 ? 'UP' : 'DOWN' }}</span></td>
                  <td class="fs12 nowrap">{{ p.speedMbps ? (p.speedMbps>=1000 ? (p.speedMbps/1000)+'G' : p.speedMbps+'M') : '-' }} / {{ p.duplex }}</td>
                  <td><span class="tag" :class="p.mode==='Trunk'?'blue':p.mode==='Hybrid'?'violet':''">{{ p.mode }}</span></td>
                  <td class="mono fs12">{{ p.pvid && p.pvid!=='-' ? p.pvid : p.vlan }}</td>
                  <td>
                    <div class="row gap8">
                      <span class="mono nowrap fs12" style="min-width:74px">{{ fmt.bps(p.inBps) }}</span>
                      <div class="grow"><div class="bar" style="height:5px"><i :style="{width:barW(p.inBps, p.speedMbps), background:'linear-gradient(90deg,#2563eb,#22d3ee)'}"></i></div></div>
                    </div>
                  </td>
                  <td>
                    <div class="row gap8">
                      <span class="mono nowrap fs12" style="min-width:74px">{{ fmt.bps(p.outBps) }}</span>
                      <div class="grow"><div class="bar" style="height:5px"><i :style="{width:barW(p.outBps, p.speedMbps), background:'linear-gradient(90deg,#7c3aed,#22d3ee)'}"></i></div></div>
                    </div>
                  </td>
                  <td class="mono fs12">{{ fmt.num(p.inPps) }}</td>
                  <td class="mono fs12">{{ fmt.num(p.outPps) }}</td>
                  <td>
                    <span v-if="(p.inErrors+p.outErrors+(p.crcErrors||0))>0" class="tag red mono">{{ p.inErrors+p.outErrors+(p.crcErrors||0) }}</span>
                    <span v-else class="dim fs12">0</span>
                  </td>
                  <td class="fs12">{{ p.poe ? (p.poe/1000).toFixed(1)+'W' : '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 流量趋势 -->
        <div v-show="tab==='traffic'" class="card-body">
          <div class="row-between mb12">
            <div class="fs13 fw6">端口流量趋势（{{ host.name }}）</div>
            <div class="btn-group">
              <button v-for="r in ['1h','6h','24h','7d']" :key="r" class="btn sm" :class="{primary: range===r}" @click="range=r;loadHistory('traffic')">{{ r }}</button>
            </div>
          </div>
          <nc-chart :option="optTraffic" height="320px" />
          <div class="divider"></div>
          <div class="fs13 fw6 mb12">流量 Top 端口</div>
          <nc-chart :option="optTopPorts" height="240px" />
        </div>

        <!-- 资源历史 -->
        <div v-show="tab==='res'" class="card-body">
          <div class="row-between mb12">
            <div class="fs13 fw6">CPU / 内存 / 温度 趋势</div>
            <div class="btn-group">
              <button v-for="r in ['1h','6h','24h','7d']" :key="r" class="btn sm" :class="{primary: range===r}" @click="range=r;loadHistory('res')">{{ r }}</button>
            </div>
          </div>
          <nc-chart :option="optRes" height="340px" />
        </div>

        <!-- 设备信息 -->
        <div v-show="tab==='info'" class="card-body">
          <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">
            <div>
              <div class="fs13 fw6 mb12">基础信息</div>
              <div class="d-row" v-for="kv in infoRows" :key="kv[0]" style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">
                <span class="muted fs12">{{ kv[0] }}</span><span class="mono fs12">{{ kv[1] || '-' }}</span>
              </div>
            </div>
            <div>
              <div class="fs13 fw6 mb12">硬件状态</div>
              <div v-for="f in det.fans || []" :key="f.name" class="row-between" style="padding:7px 0;border-bottom:1px solid var(--border)">
                <span class="row gap8"><span v-html="ic('wind',15)"></span><span class="fs13">风扇 {{ f.name }}</span></span>
                <span class="row gap8"><span class="mono fs12">{{ f.rpm }} RPM</span><span class="pill" :class="f.status==='normal'?'up':'warn'">{{ f.status==='normal'?'正常':'异常' }}</span></span>
              </div>
              <div v-for="p in det.psus || []" :key="p.name" class="row-between" style="padding:7px 0;border-bottom:1px solid var(--border)">
                <span class="row gap8"><span v-html="ic('power',15)"></span><span class="fs13">电源 {{ p.name }}</span></span>
                <span class="row gap8"><span class="mono fs12">{{ p.watts }} W</span><span class="pill" :class="p.status==='normal'?'up':'down'">{{ p.status==='normal'?'正常':'故障' }}</span></span>
              </div>
              <div class="hint-line mt12">硬件状态来自数据源监控项；演示模式为模拟值。接入真机后由 Zabbix 的硬件监控项驱动。</div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div v-else class="empty" style="padding-top:120px">加载中…</div>`,
    setup(props) {
      const host = ref(null), ports = ref([]), det = reactive({});
      const sum = reactive({ up: 0, down: 0, errTotal: 0, inTotal: 0, outTotal: 0 });
      const tab = ref('ports'), range = ref('24h');
      const pk = ref(''), pState = ref(''), pMode = ref(''), onlyTop = ref(false);
      const hist = reactive({ traffic: [], cpu: [], mem: [], temp: [] });
      const ic = (n) => icon(n);
      const hostName = () => props.params.host;
      const roleTag = (r) => ({ '核心': 'violet', '汇聚': 'blue', '接入': 'green', '防火墙': 'amber' }[r] || '');
      const healthColor = (v) => v >= 80 ? 'var(--success)' : v >= 55 ? 'var(--warn)' : 'var(--danger)';
      const barW = (v, sp) => Math.min(100, (Number(v) || 0) / ((sp || 1000) * 1e6) * 100) + '%';
      const openTerm = () => go('/terminal?host=' + encodeURIComponent(host.value.host));

      const shownPorts = computed(() => {
        let list = ports.value;
        if (pk.value) { const k = pk.value.toLowerCase(); list = list.filter(p => (p.name + ' ' + (p.alias || '') + ' ' + p.vlan).toLowerCase().includes(k)); }
        if (pState.value === 'up') list = list.filter(p => p.operStatus === 1);
        if (pState.value === 'down') list = list.filter(p => p.operStatus !== 1);
        if (pState.value === 'err') list = list.filter(p => (p.inErrors + p.outErrors + (p.crcErrors || 0)) > 0);
        if (pMode.value) list = list.filter(p => p.mode === pMode.value);
        if (onlyTop.value) list = [...list].sort((a, b) => (b.inBps + b.outBps) - (a.inBps + a.outBps)).slice(0, 20);
        return list;
      });
      const infoRows = computed(() => {
        const h = host.value; if (!h) return [];
        return [['设备标识 HostID', h.hostid], ['设备名', h.name], ['管理地址', h.ip], ['厂商', h.vendor], ['型号', h.model], ['系统版本', h.os],
          ['序列号', h.serial], ['区域', h.zone], ['角色', h.role], ['责任人', h.owner], ['机柜', h.rack], ['运行时长', fmt.dur(h.uptimeSec)],
          ['端口总数', ports.value.length], ['备注', h.note]];
      });

      const optTraffic = computed(() => {
        const b = NC.chartBase(false);
        const d = hist.traffic || [];
        const labels = d.map(p => fmt.timeShort(p.ts));
        return {
          ...b, grid: { left: 10, right: 16, top: 34, bottom: 4, containLabel: true },
          xAxis: { type: 'category', data: labels, boundaryGap: false, ...NC.AXIS(false), axisLabel: { color: '#93a2b5', fontSize: 11, interval: Math.ceil(labels.length / 8) } },
          yAxis: { type: 'value', ...NC.SPLIT(false), axisLabel: { color: '#93a2b5', fontSize: 11, formatter: v => (v / 1e6).toFixed(0) + 'M' } },
          series: [{
            name: '总流量', type: 'line', smooth: true, symbol: 'none', data: d.map(p => p.value),
            lineStyle: { width: 2.4, color: '#2563eb' },
            areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(37,99,235,.32)' }, { offset: 1, color: 'rgba(37,99,235,0)' }]) }
          }]
        };
      });
      const optTopPorts = computed(() => {
        const top = [...ports.value].sort((a, b) => (b.inBps + b.outBps) - (a.inBps + a.outBps)).slice(0, 10).reverse();
        const b = NC.chartBase(false);
        return {
          ...b, grid: { left: 10, right: 60, top: 30, bottom: 4, containLabel: true },
          legend: { ...b.legend },
          xAxis: { type: 'value', ...NC.SPLIT(false), axisLabel: { color: '#93a2b5', fontSize: 11, formatter: v => (v / 1e6).toFixed(0) + 'M' } },
          yAxis: { type: 'category', data: top.map(p => p.name), axisLine: { lineStyle: { color: '#e2e8f1' } }, axisTick: { show: false }, axisLabel: { color: '#5a6a80', fontSize: 11 } },
          series: [
            { name: '入向', type: 'bar', stack: 'x', data: top.map(p => p.inBps), itemStyle: { color: '#2563eb', borderRadius: [4, 0, 0, 4] }, barWidth: 11 },
            { name: '出向', type: 'bar', stack: 'x', data: top.map(p => p.outBps), itemStyle: { color: '#22d3ee', borderRadius: [0, 4, 4, 0] },
              label: { show: true, position: 'right', fontSize: 10, color: '#5a6a80', formatter: p => fmt.bps(top[p.dataIndex].inBps + top[p.dataIndex].outBps) } }
          ]
        };
      });
      const optRes = computed(() => {
        const b = NC.chartBase(false);
        const mk = (name, arr, color) => ({
          name, type: 'line', smooth: true, symbol: 'none', data: (arr || []).map(p => p.value),
          lineStyle: { width: 2, color }, itemStyle: { color }
        });
        const labels = (hist.cpu || []).map(p => fmt.timeShort(p.ts));
        return {
          ...b, grid: { left: 10, right: 16, top: 34, bottom: 4, containLabel: true },
          xAxis: { type: 'category', data: labels, boundaryGap: false, ...NC.AXIS(false), axisLabel: { color: '#93a2b5', fontSize: 11, interval: Math.ceil(labels.length / 8) } },
          yAxis: { type: 'value', ...NC.SPLIT(false), axisLabel: { color: '#93a2b5', fontSize: 11, formatter: '{value}' } },
          series: [mk('CPU %', hist.cpu, '#2563eb'), mk('内存 %', hist.mem, '#7c3aed'), mk('温度 ℃', hist.temp, '#d97706')]
        };
      });

      async function load() {
        try {
          const r = await api.get('/devices/' + encodeURIComponent(hostName()));
          host.value = r.host; ports.value = r.ports;
          Object.assign(sum, r.summary);
          Object.assign(det, { fans: [], psus: [] });
          try {
            const h = await api.get(`/devices/${encodeURIComponent(hostName())}/history?kind=cpu,mem,temp&range=24h`);
            Object.assign(hist, h.data);
          } catch (e) { }
        } catch (e) { toast('加载设备详情失败：' + e.message, 'err'); }
      }
      async function loadHistory(kind) {
        try {
          const kinds = kind === 'res' ? 'cpu,mem,temp' : 'traffic';
          const h = await api.get(`/devices/${encodeURIComponent(hostName())}/history?kind=${kinds}&range=${range.value}`);
          Object.assign(hist, h.data);
        } catch (e) { toast(e.message, 'err'); }
      }
      const exportPorts = () => {
        const head = ['端口', '描述', '状态', '速率Mbps', '模式', 'VLAN', '入向bps', '出向bps', '错包'];
        const rows = shownPorts.value.map(p => [p.name, p.alias, p.operStatus === 1 ? 'UP' : 'DOWN', p.speedMbps, p.mode, p.vlan, p.inBps, p.outBps, p.inErrors + p.outErrors + (p.crcErrors || 0)]);
        const csv = '\ufeff' + [head, ...rows].map(r => r.map(c => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',')).join('\r\n');
        const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
        const a = document.createElement('a'); a.href = url; a.download = `${hostName()}-ports.csv`; a.click(); URL.revokeObjectURL(url);
      };
      onMounted(load);
      return { host, ports, det, sum, tab, range, pk, pState, pMode, onlyTop, hist, shownPorts, infoRows, optTraffic, optTopPorts, optRes, loadHistory, exportPorts, ic, roleTag, healthColor, barW, openTerm, go, fmt };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.DevicesPage = DevicesPage;
  window.PAGES.DeviceDetailPage = DeviceDetailPage;
  NC.route('/devices', { title: '设备管理', comp: 'DevicesPage' });
  NC.route('/device/:host', { title: '设备详情', comp: 'DeviceDetailPage' });
})();
