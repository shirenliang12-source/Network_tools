/* =========================================================================
 * 深度排障工具（#71）
 *   1) 端口错包钻取   —— 拉端口计数器 + 基线差值，定位 CRC/错包/丢弃/双工 根因
 *   2) MTR 路径分析   —— 逐跳探测，定位瓶颈跳与丢包跳，产出延迟/丢包双图表
 *   3) PCAP 关联分析  —— 对抓包文件按 主机/端口 过滤，钻取重传/握手/HTTP·DNS 异常
 * 数据：/api/deep/port-error · /api/deep/mtr · /api/deep/pcap
 * ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted } = Vue;
  const NC = window.NC, { api, fmt, icon, toast } = NC;

  const SEV = {
    none:   { t: '无', c: '#16a34a' },
    low:    { t: '低', c: '#d97706' },
    medium: { t: '中', c: '#ea580c' },
    high:   { t: '高', c: '#dc2626' }
  };
  const HEALTH = {
    good:    { t: '路径健康', c: '#16a34a' },
    warn:    { t: '轻微异常', c: '#d97706' },
    bad:     { t: '明显异常', c: '#dc2626' },
    unknown: { t: '不可用',   c: '#64748b' }
  };
  const CONF = { high: '#16a34a', medium: '#d97706', low: '#64748b' };

  const DeepToolsPage = {
    name: 'DeepToolsPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="tabs">
        <div v-for="t in TABS" :key="t.k" class="tab" :class="{on: tab===t.k}" @click="tab=t.k">
          <span v-html="ic(t.i,14)"></span><span style="margin-left:5px">{{ t.n }}</span>
        </div>
      </div>

      <!-- 1) 端口错包钻取 -->
      <div v-if="tab==='port'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('filter',15)"></span><span>端口错包钻取</span>
            <div class="grow"></div>
            <button class="btn sm" @click="refreshDevices" v-html="ic('refresh',14)"></button>
          </div>
          <div class="row gap12 wrap">
            <select class="ipt" v-model="pe.host" @change="onHostChange" style="min-width:240px">
              <option value="">— 选择设备 —</option>
              <option v-for="h in (devices||[])" :key="h.host" :value="h.host">{{ h.name }} ({{ h.ip }})</option>
            </select>
            <select class="ipt" v-model="pe.port" style="min-width:220px">
              <option value="">— 选择端口 —</option>
              <option v-for="p in (ports||[])" :key="p.name" :value="p.name">{{ p.name }}<template v-if="p.alias"> · {{ p.alias }}</template></option>
            </select>
            <button class="btn primary" :disabled="!pe.host||!pe.port||pe.loading" @click="runPe" v-html="ic('search',14)+'<span>钻取</span>'"></button>
            <button class="btn" :disabled="!pe.host||!pe.port||pe.loading" @click="baseline" v-html="ic('save',14)+'<span>打基线</span>'"></button>
            <span class="fs12 muted" v-if="pe.loading">采集端口计数器…</span>
            <span class="fs12" v-else-if="pe.err" style="color:var(--danger)">{{ pe.err }}</span>
          </div>

          <div v-if="pe.data" class="col gap14 mt12">
            <div class="row gap16 items-center">
              <NcGauge :value="pe.data.health" :max="100" label="健康度" :warn="70" :danger="85"></NcGauge>
              <div class="col gap4">
                <div class="row gap8 items-center">
                  <span class="sev-tag" :style="sevStyle(pe.data.severity)">{{ sevText(pe.data.severity) }}</span>
                  <span class="fs13 muted">累计增量 {{ fmt.num(pe.data.totalDelta) }} 计数</span>
                </div>
                <div class="fs13">{{ pe.data.summary }}</div>
                <div class="fs11 muted">
                  <template v-if="pe.data.hasBaseline">基线时间：{{ fmt.time(pe.data.baselineAt) }}</template>
                  <template v-else>未打基线（建议先「打基线」再间隔一段时间钻取，可得准确增量）</template>
                </div>
              </div>
            </div>

            <div class="tbl">
              <table>
                <thead><tr><th>计数器</th><th>层级</th><th class="r">当前值</th><th class="r">基线</th><th class="r">增量</th><th>严重度</th></tr></thead>
                <tbody>
                  <tr v-for="r in (pe.data.counters||[])" :key="r.key">
                    <td><b>{{ r.label }}</b><div class="fs11 muted">{{ r.key }}</div></td>
                    <td><span class="tag">{{ r.layer }}</span></td>
                    <td class="r">{{ fmt.num(r.current) }}</td>
                    <td class="r">{{ r.baseline==null?'—':fmt.num(r.baseline) }}</td>
                    <td class="r" :style="{color: r.delta>0?'var(--danger)':'inherit',fontWeight: r.delta>0?'600':'normal'}">{{ r.delta>0?('+'+fmt.num(r.delta)):fmt.num(r.delta) }}</td>
                    <td><span class="sev-tag" :style="sevStyle(r.severity)">{{ sevText(r.severity) }}</span></td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div class="grid" style="grid-template-columns:1fr 1fr;gap:16px">
              <div class="card sm"><div class="card-head"><span v-html="ic('alert',14)"></span><span>可能根因</span></div>
                <ul class="disc">
                  <li v-for="(c,i) in (pe.data.causes||[])" :key="i" class="mb6"><b>{{ c.area }}</b>：{{ c.prob }}
                    <span class="tag" :style="{color: confColor(c.confidence),borderColor: confColor(c.confidence)}">置信度 {{ c.confidence }}</span></li>
                </ul></div>
              <div class="card sm"><div class="card-head"><span v-html="ic('check',14)"></span><span>处置建议</span></div>
                <ol class="dec">
                  <li v-for="(t,i) in (pe.data.recommendations||[])" :key="i" class="mb6">{{ t }}</li>
                </ol></div>
            </div>
          </div>
          <div v-else-if="!pe.loading && !pe.err" class="ts-empty">
            <div v-html="ic('filter',36)"></div>
            <div class="fs13 muted mt8">选择设备与端口 → 点击「钻取」分析错包根因；先「打基线」可得到准确增量对比</div>
          </div>
        </div>
      </div>

      <!-- 2) MTR 路径分析 -->
      <div v-if="tab==='mtr'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('link',15)"></span><span>MTR 路径分析</span></div>
          <div class="row gap12 wrap">
            <input class="ipt" v-model.trim="mtr.target" placeholder="目标 IP / 域名，如 10.252.28.1 或 www.baidu.com" style="min-width:300px">
            <input class="ipt" style="max-width:90px" v-model.number="mtr.maxHops" placeholder="最大跳数">
            <input class="ipt" style="max-width:90px" v-model.number="mtr.rounds" placeholder="轮数">
            <button class="btn primary" :disabled="!mtr.target||mtr.loading" @click="runMtr" v-html="ic('play',14)+'<span>开始探测</span>'"></button>
            <span class="fs12 muted" v-if="mtr.loading">逐跳探测中…</span>
            <span class="fs12" v-else-if="mtr.err" style="color:var(--danger)">{{ mtr.err }}</span>
          </div>

          <div v-if="mtr.data" class="col gap14 mt12">
            <div class="row gap8 items-center wrap">
              <span class="sev-tag" :style="healthStyle(mtr.data.diagnosis.health)">{{ healthText(mtr.data.diagnosis.health) }}</span>
              <b>{{ mtr.data.target }}</b>
              <span class="muted" v-if="mtr.data.ip">{{ mtr.data.ip }}</span>
              <span class="fs11 muted">{{ mtr.data.hopCount }} 跳</span>
            </div>
            <div class="fs13">{{ mtr.data.diagnosis.summary }}</div>
            <div v-if="mtr.data.charts">
              <NcChart :option="latOption" height="260px"></NcChart>
              <NcChart :option="lossOption" height="200px" class="mt8"></NcChart>
            </div>
            <div class="tbl">
              <table>
                <thead><tr><th class="r">跳</th><th>IP / 主机</th><th class="r">丢包%</th><th class="r">最小</th><th class="r">平均</th><th class="r">最大</th><th class="r">抖动</th></tr></thead>
                <tbody>
                  <tr v-for="h in (mtr.data.hops||[])" :key="h.ttl">
                    <td class="r">{{ h.ttl }}</td>
                    <td>{{ h.ip || '—' }}</td>
                    <td class="r" :style="{color: h.loss>0?'var(--danger)':'inherit'}">{{ h.loss||0 }}</td>
                    <td class="r">{{ h.min!=null?h.min+'ms':'—' }}</td>
                    <td class="r">{{ h.avg!=null?h.avg+'ms':'—' }}</td>
                    <td class="r">{{ h.max!=null?h.max+'ms':'—' }}</td>
                    <td class="r">{{ h.jitter||0 }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <div v-else-if="!mtr.loading && !mtr.err" class="ts-empty">
            <div v-html="ic('link',36)"></div>
            <div class="fs13 muted mt8">输入目标地址，逐跳定位瓶颈跳与丢包跳（沙箱无 traceroute 时会优雅返回不可用）</div>
          </div>
        </div>
      </div>

      <!-- 3) PCAP 关联分析 -->
      <div v-if="tab==='pcap'" class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('camera',15)"></span><span>PCAP 关联分析</span>
            <div class="grow"></div>
            <button class="btn sm" @click="refreshCaps" v-html="ic('refresh',14)"></button>
          </div>
          <div class="row gap12 wrap">
            <select class="ipt" v-model="pc.file" style="min-width:300px">
              <option value="">— 选择抓包文件 —</option>
              <option v-for="c in (caps||[])" :key="c.file" :value="c.file">{{ c.file }} · {{ fmt.bytes(c.size||0) }} · {{ fmt.timeShort(c.at) }}</option>
            </select>
            <input class="ipt" v-model.trim="pc.host" placeholder="按主机 IP 过滤（可选）">
            <input class="ipt" v-model.trim="pc.port" placeholder="按端口过滤（可选）">
            <button class="btn primary" :disabled="!pc.file||pc.loading" @click="runPcap" v-html="ic('search',14)+'<span>分析</span>'"></button>
            <span class="fs12 muted" v-if="pc.loading">解析 PCAP 中…</span>
            <span class="fs12" v-else-if="pc.err" style="color:var(--danger)">{{ pc.err }}</span>
          </div>

          <div v-if="pc.data" class="col gap14 mt12">
            <div class="kpi">
              <div class="kpi-card"><div class="kpi-val">{{ fmt.num(pc.data.matchedSessions) }}</div><div class="kpi-lbl">匹配会话</div></div>
              <div class="kpi-card"><div class="kpi-val" :style="{color: pc.data.kpi.retransRate>1?'var(--danger)':'inherit'}">{{ fmt.pct(pc.data.kpi.retransRate) }}</div><div class="kpi-lbl">重传率</div></div>
              <div class="kpi-card"><div class="kpi-val">{{ fmt.num(pc.data.kpi.retransSegments) }}</div><div class="kpi-lbl">重传段</div></div>
              <div class="kpi-card"><div class="kpi-val">{{ fmt.num(pc.data.kpi.avgHandshakeMs) }}ms</div><div class="kpi-lbl">平均握手</div></div>
              <div class="kpi-card"><div class="kpi-val">{{ fmt.num(pc.data.kpi.avgHttpRespMs) }}ms</div><div class="kpi-lbl">平均HTTP响应</div></div>
              <div class="kpi-card"><div class="kpi-val">{{ fmt.num(pc.data.kpi.avgDnsRespMs) }}ms</div><div class="kpi-lbl">平均DNS响应</div></div>
            </div>
            <div class="fs13 muted">{{ pc.data.summary }}</div>
            <div class="tbl">
              <table>
                <thead><tr><th>源</th><th>目的</th><th>应用</th><th class="r">字节</th><th class="r">重传</th><th>RST</th><th class="r">握手</th><th class="r">HTTP响应</th><th class="r">DNS响应</th></tr></thead>
                <tbody>
                  <tr v-for="(s,i) in (pc.data.problemSessions||[])" :key="i">
                    <td>{{ s.srcIp }}:{{ s.srcPort }}</td>
                    <td>{{ s.dstIp }}:{{ s.dstPort }}</td>
                    <td><span class="tag">{{ s.appProto||s.proto }}</span></td>
                    <td class="r">{{ fmt.bytes(s.bytes) }}</td>
                    <td class="r" :style="{color: s.retrans>0?'var(--danger)':'inherit'}">{{ s.retrans||0 }}</td>
                    <td>{{ s.rst?'是':'—' }}</td>
                    <td class="r">{{ s.handshakeMs?fmt.num(s.handshakeMs)+'ms':'—' }}</td>
                    <td class="r" :style="{color: s.httpRespMs>800?'var(--danger)':'inherit'}">{{ s.httpRespMs?fmt.num(s.httpRespMs)+'ms':'—' }}</td>
                    <td class="r" :style="{color: s.dnsRespMs>500?'var(--danger)':'inherit'}">{{ s.dnsRespMs?fmt.num(s.dnsRespMs)+'ms':'—' }}</td>
                  </tr>
                </tbody>
              </table>
              <div v-if="!(pc.data.problemSessions||[]).length" class="tbl-empty">该范围内未检出明显问题会话</div>
            </div>
          </div>
          <div v-else-if="!pc.loading && !pc.err" class="ts-empty">
            <div v-html="ic('camera',36)"></div>
            <div class="fs13 muted mt8">选择抓包文件，可按主机/端口过滤，钻取重传/握手/HTTP·DNS 异常会话</div>
          </div>
        </div>
      </div>
    </div>`,

    setup() {
      const ic = (n, s) => icon(n, s);
      const TABS = [
        { k: 'port', n: '端口错包钻取', i: 'filter' },
        { k: 'mtr', n: 'MTR 路径分析', i: 'link' },
        { k: 'pcap', n: 'PCAP 关联分析', i: 'camera' }
      ];
      const tab = ref('port');

      const devices = ref([]);
      const ports = ref([]);
      const caps = ref([]);

      const pe = reactive({ host: '', port: '', loading: false, err: '', data: null });
      const mtr = reactive({ target: '', maxHops: 20, rounds: 3, loading: false, err: '', data: null });
      const pc = reactive({ file: '', host: '', port: '', loading: false, err: '', data: null });

      const sevStyle = s => `color:${SEV[s] ? SEV[s].c : '#64748b'}`;
      const sevText = s => SEV[s] ? SEV[s].t : (s || '—');
      const confColor = c => CONF[c] || '#64748b';
      const healthStyle = h => `color:${HEALTH[h] ? HEALTH[h].c : '#64748b'}`;
      const healthText = h => HEALTH[h] ? HEALTH[h].t : (h || '—');

      async function refreshDevices() {
        try { const d = await api.get('/devices?size=200'); devices.value = (d && d.rows) || []; }
        catch (e) { toast('获取设备列表失败：' + e.message, 'err'); }
      }
      async function refreshCaps() {
        try { const d = await api.get('/capture/list'); caps.value = (d && d.rows) || []; }
        catch (e) { toast('获取抓包列表失败：' + e.message, 'err'); }
      }
      async function onHostChange() {
        ports.value = [];
        pe.port = '';
        if (!pe.host) return;
        try {
          const d = await api.get('/devices/' + encodeURIComponent(pe.host) + '/ports');
          ports.value = (d && d.ports) || [];
        } catch (e) { toast('获取端口失败：' + e.message, 'err'); }
      }

      async function runPe() {
        if (!pe.host || !pe.port) return;
        pe.loading = true; pe.err = ''; pe.data = null;
        try {
          const d = await api.post('/deep/port-error', { host: pe.host, port: pe.port });
          pe.data = d;
        } catch (e) { pe.err = e.message || '钻取失败'; }
        finally { pe.loading = false; }
      }
      async function baseline() {
        if (!pe.host || !pe.port) return;
        try {
          const d = await api.post('/deep/port-error/baseline', { host: pe.host, port: pe.port });
          toast(`已记录 ${pe.host} ${pe.port} 基线（${fmt.time(d.at)}）`, 'ok');
        } catch (e) { toast('打基线失败：' + e.message, 'err'); }
      }

      async function runMtr() {
        if (!mtr.target) return;
        mtr.loading = true; mtr.err = ''; mtr.data = null;
        try {
          const d = await api.post('/deep/mtr', { target: mtr.target, maxHops: Number(mtr.maxHops) || 20, rounds: Number(mtr.rounds) || 3 });
          if (!d.ok || !d.hops) { mtr.err = d.error || 'MTR 执行失败'; mtr.data = null; }
          else mtr.data = d;
        } catch (e) { mtr.err = e.message || '探测失败'; }
        finally { mtr.loading = false; }
      }

      async function runPcap() {
        if (!pc.file) return;
        pc.loading = true; pc.err = ''; pc.data = null;
        try {
          const d = await api.post('/deep/pcap', { file: pc.file, host: pc.host || '', port: pc.port || '' });
          if (!d.ok) { pc.err = d.error || '分析失败'; pc.data = null; }
          else pc.data = d;
        } catch (e) { pc.err = e.message || '分析失败'; }
        finally { pc.loading = false; }
      }

      const latOption = computed(() => {
        const c = mtr.data && mtr.data.charts && mtr.data.charts.latency;
        if (!c) return null;
        return {
          tooltip: { trigger: 'axis' },
          legend: { data: ['最小', '平均', '最大'] },
          grid: { left: 48, right: 16, top: 36, bottom: 64 },
          xAxis: { type: 'category', data: c.categories, axisLabel: { rotate: 30, fontSize: 10 } },
          yAxis: { type: 'value', name: 'ms' },
          series: [
            { name: '最小', type: 'line', data: c.min, itemStyle: { color: '#16a34a' }, symbolSize: 5 },
            { name: '平均', type: 'line', data: c.avg, itemStyle: { color: '#2563eb' }, symbolSize: 5 },
            { name: '最大', type: 'line', data: c.max, itemStyle: { color: '#dc2626' }, symbolSize: 5 }
          ]
        };
      });
      const lossOption = computed(() => {
        const c = mtr.data && mtr.data.charts && mtr.data.charts.loss;
        if (!c) return null;
        return {
          tooltip: { trigger: 'axis' },
          grid: { left: 48, right: 16, top: 18, bottom: 64 },
          xAxis: { type: 'category', data: c.categories, axisLabel: { rotate: 30, fontSize: 10 } },
          yAxis: { type: 'value', name: '丢包%' },
          series: [{ name: '丢包率', type: 'bar', data: c.loss, itemStyle: { color: '#f59e0b' } }]
        };
      });

      onMounted(() => { refreshDevices(); refreshCaps(); });

      return {
        ic, TABS, tab, devices, ports, caps, pe, mtr, pc,
        sevStyle, sevText, confColor, healthStyle, healthText,
        refreshDevices, refreshCaps, onHostChange, runPe, baseline, runMtr, runPcap,
        latOption, lossOption, fmt
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.DeepToolsPage = DeepToolsPage;
  NC.route('/deep-tools', { title: '深度排障工具', comp: 'DeepToolsPage' });
})();
