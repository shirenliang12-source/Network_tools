/* =========================================================================
 * 无线勘测：周边扫描（含隐藏 SSID 定向探测）· 信号热力图与 AP 三边定位
 * 后端：server/wifi.js  +  server/api.js 的 /api/wifi/*
 * 跨平台：Windows netsh / Linux iw / macOS airport（沙箱无无线网卡时优雅返回空）
 * ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted, watch, nextTick } = Vue;
  const NC = window.NC, { api, fmt, icon, toast, go } = NC;

  const W = 760, H = 520;

  function dbmToQ(dbm) { if (dbm == null || isNaN(dbm)) return null; return Math.max(0, Math.min(100, Math.round(((dbm + 100) * 100) / 70))); }
  function lerp(a, b, u) { return a + (b - a) * u; }
  function heatColor(q) {
    const t = Math.max(0, Math.min(100, q)) / 100;
    let r, g, b;
    if (t < 0.5) { const u = t / 0.5; r = lerp(30, 255, u); g = lerp(144, 204, u); b = lerp(255, 0, u); }
    else { const u = (t - 0.5) / 0.5; r = 255; g = lerp(204, 59, u); b = lerp(0, 48, u); }
    return { r: Math.round(r), g: Math.round(g), b: Math.round(b) };
  }

  const WifiPage = {
    name: 'WifiPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="row-between wrap gap2">
        <div>
          <h2 class="fs18 fw4">无线勘测</h2>
          <div class="muted fs13">周边 Wi-Fi 扫描 · 隐藏 SSID 定向探测 · 信号热力图与 AP 定位</div>
        </div>
        <div class="items-center gap14">
          <span class="chip ok" v-if="ifaces.length">无线网卡：{{ ifaces.join(' / ') }}</span>
          <span class="chip off" v-else>未检测到无线网卡（需带 Wi-Fi 的机器 + 管理员权限）</span>
        </div>
      </div>

      <div class="tabs">
        <div class="tab" :class="{on: tab==='scan'}" @click="tab='scan'"><span v-html="ic('search',14)"></span><span style="margin-left:5px">周边扫描</span></div>
        <div class="tab" :class="{on: tab==='heat'}" @click="tab='heat'"><span v-html="ic('wifi',14)"></span><span style="margin-left:5px">信号热力图</span></div>
      </div>

      <!-- ==================== 周边扫描 ==================== -->
      <template v-if="tab==='scan'">
        <div class="card">
          <div class="card-head"><span v-html="ic('wifi',15)"></span><span>周边 Wi-Fi 扫描</span>
            <div class="grow"></div>
            <button class="btn primary sm" :disabled="scanning" @click="doScan">{{ scanning ? '扫描中…' : '开始扫描' }}</button>
          </div>
          <div class="muted fs13 mb4" v-if="scanNote">{{ scanNote }}</div>
          <div v-if="aps.length" class="table-scroll">
            <table class="ntable">
              <thead><tr><th>SSID</th><th>BSSID</th><th>信号</th><th>信道</th><th>类型</th><th>安全</th></tr></thead>
              <tbody>
                <tr v-for="a in aps" :key="a.bssid">
                  <td>
                    <span v-if="a.hidden" class="chip off">隐藏网络</span>
                    <span v-else>{{ a.ssid }}</span>
                  </td>
                  <td class="mono fs13">{{ a.bssid }}</td>
                  <td style="min-width:150px">
                    <div class="sigbar"><div class="sigbar-f" :style="{width:(a.quality||0)+'%'}"></div></div>
                    <span class="muted fs12">{{ a.signal }} dBm · {{ a.quality }}%</span>
                  </td>
                  <td>{{ a.channel || '-' }}</td>
                  <td class="mono fs12">{{ a.radio || '-' }}</td>
                  <td class="mono fs12">{{ a.security }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else-if="scanRaw" class="mt2">
            <div class="muted fs12 mb2">原始输出（前 1500 字，用于排查：无线未开启 / WlanSvc 服务未运行 / 无管理员权限）</div>
            <pre class="scan-raw">{{ scanRaw }}</pre>
          </div>
          <div class="ts-empty" v-else-if="!scanning">暂无数据，点击「开始扫描」开始周边勘测。</div>
        </div>

        <div class="card">
          <div class="card-head"><span v-html="ic('shield',15)"></span><span>隐藏 SSID 定向探测</span>
            <div class="grow"></div>
            <button class="btn primary sm" :disabled="probing" @click="doProbe">{{ probing ? '探测中…' : '定向探测' }}</button>
          </div>
          <div class="muted fs13 mb4">被动扫描只能发现隐藏 AP 的存在（标“隐藏网络”），拿不到名称。输入 SSID（可选 BSSID）发起定向探测（directed probe），AP 应答时即暴露其名称。</div>
          <div class="row gap14 wrap items-end mb4">
            <div><div class="muted fs12 mb2">SSID</div><input class="inp" v-model="probe.ssid" placeholder="例如 Corp-Hidden" style="width:220px"></div>
            <div><div class="muted fs12 mb2">BSSID（可选，限定 MAC）</div><input class="inp" v-model="probe.bssid" placeholder="可选" style="width:220px"></div>
          </div>
          <div v-if="probeRes" class="tb-notes">
            <div class="tb-note" :class="probeRes.probed ? 'c-green' : 'c-amber'"><span class="dot"></span>{{ probeRes.note }}</div>
            <div v-for="f in (probeRes.found||[])" :key="f.bssid" class="kv">
              <span>{{ f.ssid || '隐藏网络' }}</span>
              <span class="mono">{{ f.bssid }} · {{ f.signal }} dBm · CH{{ f.channel }}</span>
            </div>
          </div>
        </div>
      </template>

      <!-- ==================== 信号热力图 ==================== -->
      <div v-else class="col gap16">
        <div class="card">
          <div class="card-head"><span v-html="ic('wifi',15)"></span><span>信号热力图与 AP 定位</span>
            <div class="grow"></div>
            <div class="row gap14 wrap">
              <label class="btn sm" style="cursor:pointer">导入平面图<input type="file" accept="image/*" @change="onFloor" hidden></label>
              <select class="inp sm" v-model="targetSsid" style="width:210px">
                <option value="">— 选择目标 SSID / BSSID —</option>
                <option v-for="o in targetOptions" :key="o.key" :value="o.key">{{ o.label }}</option>
              </select>
              <button class="btn sm" :class="{on: collect}" @click="collect=!collect">采集模式：{{ collect ? '开' : '关' }}</button>
              <button class="btn sm" :class="{on: showHeat}" @click="showHeat=!showHeat">热力图：{{ showHeat ? '显示' : '隐藏' }}</button>
              <button class="btn sm primary" @click="doLocate" :disabled="!targetSsid">定位 AP</button>
              <button class="btn sm" @click="saveSurvey">保存勘测</button>
              <button class="btn sm off" @click="clearSurvey">清空</button>
              <button class="btn sm" @click="exportPng">导出 PNG</button>
            </div>
          </div>
          <div class="muted fs13 mb4">工作流：① 导入厂区/楼层平面图 → ② 选目标 SSID → ③ 开“采集模式”，到现场读 RSSI 填入下方，点击地图落点 → ④ 生成热力图 / 定位 AP。</div>
          <div class="row gap14 wrap items-end mb4" v-if="collect">
            <div><div class="muted fs12 mb2">当前 RSSI (dBm)</div><input class="inp sm" type="number" v-model="curRssi" style="width:130px"></div>
            <div class="muted fs12">当前目标 <b>{{ targetLabel || '未选' }}</b>；点击地图即在该处落一个 {{ curRssi }} dBm 测点。</div>
          </div>

          <div class="heat-wrap" :style="{aspectRatio: (W/H)}">
            <canvas ref="cv" class="heat-canvas" :width="W" :height="H" @click="onCanvasClick"></canvas>
            <div v-if="!floorImage && !samples.length" class="heat-empty">请先导入平面图；即便无平面图，也可直接以画布像素坐标采集（导出 PNG 即为成果）。</div>
          </div>

          <div class="muted fs12 mt2" v-if="apPos">推算 AP 位置（红★）：x={{ apPos.x }}，y={{ apPos.y }}（残差 {{ apPos.residual }}，与测距模型同量级）</div>
          <div class="muted fs12 mt2 c-amber" v-if="locateErr">{{ locateErr }}</div>
        </div>

        <div class="card" v-if="samples.length">
          <div class="card-head"><span v-html="ic('list',15)"></span><span>测点列表（{{ samples.length }}）</span></div>
          <div class="table-scroll">
            <table class="ntable">
              <thead><tr><th>#</th><th>SSID</th><th>x</th><th>y</th><th>RSSI</th><th>质量</th><th>信道</th><th></th></tr></thead>
              <tbody>
                <tr v-for="(s,i) in samples" :key="s.id">
                  <td>{{ i+1 }}</td>
                  <td>{{ s.ssid || '隐藏网络' }}</td>
                  <td>{{ s.x }}</td><td>{{ s.y }}</td>
                  <td>{{ s.rssi }} dBm</td><td>{{ s.quality }}%</td><td>{{ s.channel || '-' }}</td>
                  <td><button class="btn xs off" @click="delSample(i)">删</button></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>`,

    setup() {
      const ic = (n, s) => icon(n, s);
      const tab = ref('scan');
      const ifaces = ref([]);
      const aps = ref([]);
      const scanning = ref(false);
      const scanNote = ref('');
      const scanRaw = ref('');
      const probe = reactive({ ssid: '', bssid: '' });
      const probing = ref(false);
      const probeRes = ref(null);

      const floorImage = ref('');
      const floorImg = ref(null);
      const targetSsid = ref('');
      const collect = ref(false);
      const showHeat = ref(true);
      const curRssi = ref(-55);
      const samples = ref([]);
      const apPos = ref(null);
      const locateErr = ref('');
      const cv = ref(null);

      const targetOptions = computed(() => {
        const map = new Map();
        for (const a of (aps.value || [])) map.set(a.bssid, { key: a.bssid, ssid: a.ssid, bssid: a.bssid });
        for (const s of (samples.value || [])) {
          const k = s.bssid || s.ssid;
          if (k && !map.has(k)) map.set(k, { key: k, ssid: s.ssid, bssid: s.bssid });
        }
        return [...map.values()].map(o => ({ key: o.key, label: `${o.ssid || '隐藏网络'}${o.bssid ? ' (' + o.bssid + ')' : ''}`, ssid: o.ssid, bssid: o.bssid }));
      });
      const targetLabel = computed(() => {
        const o = targetOptions.value.find(x => x.key === targetSsid.value);
        return o ? o.label : '';
      });

      /* ----------------- 周边扫描 ----------------- */
      async function doScan() {
        scanning.value = true; scanNote.value = ''; scanRaw.value = ''; aps.value = [];
        try {
          const r = await api.post('/wifi/scan', {});
          if (r.ok) {
            aps.value = r.aps || [];
            const tail = r.iface ? ` · 接口 ${r.iface}` : '';
            if (aps.value.length) {
              const hid = aps.value.filter(a => a.hidden).length;
              scanNote.value = `发现 ${aps.value.length} 个 BSSID（${aps.value.length - hid} 个有名称` +
                (hid ? `，${hid} 个隐藏 SSID —— 可对目标发起下方「定向探测」暴露名称` : '') + `）` + tail;
            } else {
              scanNote.value = (r.note || '未发现无线网络') + tail;
              scanRaw.value = r.raw || '';
            }
          } else scanNote.value = '扫描失败：' + (r.error || '');
        } catch (e) { scanNote.value = '扫描异常：' + e.message; }
        finally { scanning.value = false; }
      }

      async function doProbe() {
        if (!probe.ssid && !probe.bssid) { toast('请输入要探测的 SSID 或 BSSID', 'warn'); return; }
        probing.value = true; probeRes.value = null;
        try {
          const r = await api.post('/wifi/probe', { ssid: probe.ssid, bssid: probe.bssid });
          probeRes.value = r;
          toast(r.probed ? '已暴露隐藏 SSID' : '未发现该隐藏网络', r.probed ? 'ok' : 'warn');
        } catch (e) { probeRes.value = { probed: false, note: '探测异常：' + e.message, found: [] }; }
        finally { probing.value = false; }
      }

      /* ----------------- 热力图 ----------------- */
      function onFloor(e) {
        const f = e.target.files && e.target.files[0];
        if (!f) return;
        const rd = new FileReader();
        rd.onload = () => {
          floorImage.value = rd.result;
          const img = new Image();
          img.onload = () => { floorImg.value = img; nextTick(draw); };
          img.src = rd.result;
        };
        rd.readAsDataURL(f);
      }

      function onCanvasClick(ev) {
        if (!collect.value) { toast('先开启“采集模式”再点击地图落点', 'info'); return; }
        if (!targetSsid.value) { toast('请先选择目标 SSID', 'warn'); return; }
        const rect = ev.currentTarget.getBoundingClientRect();
        const x = Math.round((ev.clientX - rect.left) * (W / rect.width));
        const y = Math.round((ev.clientY - rect.top) * (H / rect.height));
        const opt = targetOptions.value.find(o => o.key === targetSsid.value) || { ssid: targetSsid.value, bssid: '' };
        const rssi = Number(curRssi.value) || -55;
        samples.value.push({
          id: 'w' + Math.random().toString(36).slice(2, 9),
          ssid: opt.ssid || '', bssid: opt.bssid || '',
          x, y, rssi, quality: dbmToQ(rssi), channel: null, note: '', createdAt: new Date().toISOString()
        });
        nextTick(draw);
      }

      function delSample(i) { samples.value.splice(i, 1); nextTick(draw); }

      function idw(sel, x, y) {
        let num = 0, den = 0;
        for (const s of sel) {
          const d = Math.hypot(s.x - x, s.y - y) + 0.5;
          const w = 1 / (d * d);
          const q = (s.quality != null) ? s.quality : dbmToQ(s.rssi);
          if (q == null) continue;
          num += w * q; den += w;
        }
        return den ? num / den : null;
      }

      function draw() {
        const c = cv.value; if (!c) return;
        const ctx = c.getContext('2d');
        ctx.clearRect(0, 0, W, H);
        if (floorImg.value) { ctx.globalAlpha = 1; ctx.drawImage(floorImg.value, 0, 0, W, H); }
        else { ctx.fillStyle = '#0e1116'; ctx.fillRect(0, 0, W, H); }

        if (showHeat.value && targetSsid.value) {
          const sel = (samples.value || []).filter(s => s.ssid === targetSsid.value || s.bssid === targetSsid.value);
          if (sel.length) {
            const step = 9;
            for (let y = 0; y < H; y += step) {
              for (let x = 0; x < W; x += step) {
                const q = idw(sel, x, y);
                if (q == null) continue;
                const col = heatColor(q);
                ctx.fillStyle = `rgba(${col.r},${col.g},${col.b},0.55)`;
                ctx.fillRect(x, y, step, step);
              }
            }
          }
        }
        for (const s of (samples.value || [])) {
          const hot = (s.ssid === targetSsid.value || s.bssid === targetSsid.value);
          ctx.beginPath(); ctx.arc(s.x, s.y, 5, 0, Math.PI * 2);
          ctx.fillStyle = hot ? '#ffcc00' : '#9aa4b2'; ctx.fill();
          ctx.lineWidth = 1.5; ctx.strokeStyle = '#000'; ctx.stroke();
        }
        if (apPos.value) {
          const { x, y } = apPos.value;
          ctx.save();
          ctx.fillStyle = '#ff3b30'; ctx.strokeStyle = '#fff'; ctx.lineWidth = 2;
          ctx.beginPath();
          for (let i = 0; i < 5; i++) {
            const a1 = -Math.PI / 2 + i * 2 * Math.PI / 5;
            const a2 = a1 + Math.PI / 5;
            ctx.lineTo(x + 11 * Math.cos(a1), y + 11 * Math.sin(a1));
            ctx.lineTo(x + 5 * Math.cos(a2), y + 5 * Math.sin(a2));
          }
          ctx.closePath(); ctx.fill(); ctx.stroke();
          ctx.restore();
        }
      }

      async function doLocate() {
        locateErr.value = '';
        const sel = (samples.value || []).filter(s => (s.ssid === targetSsid.value || s.bssid === targetSsid.value) && s.x != null && s.y != null && s.rssi != null);
        if (sel.length < 3) { locateErr.value = '至少需要 3 个有效测点（含坐标与 RSSI）才能三边定位'; return; }
        try {
          const r = await api.post('/wifi/locate', { samples: sel.map(s => ({ x: s.x, y: s.y, rssi: s.rssi })) });
          if (r.ok && r.x != null) { apPos.value = { x: r.x, y: r.y, residual: r.residual }; nextTick(draw); toast('AP 定位完成', 'ok'); }
          else locateErr.value = r.error || '定位失败';
        } catch (e) { locateErr.value = '定位异常：' + e.message; }
      }

      async function saveSurvey() {
        try {
          await api.post('/wifi/samples', { floorImage: floorImage.value, floorName: '', samples: samples.value });
          toast('勘测已保存', 'ok');
        } catch (e) { toast('保存失败：' + e.message, 'err'); }
      }
      async function clearSurvey() {
        try {
          await api.del('/wifi/samples');
          floorImage.value = ''; floorImg.value = null; samples.value = []; apPos.value = null; targetSsid.value = '';
          nextTick(draw); toast('已清空', 'ok');
        } catch (e) { toast('清空失败：' + e.message, 'err'); }
      }
      function exportPng() {
        nextTick(() => {
          const c = cv.value; if (!c) return;
          const a = document.createElement('a');
          a.download = 'wifi-heatmap-' + Date.now() + '.png';
          a.href = c.toDataURL('image/png');
          a.click();
        });
      }

      /* ----------------- 初始化 ----------------- */
      onMounted(async () => {
        try { const r = await api.get('/wifi/interfaces'); if (r.ok) ifaces.value = r.interfaces || []; } catch (e) {}
        try {
          const r = await api.get('/wifi/samples');
          if (r.ok && r.data) {
            floorImage.value = r.data.floorImage || '';
            samples.value = r.data.samples || [];
            if (floorImage.value) {
              const img = new Image();
              img.onload = () => { floorImg.value = img; nextTick(draw); };
              img.src = floorImage.value;
            }
          }
        } catch (e) {}
      });

      watch([showHeat, targetSsid, samples, floorImg, apPos], () => nextTick(draw));
      watch(tab, () => { if (tab.value === 'heat') nextTick(draw); });

      return {
        ic,
        tab, ifaces, aps, scanning, scanNote, scanRaw, probe, probing, probeRes,
        floorImage, targetSsid, collect, showHeat, curRssi, samples, apPos, locateErr, cv,
        targetOptions, targetLabel,
        doScan, doProbe, onFloor, onCanvasClick, delSample, doLocate, saveSurvey, clearSurvey, exportPng
      };
    }
  };

  window.PAGES = window.PAGES || {};
  window.PAGES.WifiPage = WifiPage;
  NC.route('/wifi', { title: '无线勘测', comp: 'WifiPage' });
})();
