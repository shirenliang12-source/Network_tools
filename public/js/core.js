/* =========================================================================
   核心：API 客户端 / 全局状态 / 路由 / 通用组件
   ========================================================================= */
(function () {
  const { reactive, ref, computed, watch, onMounted, onBeforeUnmount, nextTick } = Vue;

  /* ------------------------------ 工具函数 ------------------------------ */
  const fmt = {
    bps(v) {
      v = Number(v) || 0;
      if (v >= 1e9) return (v / 1e9).toFixed(2) + ' Gbps';
      if (v >= 1e6) return (v / 1e6).toFixed(2) + ' Mbps';
      if (v >= 1e3) return (v / 1e3).toFixed(2) + ' Kbps';
      return Math.round(v) + ' bps';
    },
    bytes(v) {
      v = Number(v) || 0;
      const u = ['B', 'KB', 'MB', 'GB', 'TB'];
      let i = 0;
      while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
      return v.toFixed(i ? 1 : 0) + ' ' + u[i];
    },
    dur(sec) {
      if (sec === null || sec === undefined || isNaN(sec)) return '-';
      sec = Number(sec);
      const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
      if (d > 0) return `${d}天 ${h}小时`;
      if (h > 0) return `${h}小时 ${m}分`;
      return `${m}分`;
    },
    time(ts) {
      const d = toDate(ts);
      if (!d) return '-';
      const p = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    },
    timeShort(ts) {
      const d = toDate(ts);
      if (!d) return '-';
      const p = n => String(n).padStart(2, '0');
      if (Date.now() - d.getTime() < 86400000) return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
      return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
    },
    ago(ts) {
      const d = toDate(ts);
      if (!d) return '-';
      const s = Math.floor((Date.now() - d.getTime()) / 1000);
      if (s < 60) return s + ' 秒前';
      if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
      if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
      return Math.floor(s / 86400) + ' 天前';
    },
    pct: v => (v === null || v === undefined || isNaN(v) ? '-' : Number(v).toFixed(1) + '%'),
    num: v => (v === null || v === undefined || v === '' ? '-' : Number(v).toLocaleString('zh-CN'))
  };

  /** 兼容：秒级时间戳 / 毫秒时间戳 / ISO 字符串 / Date */
  function toDate(ts) {
    if (!ts && ts !== 0) return null;
    if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts;
    if (typeof ts === 'string') { const n = Date.parse(ts); return isNaN(n) ? null : new Date(n); }
    const n = Number(ts);
    if (isNaN(n)) return null;
    return new Date(n > 1e11 ? n : n * 1000);
  }
  const SEV_CN = { disaster: '灾难', high: '严重', average: '一般', warning: '警告', information: '信息', critical: '紧急' };
  const SEV_ORDER = { disaster: 5, critical: 5, high: 4, average: 3, warning: 2, information: 1 };

  /* ------------------------------ 图标库 ------------------------------ */
  const P = {
    dashboard: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
    server: '<rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><line x1="6" y1="6.5" x2="6.01" y2="6.5"/><line x1="6" y1="17.5" x2="6.01" y2="17.5"/>',
    terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    share: '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.6" y1="10.5" x2="15.4" y2="6.5"/><line x1="8.6" y1="13.5" x2="15.4" y2="17.5"/>',
    bell: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    robot: '<rect x="3" y="8" width="18" height="12" rx="3"/><line x1="12" y1="8" x2="12" y2="4"/><circle cx="12" cy="3" r="1.4"/><line x1="8" y1="14" x2="8.01" y2="14"/><line x1="16" y1="14" x2="16.01" y2="14"/>',
    search: '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.6" y2="16.6"/>',
    refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    edit: '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
    trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
    close: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    alert: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    play: '<polygon points="6 3 20 12 6 21 6 3"/>',
    stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
    filter: '<polygon points="22 3 2 3 10 12.5 10 21 14 18 14 12.5 22 3"/>',
    menu: '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
    user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>',
    clock: '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 16 14"/>',
    wifi: '<path d="M5 12.55a11 11 0 0 1 14 0"/><path d="M1.4 9a16 16 0 0 1 21.2 0"/><path d="M8.5 16a6 6 0 0 1 7 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.5 1.5"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7L12 19"/>',
    eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    list: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
    send: '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
    monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    power: '<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>',
    wind: '<path d="M9.6 4.6A2 2 0 1 1 11 8H2"/><path d="M12.6 19.4A2 2 0 1 0 14 16H2"/><path d="M17.7 7.7A2.5 2.5 0 1 1 19.5 12H2"/>',
    thermo: '<path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/>',
    layers: '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
    toolbox: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18v3h3l6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2-2 2.5-2.5z"/><line x1="14.5" y1="9.5" x2="14.5" y2="9.5"/>',
    globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10 15 15 0 0 1 4-10z"/>',
    camera: '<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>',
    clipboard: '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/>',
    database: '<ellipse cx="12" cy="5.5" rx="8.5" ry="3"/><path d="M3.5 5.5v13c0 1.66 3.8 3 8.5 3s8.5-1.34 8.5-3v-13"/><path d="M3.5 12c0 1.66 3.8 3 8.5 3s8.5-1.34 8.5-3"/>',
    pie: '<path d="M21.21 15.89A10 10 0 1 1 8 2.83"/><path d="M22 12A10 10 0 0 0 12 2v10z"/>',
    history: '<polyline points="3 3 3 9 9 9"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/>',
    save: '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    bar: '<line x1="6" y1="20" x2="6" y2="16"/><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/>',
    grid: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
    table: '<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/><line x1="9" y1="3" x2="9" y2="21"/>',
    gauge: '<path d="M12 14l4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>'
  };
  function icon(name, size) {
    const body = P[name] || P.file;
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" ${size ? `style="width:${size}px;height:${size}px"` : ''}>${body}</svg>`;
  }

  /* ------------------------------ API 客户端 ------------------------------ */
  const TOKEN_KEY = 'netops.token';
  const S = reactive({
    token: localStorage.getItem(TOKEN_KEY) || '',
    user: null, site: { name: '网络运维控制台', subtitle: 'Network Operations Console' },
    route: location.hash.replace(/^#/, '') || '/screen',
    sidebarCollapsed: localStorage.getItem('netops.sb') === '1',
    alarmCount: 0, criticalCount: 0,
    datasourceMode: 'demo',
    loading: false,
    toasts: []
  });

  async function api(path, opt = {}) {
    const headers = { ...(opt.headers || {}) };
    if (S.token) headers.Authorization = 'Bearer ' + S.token;
    if (opt.body && !(opt.body instanceof FormData)) headers['Content-Type'] = 'application/json';
    const res = await fetch('/api' + path, {
      method: opt.method || 'GET',
      headers,
      body: opt.body ? (opt.body instanceof FormData ? opt.body : (typeof opt.body === 'string' ? opt.body : JSON.stringify(opt.body))) : undefined
    });
    if (res.status === 401) {
      S.token = ''; S.user = null; localStorage.removeItem(TOKEN_KEY);
      toast('登录已过期，请重新登录', 'err');
      throw new Error('未登录');
    }
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res;
    }
    const data = await res.json();
    if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }
  const api$ = {
    get: (p) => api(p),
    post: (p, b) => api(p, { method: 'POST', body: b }),
    put: (p, b) => api(p, { method: 'PUT', body: b }),
    del: (p) => api(p, { method: 'DELETE' }),
    raw: api
  };

  function toast(msg, kind = 'ok', title) {
    const id = Math.random().toString(36).slice(2);
    S.toasts.push({ id, msg, kind, title: title || ({ ok: '操作成功', err: '出错了', warn: '提示', info: '通知' })[kind] });
    setTimeout(() => { const i = S.toasts.findIndex(t => t.id === id); if (i >= 0) S.toasts.splice(i, 1); }, kind === 'err' ? 6000 : 3200);
  }

  /* ------------------------------ 简易路由 ------------------------------ */
  const routes = {};
  function route(path, def) { routes[path] = def; }
  function go(path) { location.hash = path; }
  window.addEventListener('hashchange', () => { S.route = location.hash.replace(/^#/, '') || '/screen'; });
  const currentRoute = computed(() => {
    const p = S.route.split('?')[0];
    if (routes[p]) return { path: p, def: routes[p], query: parseQuery(S.route) };
    // 带参数路由
    for (const k of Object.keys(routes)) {
      if (k.includes(':')) {
        const kp = k.split('/'), cp = p.split('/');
        if (kp.length === cp.length) {
          const params = {};
          let ok = true;
          for (let i = 0; i < kp.length; i++) {
            if (kp[i].startsWith(':')) params[kp[i].slice(1)] = decodeURIComponent(cp[i]);
            else if (kp[i] !== cp[i]) { ok = false; break; }
          }
          if (ok) return { path: k, def: routes[k], params, query: parseQuery(S.route) };
        }
      }
    }
    return { path: '/screen', def: routes['/screen'] || { title: '大屏', comp: null }, query: {} };
  });
  function parseQuery(str) {
    const q = {};
    const i = str.indexOf('?');
    if (i < 0) return q;
    for (const kv of str.slice(i + 1).split('&')) {
      const [k, v] = kv.split('=');
      if (k) q[decodeURIComponent(k)] = decodeURIComponent(v || '');
    }
    return q;
  }

  /* ------------------------------ 通用组件 ------------------------------ */
  const NcChart = {
    props: { option: Object, height: { default: '280px' }, theme: { default: 'light' } },
    emits: ['click'],
    template: `<div ref="el" :style="{width:'100%',height:height}"></div>`,
    setup(props, { emit }) {
      const el = ref(null);
      let inst = null;
      const draw = () => {
        if (!el.value || !props.option) return;
        if (!inst) {
          inst = echarts.init(el.value, null, { renderer: 'canvas' });
          inst.on('click', (p) => emit('click', p));
        }
        inst.setOption(props.option, true);
      };
      const resize = () => inst && inst.resize();
      onMounted(() => { draw(); window.addEventListener('resize', resize); });
      onBeforeUnmount(() => { window.removeEventListener('resize', resize); if (inst) { inst.dispose(); inst = null; } });
      watch(() => props.option, () => nextTick(draw), { deep: true });
      return { el };
    }
  };

  const NcGauge = {
    props: { value: [Number, String], max: { default: 100 }, unit: { default: '%' }, size: { default: 78 }, label: String, warn: { default: 70 }, danger: { default: 85 } },
    template: `
      <div class="col" style="align-items:center;gap:3px">
        <div class="gauge" :class="{sm: size<=60}" :style="{width:size+'px',height:size+'px',flexBasis:size+'px'}">
          <svg width="100%" height="100%" :viewBox="'0 0 80 80'">
            <circle class="g-bg" cx="40" cy="40" :r="r" fill="none" :stroke-width="sw"></circle>
            <circle class="g-fg" cx="40" cy="40" :r="r" fill="none" :stroke-width="sw"
              :stroke="color" :stroke-dasharray="C" :stroke-dashoffset="off"></circle>
          </svg>
          <div class="g-txt">
            <div class="g-val" :style="{color:color}">{{ display }}</div>
            <div class="g-unit">{{ unit }}</div>
          </div>
        </div>
        <div v-if="label" class="fs12 muted">{{ label }}</div>
      </div>`,
    setup(props) {
      const r = 32, sw = 7, C = 2 * Math.PI * r;
      const val = computed(() => { const v = Number(props.value); return isNaN(v) ? 0 : Math.max(0, Math.min(props.max, v)); });
      const off = computed(() => C * (1 - val.value / props.max));
      const color = computed(() => {
        const p = val.value / props.max * 100;
        if (p >= props.danger) return '#dc2626';
        if (p >= props.warn) return '#d97706';
        return '#16a34a';
      });
      const display = computed(() => props.value === null || props.value === undefined || props.value === '' ? '-' : Number(props.value).toFixed(0));
      return { r, sw, C, off, color, display };
    }
  };

  const NcModal = {
    props: { title: String, wide: Boolean, okText: { default: '确定' }, cancelText: { default: '取消' }, okKind: { default: 'primary' }, okDisabled: Boolean, loading: Boolean, hideOk: Boolean },
    emits: ['ok', 'close'],
    template: `
      <div class="mask" @click.self="$emit('close')"></div>
      <div class="modal" :class="{wide}">
        <div class="modal-head">
          <h3>{{ title }}</h3>
          <button class="icon-btn" @click="$emit('close')" v-html="ic('close')"></button>
        </div>
        <div class="modal-body"><slot></slot></div>
        <div class="modal-foot">
          <slot name="foot">
            <button class="btn" @click="$emit('close')" :disabled="loading">{{ cancelText }}</button>
            <button v-if="!hideOk" class="btn" :class="okKind" @click="$emit('ok')" :disabled="okDisabled || loading">
              <span v-if="loading" class="typing"><span></span><span></span><span></span></span>
              <span v-else>{{ okText }}</span>
            </button>
          </slot>
        </div>
      </div>`,
    setup() { return { ic: (n) => icon(n, 15) }; }
  };

  const NcDrawer = {
    props: { title: String, wide: Boolean },
    emits: ['close'],
    template: `
      <div class="mask" @click.self="$emit('close')"></div>
      <div class="drawer" :class="{wide}">
        <div class="drawer-head">
          <h3>{{ title }}</h3>
          <button class="icon-btn" @click="$emit('close')" v-html="ic('close')"></button>
        </div>
        <div class="drawer-body"><slot></slot></div>
        <div class="drawer-foot" v-if="$slots.foot"><slot name="foot"></slot></div>
      </div>`,
    setup() { return { ic: (n) => icon(n, 15) }; }
  };

  const NcPager = {
    props: { page: Number, size: Number, total: Number },
    emits: ['update:page'],
    template: `
      <div class="pager">
        <div>共 <b>{{ total }}</b> 条，第 {{ page }} / {{ pages }} 页</div>
        <div class="pages">
          <button :disabled="page<=1" @click="$emit('update:page',1)">首页</button>
          <button :disabled="page<=1" @click="$emit('update:page',page-1)">上一页</button>
          <button v-for="p in shown" :key="p" :class="{on:p===page}" @click="$emit('update:page',p)">{{ p }}</button>
          <button :disabled="page>=pages" @click="$emit('update:page',page+1)">下一页</button>
          <button :disabled="page>=pages" @click="$emit('update:page',pages)">末页</button>
        </div>
      </div>`,
    setup(props) {
      const pages = computed(() => Math.max(1, Math.ceil(props.total / props.size)));
      const shown = computed(() => {
        const out = [], tp = pages.value;
        let s = Math.max(1, props.page - 2), e = Math.min(tp, s + 4);
        s = Math.max(1, e - 4);
        for (let i = s; i <= e; i++) out.push(i);
        return out;
      });
      return { pages, shown };
    }
  };

  const NcBar = {
    props: { value: Number, max: { default: 100 }, color: String, showText: Boolean },
    template: `
      <div>
        <div class="bar"><i :style="{width: w, background: c}"></i></div>
        <div v-if="showText" class="bar-lbl mono-num">{{ (value||0).toFixed(1) }}%</div>
      </div>`,
    setup(props) {
      const w = computed(() => Math.max(0, Math.min(100, (Number(props.value) || 0) / props.max * 100)) + '%');
      const c = computed(() => props.color || (props.value >= 85 ? '#dc2626' : props.value >= 70 ? '#d97706' : '#16a34a'));
      return { w, c };
    }
  };

  /* ECharts 深色/浅色基础配置 */
  function chartBase(dark) {
    return {
      textStyle: { fontFamily: 'var(--sans), sans-serif', color: dark ? '#8298bb' : '#5a6a80' },
      grid: { left: 8, right: 12, top: 28, bottom: 4, containLabel: true },
      tooltip: {
        trigger: 'axis',
        backgroundColor: dark ? 'rgba(6,14,26,.95)' : 'rgba(255,255,255,.98)',
        borderColor: dark ? 'rgba(64,152,255,.35)' : '#e2e8f1',
        textStyle: { color: dark ? '#dbe8ff' : '#16202e', fontSize: 12 },
        axisPointer: { type: 'line', lineStyle: { color: dark ? 'rgba(64,152,255,.5)' : '#c9d5e5' } }
      },
      legend: { textStyle: { color: dark ? '#8298bb' : '#5a6a80', fontSize: 11.5 }, itemWidth: 12, itemHeight: 8, top: 0 }
    };
  }
  const AXIS = (dark) => ({
    axisLine: { lineStyle: { color: dark ? 'rgba(64,152,255,.25)' : '#e2e8f1' } },
    axisLabel: { color: dark ? '#8298bb' : '#93a2b5', fontSize: 11 },
    splitLine: { lineStyle: { color: dark ? 'rgba(64,152,255,.08)' : '#eef2f8' } }
  });
  const SPLIT = (dark) => ({ splitLine: { lineStyle: { color: dark ? 'rgba(64,152,255,.08)' : '#eef2f8' } } });

  /* ------------------------------ 导出 ------------------------------ */
  window.NC = {
    state: S, api: api$, fmt, icon, toast, route, go, currentRoute, routes,
    SEV_CN, SEV_ORDER, chartBase, AXIS, SPLIT,
    components: { NcChart, NcGauge, NcModal, NcDrawer, NcPager, NcBar },
    setToken(t) { S.token = t; localStorage.setItem(TOKEN_KEY, t); },
    clearToken() { S.token = ''; S.user = null; localStorage.removeItem(TOKEN_KEY); },
    wsUrl(path, params) {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const q = new URLSearchParams({ token: S.token, ...(params || {}) });
      return `${proto}//${location.host}${path}?${q}`;
    }
  };
  window.NC.fmt.human = window.NC.fmt.dur;
})();
