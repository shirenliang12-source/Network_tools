/* =========================================================================
   自定义协议（业务协议）定义管理
   · 列表 / 新增 / 编辑 / 删除
   · 匹配条件：端口列表 / 源-目的 IP 正则 / HEX 魔数（偏移 + 字节）
   · 命中后协议名覆盖内置 DPI，并出现在性能与协议报表中
   数据：/api/custom-protocols
   ========================================================================= */
(function () {
  const { ref, reactive, computed, onMounted } = Vue;
  const NC = window.NC, { api, fmt, icon, toast } = NC;

  const CustomProtocolPage = {
    name: 'CustomProtocolPage',
    props: { params: Object, query: Object },
    template: `
    <div class="col gap16">
      <div class="card">
        <div class="card-head">
          <span v-html="ic('layers',15)"></span><span>自定义协议定义</span>
          <div class="grow"></div>
          <button class="btn primary" @click="openNew" v-html="ic('plus',13)+'<span>新增协议</span>'"></button>
          <button class="btn" @click="load" v-html="ic('refresh',13)+'<span>刷新</span>'"></button>
        </div>
        <div class="fs12 muted" style="padding:0 12px 8px">
          自定义协议优先级高于内置 DPI：同端口上既匹配标准协议又匹配自定义规则时，自定义名称生效。
          支持「端口 / IP 正则 / HEX 魔数」三选一组合命中。
        </div>
        <div class="table-wrap">
          <table class="ntable">
            <thead><tr>
              <th style="width:40px">#</th>
              <th style="width:150px">协议名称</th>
              <th>匹配条件</th>
              <th style="width:80px">状态</th>
              <th style="width:200px">操作</th>
            </tr></thead>
            <tbody>
              <tr v-for="(p,i) in list" :key="p.id">
                <td class="mono muted">{{ i+1 }}</td>
                <td>
                  <span class="dot" :style="{background:p.color}"></span>
                  <b>{{ p.name }}</b>
                  <div class="fs11 muted" v-if="p.desc">{{ p.desc }}</div>
                </td>
                <td>
                  <span class="tag" v-if="p.ports && p.ports.length">端口 {{ p.ports.join(', ') }}</span>
                  <span class="tag" v-if="p.ipFilter">IP≈{{ p.ipFilter }}</span>
                  <span class="tag" v-if="p.hexOffset != null && p.hexBytes">@{{ p.hexOffset }}: {{ p.hexBytes }}</span>
                  <span class="muted fs11" v-if="!(p.ports&&p.ports.length)&&!p.ipFilter&&!(p.hexOffset!=null&&p.hexBytes)">—</span>
                </td>
                <td><span class="chip" :class="p.enabled?'ok':'off'">{{ p.enabled?'启用':'停用' }}</span></td>
                <td class="row gap8">
                  <button class="btn xs" @click="openEdit(p)" v-html="ic('edit',12)+'<span>编辑</span>'"></button>
                  <button class="btn xs" :class="p.enabled?'':'primary'" @click="toggle(p)" v-html="p.enabled?'停用':'启用'"></button>
                  <button class="btn xs danger ghost" @click="del(p)" v-html="ic('trash',12)+'<span>删除</span>'"></button>
                </td>
              </tr>
              <tr v-if="!list.length"><td colspan="5" class="tbl-empty">暂无自定义协议，点击「新增协议」创建第一条</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <NcModal v-if="editing" :title="form.id?'编辑协议：'+form.name:'新增自定义协议'" ok-text="保存" @close="editing=false" @ok="save">
        <div class="col gap12" style="padding:4px 2px">
          <div class="row gap12 wrap">
            <div class="field grow"><label>协议名称 *</label><input class="ipt" v-model.trim="form.name" maxlength="60" placeholder="如 MyERP-Sync"></div>
            <div class="field" style="width:120px"><label>颜色</label><input class="ipt" type="color" v-model="form.color"></div>
          </div>
          <div class="field"><label>业务说明（可选）</label><input class="ipt" v-model.trim="form.desc" maxlength="80" placeholder="用于在报表/会话中标识业务含义"></div>
          <div class="divider"></div>
          <div class="fs12 muted">匹配条件（至少填写一项）</div>
          <div class="field"><label>端口列表（逗号分隔）</label><input class="ipt" v-model.trim="form.portsText" placeholder="如 9000 或 9000,9100"></div>
          <div class="field"><label>源/目的 IP 正则</label><input class="ipt" v-model.trim="form.ipFilter" placeholder="如 10\\.252\\.28\\.\\d+ （留空不限制）"></div>
          <div class="row gap12 wrap">
            <div class="field" style="width:160px"><label>HEX 偏移（字节）</label><input class="ipt" v-model.trim="form.hexOffset" placeholder="如 0"></div>
            <div class="field grow"><label>HEX 魔数字节</label><input class="ipt mono" v-model.trim="form.hexBytes" placeholder="如 4d517250 或 0x4d517250"></div>
          </div>
          <div class="fs12" :style="{color: form.enabled?'var(--ok)':'var(--muted)'}">
            <input type="checkbox" v-model="form.enabled"> 启用该协议（关闭后不参与匹配）
          </div>
          <div class="fs12" v-if="err" style="color:var(--danger)">{{ err }}</div>
        </div>
      </NcModal>
    </div>`,
    setup() {
      const ic = (n, s) => icon(n, s);
      const list = ref([]);
      const editing = ref(false);
      const err = ref('');
      const blank = () => ({ id: '', name: '', desc: '', portsText: '', ipFilter: '', hexOffset: '', hexBytes: '', color: '#3b82f6', enabled: true });
      const form = reactive(blank());

      async function load() {
        try { const d = await api.get('/custom-protocols'); list.value = d.list || []; }
        catch (e) { toast('加载失败：' + (e.message || e), 'err'); }
      }
      function openNew() { Object.assign(form, blank()); err.value = ''; editing.value = true; }
      function openEdit(p) {
        Object.assign(form, {
          id: p.id, name: p.name, desc: p.desc || '',
          portsText: (p.ports || []).join(', '), ipFilter: p.ipFilter || '',
          hexOffset: p.hexOffset != null ? String(p.hexOffset) : '', hexBytes: p.hexBytes || '',
          color: p.color || '#3b82f6', enabled: p.enabled !== false
        });
        err.value = ''; editing.value = true;
      }
      async function save() {
        err.value = '';
        const payload = {
          name: form.name, desc: form.desc,
          ports: form.portsText, ipFilter: form.ipFilter,
          hexOffset: form.hexOffset, hexBytes: form.hexBytes,
          color: form.color, enabled: form.enabled
        };
        try {
          if (form.id) {
            const d = await api.put('/custom-protocols/' + form.id, payload);
            if (!d.ok) { err.value = d.error || '保存失败'; return; }
          } else {
            const d = await api.post('/custom-protocols', payload);
            if (!d.ok) { err.value = d.error || '保存失败'; return; }
          }
          editing.value = false; toast('已保存', 'ok'); await load();
        } catch (e) { err.value = e.message || '请求异常'; }
      }
      async function toggle(p) {
        try {
          const d = await api.put('/custom-protocols/' + p.id, { enabled: !p.enabled });
          if (!d.ok) return toast(d.error || '操作失败', 'err');
          await load();
        } catch (e) { toast('操作失败：' + (e.message || e), 'err'); }
      }
      async function del(p) {
        if (!confirm(`确认删除自定义协议「${p.name}」？`)) return;
        try { const d = await api.delete('/custom-protocols/' + p.id); if (!d.ok) return toast(d.error || '删除失败', 'err'); toast('已删除', 'ok'); await load(); }
        catch (e) { toast('删除失败：' + (e.message || e), 'err'); }
      }

      onMounted(load);
      return { ic, list, editing, err, form, load, openNew, openEdit, save, toggle, del };
    }
  };
  window.PAGES = window.PAGES || {};
  window.PAGES.CustomProtocolPage = CustomProtocolPage;
  NC.route('/custom-protocols', { title: '自定义协议', comp: 'CustomProtocolPage' });
})();
