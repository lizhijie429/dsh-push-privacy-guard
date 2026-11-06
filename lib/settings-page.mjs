/**
 * Standalone graphical settings page served inside the DSH Web GUI.
 * All data is rendered client-side from the token-protected JSON API.
 *
 * @module dsh-push-privacy-guard/settings-page
 */

export function renderSettingsPage({ token, pluginVersion = '0.0.0', config = {} }) {
  const tokenJson = JSON.stringify(String(token))
  const version = String(pluginVersion).replace(/[^0-9A-Za-z.+_-]/g, '')
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>提交推送隐私检查 · 设置</title>
<style>
  :root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--text:#1c1f24;--muted:#69707a;--line:#e3e6eb;--accent:#2563eb;--accent-weak:#eff4ff;--danger:#c03434;--ok:#187a4b;--radius:14px;--shadow:0 1px 2px rgba(16,24,40,.05),0 8px 24px rgba(16,24,40,.06)}
  @media (prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1d2025;--text:#e8eaf0;--muted:#a0a7b2;--line:#2d323a;--accent:#7aa2ff;--accent-weak:#1e2a44;--danger:#ff8a8a;--ok:#7fd3a7;--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35)}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
  .wrap{max-width:1080px;margin:0 auto;padding:28px 22px 48px}
  header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:20px}
  h1{font-size:22px;margin:0 0 4px}
  .sub{color:var(--muted);margin:0;font-size:13px}
  .badge{background:var(--accent-weak);color:var(--accent);padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
  .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;align-items:start}
  .card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:18px}
  .card.wide{grid-column:1/-1}
  h2{font-size:15px;margin:0 0 12px;display:flex;align-items:center;justify-content:space-between;gap:8px}
  h2 .hint{font-size:12px;font-weight:400;color:var(--muted)}
  .row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px dashed var(--line)}
  .row:last-child{border-bottom:0}
  .row label{color:var(--text);font-size:13px}
  .row .en{color:var(--muted);font-size:11px;margin-left:4px}
  input[type=text],input[type=number],select{background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 9px;font:inherit;max-width:260px;min-width:120px}
  input[type=checkbox]{width:34px;height:18px;accent-color:var(--accent)}
  button{cursor:pointer;border:1px solid var(--line);background:var(--card);color:var(--text);padding:6px 12px;border-radius:8px;font:inherit}
  button:hover{border-color:var(--accent);color:var(--accent)}
  button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
  button.primary:hover{filter:brightness(1.05);color:#fff}
  button.link{border:0;background:transparent;color:var(--accent);padding:2px 4px}
  button.danger{border-color:transparent;color:var(--danger);background:transparent}
  .toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:12px}
  .muted{color:var(--muted);font-size:12px}
  .empty{color:var(--muted);font-size:12px;padding:14px 0}
  .notice{background:var(--accent-weak);border:1px solid color-mix(in srgb,var(--accent) 25%,transparent);color:var(--text);padding:10px 12px;border-radius:10px;font-size:12px;margin-top:10px}
  .warn{color:var(--danger);font-size:12px;margin-top:8px}
  .toast{position:fixed;right:18px;bottom:18px;max-width:420px;padding:10px 14px;border-radius:10px;background:var(--card);border:1px solid var(--line);box-shadow:var(--shadow);font-size:13px;display:none;z-index:10}
  .toast.show{display:block}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th,td{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.02em}
  td.mono,span.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px}
  .pill{display:inline-block;padding:1px 7px;border-radius:999px;background:var(--accent-weak);color:var(--accent);font-size:11px}
  .pill.danger{background:transparent;color:var(--danger);border:1px solid color-mix(in srgb,var(--danger) 35%,transparent)}
  .path{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;color:var(--muted);word-break:break-all}
  .kv{display:grid;grid-template-columns:120px 1fr;gap:6px 10px;font-size:12px}
  .kv div:nth-child(odd){color:var(--muted)}
  .status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px}
  @media(max-width:820px){.grid{grid-template-columns:1fr}.wrap{padding:18px 14px 34px}h1{font-size:19px}.kv{grid-template-columns:100px 1fr}}
</style>
</head>
<body>
<main class="wrap">
  <header>
    <div>
      <h1>提交推送隐私检查</h1>
      <p class="sub">Push Privacy Guard · 全局 / 项目 / 会话放行与插件配置</p>
    </div>
    <span class="badge">v${version}</span>
  </header>

  <section class="grid">
    <div class="card wide" id="status-card">
      <h2>运行状态 <span class="hint">只读</span></h2>
      <div id="status" class="muted">加载中…</div>
    </div>

    <div class="card" id="config-card">
      <h2>插件配置 <span class="hint">保存后热生效</span></h2>
      <form id="config-form"><div id="config-fields" class="muted">加载中…</div>
        <div class="toolbar"><button class="primary" type="submit">保存配置</button><span id="config-hint" class="muted"></span></div>
      </form>
    </div>

    <div class="card" id="pending-card">
      <h2>最近拦截 <span class="hint">可一键放行</span></h2>
      <div id="pending" class="muted">加载中…</div>
      <div class="toolbar"><button id="refresh" type="button">刷新</button></div>
    </div>

    <div class="card" id="global-card">
      <h2>全局白名单 <span class="hint" id="global-count"></span></h2>
      <div id="global-entries" class="muted">加载中…</div>
      <div class="toolbar"><button id="global-clear" class="danger" type="button">清空全局白名单</button></div>
    </div>

    <div class="card" id="project-card">
      <h2>项目白名单 <span class="hint" id="project-count"></span></h2>
      <div class="toolbar" style="margin:0 0 10px">
        <input id="cwd" type="text" placeholder="仓库绝对路径，例如 D:\\Work\\repo" style="flex:1;max-width:none">
        <button id="project-load" type="button">加载</button>
      </div>
      <div id="project-entries" class="muted">填写仓库路径后加载。</div>
      <div class="toolbar"><button id="project-clear" class="danger" type="button">清空项目白名单</button></div>
    </div>

    <div class="card wide">
      <h2>说明</h2>
      <div class="notice">
        <div>· 会话级放行只在当前会话内存中有效，请在对话中让助手调用 <span class="mono">privacy_guard</span> 工具，或使用 <span class="mono">/privacy-guard session</span> 管理。</div>
        <div>· 项目白名单仅接受本仓库根目录内的文件；符号链接或越界路径会被忽略。</div>
        <div>· 放行操作只针对“最近拦截”里的条目，避免误放行未知内容；本页所有请求都带一次性 token 并校验同源。</div>
      </div>
    </div>
  </section>
</main>
<div id="toast" class="toast"></div>
<script>
(() => {
  const TOKEN = ${tokenJson};
  const $ = (selector) => document.querySelector(selector);
  let state = { cwd: localStorage.getItem('pg.cwd') || '', fields: [], data: null };
  const zh = String(navigator.language || 'zh').toLowerCase().startsWith('zh');

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  function toast(message, isError) {
    const el = $('#toast');
    el.textContent = message;
    el.style.borderColor = isError ? 'var(--danger)' : 'var(--line)';
    el.classList.add('show');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => el.classList.remove('show'), 4200);
  }
  async function api(path, options) {
    const res = await fetch(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', 'X-Privacy-Guard-Token': TOKEN, ...(options && options.headers) },
      cache: 'no-store',
    });
    let data;
    try { data = await res.json(); } catch { data = { ok: false, error: '接口返回非 JSON（' + res.status + '）' }; }
    if (!data.ok) throw new Error(data.error || ('请求失败（' + res.status + '）'));
    return data;
  }
  function statusUrl() {
    const url = new URL('/privacy-guard/api', location.origin);
    if (state.cwd) url.searchParams.set('cwd', state.cwd);
    return url.pathname + url.search;
  }
  async function load() {
    $('#cwd').value = state.cwd;
    try {
      const data = await api(statusUrl());
      state.data = data;
      state.fields = data.fields || [];
      renderStatus(data);
      renderConfig(data.fields || []);
      renderPending(data.pending || []);
      renderEntries('global', data.global ? data.global.entries : []);
      renderProject(data.project);
    } catch (error) {
      toast(error.message, true);
      $('#status').textContent = '加载失败：' + error.message;
    }
  }
  function renderStatus(data) {
    const c = data.config || {};
    const repo = data.project;
    const pending = (data.pending || []).length;
    const html = [
      '<div class="kv">',
      '<div>插件</div><div><span class="status-dot"></span>' + (c.enabled ? '已启用' : '已禁用') + '</div>',
      '<div>检查项</div><div>commit / push / gh repo sync</div>',
      '<div>授权作用域</div><div><span class="pill">' + esc(c.approvalScope) + '</span></div>',
      '<div>全局白名单</div><div>' + (data.global ? data.global.entries.length : 0) + ' 条</div>',
      '<div>项目状态</div><div>' + (repo ? (repo.warning ? '<span class="warn">' + esc(repo.warning) + '</span>' : esc(repo.file) + '（' + (repo.entries || []).length + ' 条）') : '<span class="muted">未选择仓库</span>') + '</div>',
      '<div>最近拦截</div><div>' + pending + ' 条</div>',
      '<div>运行时</div><div class="path">' + esc((data.paths || {}).whitelistFile || '') + '</div>',
      '</div>',
    ].join('');
    $('#status').innerHTML = html;
  }
  function renderConfig(fields) {
    const groups = { basic: '基础', policy: '审批与策略', project: '项目白名单', limits: '限制' };
    const wrap = $('#config-fields');
    if (!fields.length) { wrap.textContent = '没有可编辑字段。'; return; }
    const wrapper = document.createElement('div');
    for (const field of fields) {
      const row = document.createElement('div');
      row.className = 'row';
      const label = document.createElement('label');
      label.innerHTML = esc(zh ? field.zh : field.en) + '<span class="en">' + esc(zh ? field.en : field.zh) + '</span>';
      row.appendChild(label);
      let input;
      if (field.type === 'boolean') {
        input = document.createElement('input');
        input.type = 'checkbox';
        input.checked = field.value !== false;
      } else if (field.type === 'enum') {
        input = document.createElement('select');
        for (const option of field.options || []) {
          const opt = document.createElement('option');
          opt.value = option;
          opt.textContent = option;
          if (String(field.value) === option) opt.selected = true;
          input.appendChild(opt);
        }
      } else if (field.type === 'number') {
        input = document.createElement('input');
        input.type = 'number';
        input.min = field.min;
        input.max = field.max;
        input.value = field.value;
      } else {
        input = document.createElement('input');
        input.type = 'text';
        input.value = field.value == null ? '' : String(field.value);
      }
      input.name = field.key;
      input.dataset.type = field.type;
      row.appendChild(input);
      wrapper.appendChild(row);
    }
    wrap.innerHTML = '';
    wrap.appendChild(wrapper);
  }
  function renderEntries(scope, entries) {
    const target = scope === 'global' ? '#global-entries' : '#project-entries';
    const count = scope === 'global' ? '#global-count' : '#project-count';
    $(count).textContent = entries.length ? entries.length + ' 条' : '';
    if (!entries.length) { $(target).innerHTML = '<div class="empty">暂无条目。</div>'; return; }
    const rows = entries.map((entry) => '<tr>' +
      '<td class="mono">' + esc(entry.id) + '</td>' +
      '<td>' + esc(entry.rule) + '</td>' +
      '<td class="mono">' + esc(entry.masked || '') + '</td>' +
      '<td class="path">' + esc(entry.firstFile || '') + '</td>' +
      '<td>' + (entry.allowed === false ? '<span class="pill danger">撤销</span>' : '<span class="pill">允许</span>') + '</td>' +
      '<td><button type="button" class="link" data-scope="' + scope + '" data-revoke="' + esc(entry.id) + '">删除</button></td>' +
      '</tr>').join('');
    $(target).innerHTML = '<table><thead><tr><th>ID</th><th>规则</th><th>掩码</th><th>文件</th><th>类型</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
  }
  function renderProject(project) {
    if (!project) {
      renderEntries('project', []);
      $('#project-entries').innerHTML = '<div class="empty">填写仓库路径后加载。</div>';
      return;
    }
    if (project.warning) toast(project.warning, false);
    renderEntries('project', project.entries || []);
  }
  function renderPending(pending) {
    if (!pending.length) { $('#pending').innerHTML = '<div class="empty">最近没有拦截记录。</div>'; return; }
    const rows = pending.map((item) => '<tr>' +
      '<td class="mono">' + esc(item.identity) + '</td>' +
      '<td>' + esc(item.ruleId) + '</td>' +
      '<td class="mono">' + esc(item.masked || '') + '</td>' +
      '<td class="path">' + esc(item.file || '') + '</td>' +
      '<td><button class="link" type="button" data-allow="' + esc(item.identity) + '" data-scope="global">→ 全局</button>' +
      '<button class="link" type="button" data-allow="' + esc(item.identity) + '" data-scope="project">→ 项目</button></td>' +
      '</tr>').join('');
    $('#pending').innerHTML = '<table><thead><tr><th>ID</th><th>规则</th><th>掩码</th><th>文件</th><th>放行</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }
  async function toggle(action, scope, target, cwd) {
    try {
      if (scope === 'project' && (!cwd || !state.data || !state.data.project)) throw new Error('先填写并加载仓库路径');
      const data = await api('/privacy-guard/api', {
        method: 'POST',
        body: JSON.stringify({ action, scope, target, cwd }),
      });
      toast(data.message || '操作成功');
      await load();
    } catch (error) {
      toast(error.message, true);
    }
  }
  $('#config-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const values = {};
    for (const input of document.querySelectorAll('#config-fields [name]')) {
      const type = input.dataset.type;
      if (type === 'boolean') values[input.name] = input.checked;
      else if (type === 'number') values[input.name] = Number(input.value);
      else values[input.name] = input.value;
    }
    try {
      const data = await api('/privacy-guard/api', { method: 'POST', body: JSON.stringify({ action: 'save-config', values }) });
      toast(data.message || '已保存');
      await load();
    } catch (error) { toast(error.message, true); }
  });
  $('#refresh').addEventListener('click', load);
  $('#project-load').addEventListener('click', async () => {
    state.cwd = $('#cwd').value.trim();
    localStorage.setItem('pg.cwd', state.cwd);
    await load();
  });
  $('#cwd').addEventListener('keydown', (event) => { if (event.key === 'Enter') $('#project-load').click(); });
  $('#global-clear').addEventListener('click', () => {
    if (confirm('确定清空全局白名单？')) toggle('clear', 'global', '', '');
  });
  $('#project-clear').addEventListener('click', () => {
    if (confirm('确定清空项目白名单？')) toggle('clear', 'project', '', state.cwd);
  });
  document.addEventListener('click', (event) => {
    const allow = event.target.closest('[data-allow]');
    if (allow) return toggle('allow', allow.dataset.scope, allow.dataset.allow, state.cwd);
    const revoke = event.target.closest('[data-revoke]');
    if (revoke) return toggle('revoke', revoke.dataset.scope, revoke.dataset.revoke, state.cwd);
  });
  load();
})();
</script>
</body>
</html>`
}
