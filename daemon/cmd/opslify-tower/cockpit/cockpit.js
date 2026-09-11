// The cockpit, built to design/Cockpit.dc.html.
//
// Every mutation here is a request to the SAME daemon endpoint the CLI calls, so
// the policy classifier, the approval gates and the audit trail apply
// identically. There is no second path to get wrong — and the tower's allowlist
// (routes.go) refuses anything this file should not be reaching for, so a bug
// here is a broken button rather than a new capability.
'use strict';

/* ------------------------------------------------------------------ util --- */

const $ = (id) => document.getElementById(id);

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// api wraps fetch with the one rule that matters: a non-2xx is an ERROR carrying
// the daemon's own message, never a silently empty panel. An operator seeing a
// blank Connections page cannot tell "none defined" from "the request was
// refused", and those need different actions.
async function api(path, opts) {
  const res = await fetch(path, Object.assign({ credentials: 'same-origin' }, opts || {}));
  const text = await res.text();
  if (!res.ok) {
    let msg = text;
    try { msg = JSON.parse(text).error || text; } catch (_) { /* not JSON; use the body */ }
    const err = new Error(msg || (res.status + ' ' + res.statusText));
    err.status = res.status;
    throw err;
  }
  return text ? JSON.parse(text) : null;
}

const send = (method, path, body) => api(path, {
  method,
  headers: { 'Content-Type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
});

function toast(msg, kind) {
  const el = document.createElement('div');
  if (kind) el.className = kind;
  el.textContent = msg;
  $('toast').appendChild(el);
  setTimeout(() => el.remove(), kind === 'bad' ? 9000 : 4500);
}

// Base64 for a secret value typed by the operator. btoa() is byte-oriented, so
// anything non-ASCII has to be encoded first or the stored bytes are not what
// was typed — a passphrase with a é in it would be silently corrupted.
function b64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin);
}

// splitArgv turns what the operator typed into an argv vector, WITHOUT a shell.
//
// This is the security-critical function on the page. The daemon classifies each
// exec on its argv — that is how "^kubectl delete" becomes an approval gate. Wrap
// the input in `sh -c "..."` for the convenience of pipes and every gate in the
// product stops matching, because the classifier would see `sh` and nothing else.
// So: quotes are honoured, and shell metacharacters are REFUSED rather than
// passed through as literal arguments, which would silently do the wrong thing.
function splitArgv(line) {
  const argv = [];
  let cur = '', quote = null, any = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === '\\' && quote === '"' && i + 1 < line.length) { cur += line[++i]; continue; }
      if (c === quote) { quote = null; continue; }
      cur += c;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; any = true; continue; }
    if (c === ' ' || c === '\t') {
      if (cur || any) { argv.push(cur); cur = ''; any = false; }
      continue;
    }
    if ('|&;<>$`'.includes(c)) {
      throw new Error('"' + c + '" is a shell metacharacter, and this is not a shell. ' +
        'Commands run as argv so the policy classifier sees the command you actually ' +
        'ran — wrapping them in `sh -c` would make every approval gate stop matching.');
    }
    cur += c;
  }
  if (quote) throw new Error('unbalanced ' + quote + ' quote');
  if (cur || any) argv.push(cur);
  if (!argv.length) throw new Error('nothing to run');
  return argv;
}

const fmtBytes = (n) => {
  n = Number(n) || 0;
  if (n < 1024) return n + 'b';
  if (n < 1024 * 1024) return Math.round(n / 1024) + 'k';
  return Math.round(n / (1024 * 1024)) + 'M';
};

const fmtSecs = (n) => {
  n = Math.max(0, Number(n) || 0);
  if (n < 90) return Math.round(n) + 's';
  if (n < 5400) return Math.round(n / 60) + 'm';
  if (n < 172800) return Math.round(n / 3600) + 'h';
  return Math.round(n / 86400) + 'd';
};

const fmtAge = (iso) => {
  if (!iso) return '—';
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 90) return Math.round(secs) + 's';
  if (secs < 5400) return Math.round(secs / 60) + 'm';
  if (secs < 172800) return Math.round(secs / 3600) + 'h';
  return Math.round(secs / 86400) + 'd';
};

const short = (s, n) => {
  s = String(s == null ? '' : s);
  return s.length > (n || 12) ? s.slice(0, n || 12) : s;
};

/* ----------------------------------------------------------------- state --- */

const S = {
  projects: [],
  projectID: null,
  envID: null,
  sessions: [],
  connections: [],
  secrets: [],
  consumers: [],
  agents: [],
  boundAgent: null,
  changes: [],
  policy: null,
  health: null,
  tabs: [],          // [{id, label, kind, arg}]
  activeTab: null,
  drawerShut: false,
  loadError: null,
  // The drawer's Shell. sessionID is which sandbox it is attached to; lines is
  // the scrollback; pending is a gate waiting on a human.
  drawerTab: 'shell',
  shell: { sessionID: null, lines: [], busy: false, pending: null, history: [], hpos: -1 },
  // The agent thread: what you asked, and what it said back. Kept in memory only
  // — the daemon owns the durable record of what an agent actually DID (the
  // trace), and a second half-copy of it here would just be a way to disagree.
  chat: { turns: [], busy: false },
  draft: '',
  draftFocus: false,
  bindings: [],
  memory: [],
  tree: null,
  catalogue: [],
  memHits: null,
  memQuery: '',
};

// resolveBinding applies F8.5's precedence: the most specific binding wins, and
// "_fallback" is the daemon-wide default.
//
// The API returns `bindings` as scope→agent pairs. The first version of this read
// a `bound` field that has never existed on any response, so boundAgent was
// always null and the composer was permanently disabled with "No agent is bound"
// — while `opslify agent ls` showed one bound perfectly well.
function resolveBinding() {
  const env = S.envID;
  const byScope = {};
  for (const b of S.bindings) byScope[b.scope] = b.agent;
  const name = (env && byScope[env]) ||
    (S.projectID && byScope[S.projectID]) ||
    byScope._fallback || null;
  if (!name) return null;
  return S.agents.find((a) => a.name === name) || null;
}

const project = () => S.projects.find((p) => p.id === S.projectID) || null;
const environment = () => {
  const p = project();
  if (!p || !p.environments) return null;
  return p.environments.find((e) => e.id === S.envID) || p.environments[0] || null;
};

// Connections and changes are filtered to the selected scope. A cockpit that
// shows prod's objects while the header says staging is worse than one that
// shows nothing.
const inScope = (o) => {
  if (!o) return false;
  const env = environment();
  if (o.environment_id) return env ? o.environment_id === env.id : false;
  if (o.scope) return o.scope === S.projectID || (env && o.scope === env.id);
  if (o.project_id) return o.project_id === S.projectID;
  return true; // unscoped objects are global and belong everywhere
};

/* ------------------------------------------------------------------ load --- */

async function loadAll() {
  const get = async (path, fallback) => {
    try { return await api(path); } catch (e) { return fallback; }
  };
  const [projects, sessions, connections, secrets, consumers, agents, changes, policy, health] =
    await Promise.all([
      get('/v1/projects', []),
      get('/v1/sessions', []),
      get('/v1/connections', []),
      get('/v1/secrets', []),
      get('/v1/secrets/consumers', []),
      get('/v1/agents', { agents: [] }),
      get('/v1/changes', []),
      get('/v1/policy', null),
      get('/v1/health', null),
    ]);

  S.projects = projects || [];
  // session.View is session_id + age_seconds + ttl_remaining_seconds — NOT id,
  // started and ttl. Normalised HERE, once, so a shape change is a one-line fix
  // rather than a hunt through every screen. This was found by running a real
  // sandbox: the evaluation instance has no runtime, so every session list was
  // empty and every one of these bugs was invisible.
  S.sessions = (sessions || []).map((x) => Object.assign({}, x, {
    id: x.session_id || x.id,
    ttl: x.ttl_remaining_seconds != null ? fmtSecs(x.ttl_remaining_seconds) : (x.ttl || null),
    age: x.age_seconds != null ? fmtSecs(x.age_seconds) : null,
  }));
  S.connections = connections || [];
  S.secrets = secrets || [];
  S.consumers = consumers || [];
  S.agents = (agents && agents.agents) || [];
  S.bindings = (agents && agents.bindings) || [];
  S.boundAgent = resolveBinding();
  S.changes = changes || [];
  S.policy = policy;
  S.health = health;

  if (!S.projectID || !project()) {
    const first = S.projects[0];
    S.projectID = first ? first.id : null;
    S.envID = first && first.environments && first.environments[0] ? first.environments[0].id : null;
  }
  if (!environment()) {
    const p = project();
    S.envID = p && p.environments && p.environments[0] ? p.environments[0].id : null;
  }

  // Memory and the workspace tree are per-PROJECT, so they are fetched after the
  // project is resolved — not alongside it. Batching them with the rest sent
  // ?project= as undefined on the very first load, which read the DEFAULT
  // project's memory and rendered "no documents" over a populated one.
  const scope = S.projectID ? '?project=' + encodeURIComponent(S.projectID) : '';
  const [memoryList, tree, catalogue] = await Promise.all([
    get('/v1/memory' + scope, null),
    get('/v1/workspace' + scope, null),
    get('/v1/agents/catalogue', null),
  ]);
  S.memory = (memoryList && memoryList.documents) || [];
  S.tree = tree;
  S.catalogue = (catalogue && catalogue.entries) || [];
}

async function refresh() {
  await loadAll();
  render();
}

/* ------------------------------------------------------------------- tabs -- */

function openTab(kind, arg, label) {
  const id = arg ? kind + ':' + arg : kind;
  if (!S.tabs.some((t) => t.id === id)) S.tabs.push({ id, kind, arg, label: label || kind });
  S.activeTab = id;
  render();
}

function closeTab(id) {
  const i = S.tabs.findIndex((t) => t.id === id);
  if (i < 0) return;
  S.tabs.splice(i, 1);
  if (S.activeTab === id) S.activeTab = S.tabs.length ? S.tabs[Math.max(0, i - 1)].id : null;
  render();
}

/* ----------------------------------------------------------------- render -- */

function render() {
  renderHeader();
  renderSide();
  renderTabs();
  renderWork();
  renderDrawer();
  renderChat();
}

function renderHeader() {
  const p = project(); const e = environment();
  // OptionC2 has no project rail, so the crumb IS the switcher. The + beside it
  // is the only way into the wizard now, which makes it load-bearing rather than
  // decorative.
  $('crumbs').innerHTML = (S.projects.length
    ? '<select class="projsel" id="projsel">' + S.projects.map((x) =>
        '<option value="' + esc(x.id) + '"' + (x.id === S.projectID ? ' selected' : '') + '>' +
        esc(x.name) + '</option>').join('') + '</select>'
    : '<span class="tag">no project yet</span>') +
    '<button class="addproj" data-wizard="1" title="new project">+</button>' +
    (p ? '<span class="tag">/</span>' +
      '<span class="crumb" style="color:var(--' + (e && e.production ? 'danger' : 'warn') + ');">' +
      esc(e ? e.name : '—') + '</span>' : '');

  const a = S.boundAgent;
  const pill = $('agentpill');
  if (a) {
    pill.className = 'agentpill';
    // Locality is stated, not implied. An agent whose locality is unknown is
    // shown as off-host, because claiming a prompt stayed on this machine when
    // nobody said so would be the one lie this pill must never tell.
    const off = a.locality !== 'local';
    pill.innerHTML = '<span class="dot"></span><span class="nm">' + esc(a.name) + '</span>' +
      '<span class="ch">' + esc(a.model_hint || 'model unstated') +
      (off ? ' · <span style="color:var(--warn)">off-host</span>' : ' · on-host') + '</span>';
  } else {
    pill.className = 'agentpill none';
    pill.innerHTML = '<span class="dot off"></span><span class="nm">no agent bound</span>' +
      '<span class="ch">' + (S.agents.length ? S.agents.length + ' registered' : '') + '</span>';
  }

  const badge = $('tracebadge');
  if (S.health && S.health.status === 'ok') {
    badge.className = 'badge ok';
    badge.textContent = 'daemon ok · ' + (S.health.version || 'dev');
  } else {
    badge.className = 'badge danger';
    badge.textContent = 'daemon unreachable';
  }
}

// esec renders one explorer section header: a label, a live count, and a + that
// adds one of whatever the section holds. The + is the whole point — adding a
// connection belongs where the connections are, not behind a screen you have to
// know exists.
function esec(title, count, addAction, moreTab) {
  return '<div class="esec"><span>' + esc(title) + '</span>' +
    (count != null ? '<span class="n">' + esc(String(count)) + '</span>' : '<span class="n"></span>') +
    (moreTab ? '<span class="more" data-open="' + esc(moreTab) + '">all →</span>' : '') +
    (addAction ? '<button class="add" data-add="' + esc(addAction) +
      '" title="add">+</button>' : '') +
    '</div>';
}

const noneRow = (what) => '<div class="row none"><span class="nm">' + esc(what) + '</span></div>';

function renderSide() {
  const p = project();
  if (!p) {
    $('side').innerHTML = '<div class="empty"><h3>No project yet</h3>' +
      'A project is the unit everything else hangs off — environments, tools, ' +
      'connections, policy and changes.' +
      '<div style="margin-top:14px;"><button class="primary lg" data-wizard="1">' +
      'Create a project</button></div>' +
      '<div class="cli">opslify project create &lt;name&gt;</div></div>';
    return;
  }

  const envs = p.environments || [];
  const live = S.sessions.filter(inScope);
  const conns = S.connections.filter(inScope);
  const pending = S.changes.filter((c) => inScope(c) && c.status === 'awaiting_approval');
  const caps = p.capabilities || {};
  const roles = Object.keys(caps).sort();

  let html = '';

  // --- environments -----------------------------------------------------------
  html += esec('Environments', envs.length, 'env');
  html += '<div class="envrow">' + envs.map((e) =>
    '<div class="env' + (e.id === S.envID ? ' on' : '') + (e.production ? ' prod' : '') +
    '" data-env="' + esc(e.id) + '" title="' + (e.production ? 'production' : 'non-production') +
    '">' + esc(e.name) + '</div>').join('') + '</div>';

  // --- tools ------------------------------------------------------------------
  // Tools are the project's role → tool map. Until F8.8 there was no way to edit
  // one after `project create`, from any surface.
  html += esec('Tools', roles.length, 'tool', 'tools');
  html += roles.length ? roles.map((r) =>
    '<div class="row" data-open="tools"><span class="kd">' + esc(r) + '</span>' +
    '<span class="nm">' + esc(caps[r]) + '</span>' +
    '<span class="x" data-rmtool="' + esc(r) + '" title="remove">✕</span></div>').join('')
    : noneRow('no tools recorded');

  // --- sandboxes --------------------------------------------------------------
  html += esec('Sandboxes', live.length ? live.length + ' live' : 0, 'session', 'sandboxes');
  html += live.length ? live.map((sx) =>
    '<div class="row" data-open="sandboxes">' +
    '<span class="dot' + (sx.state === 'running' ? '' : ' off') + '"></span>' +
    '<span class="nm">' + esc(short(sx.id, 8)) + '</span>' +
    '<span class="rt" style="color:var(--db);">' + esc(sx.tier || '—') + '</span></div>').join('')
    : noneRow('none running');

  // --- connections ------------------------------------------------------------
  html += esec('Connections', conns.length, 'conn', 'connections');
  html += conns.length ? conns.map((c) =>
    '<div class="row" data-open="connections"><span class="kd ' + esc(c.kind) + '">' +
    esc(c.kind) + '</span><span class="nm" title="' + esc(c.name) + '">' + esc(c.name) + '</span>' +
    '<span class="x" data-rmconn="' + esc(c.name) + '" title="remove">✕</span></div>').join('')
    : noneRow('none bound');

  // --- secrets ----------------------------------------------------------------
  html += esec('Secrets', S.secrets.length, 'secret', 'secrets');
  html += S.secrets.length ? S.secrets.map((x) =>
    '<div class="row" data-open="secrets"><span class="kd">ref</span>' +
    '<span class="nm">' + esc(x.ref) + '</span>' +
    '<span class="rt">' + esc(x.provider || '') + '</span></div>').join('')
    : noneRow('none stored');

  // --- memory -----------------------------------------------------------------
  // No + that uploads. Memory is a folder of reviewed files in the project's
  // workspace; a button that wrote one would be a second, unreviewed path into
  // what the agent reads.
  html += esec('Memory', S.memory.length, null, 'memory');
  html += S.memory.length ? S.memory.slice(0, 8).map((d) =>
    '<div class="row" data-open="memory"><span class="kd">md</span>' +
    '<span class="nm" title="' + esc(d.rel) + '">' + esc(d.title || d.rel) + '</span>' +
    '<span class="rt" style="color:var(--' + (d.enabled ? 'muted' : 'danger') + ');">' +
    (d.enabled ? d.chunks + ' ch' : 'off') + '</span></div>').join('')
    : noneRow('no documents');

  // --- policy -----------------------------------------------------------------
  html += esec('Policy', S.policy ? short(S.policy.hash, 8) : null, 'policy', 'policy');
  html += S.policy ? (S.policy.layers || []).map((l) =>
    '<div class="row" data-open="policy"><span class="ind">' + (l.editable ? '✎' : '🔒') + '</span>' +
    '<span class="nm" style="color:' + (l.editable ? 'var(--accent)' : 'var(--muted)') + '">' +
    esc(l.layer) + '</span><span class="rt">' + (l.editable ? 'editable' : 'locked') +
    '</span></div>').join('') : noneRow('unavailable');

  // --- changes ----------------------------------------------------------------
  html += esec('Changes', pending.length ? pending.length + ' open' : 0, null, 'changes');
  html += pending.length ? pending.map((c) =>
    '<div class="row" data-open="change:' + esc(c.id) + '">' +
    '<span class="dot warn"></span><span class="nm">' + esc(short(c.id, 18)) + '</span>' +
    '<span class="rt" style="color:var(--warn);">approve</span></div>').join('')
    : noneRow('nothing awaiting you');

  // --- workspace --------------------------------------------------------------
  // The project's directory on the host, mounted at /workspace in every sandbox.
  // This is a LISTING: names and sizes, never contents. F3.6's refusal to serve
  // raw workspace bytes to a browser stays closed.
  const tree = S.tree;
  const treeEntries = (tree && tree.entries) || [];
  html += esec('Workspace', treeEntries.length, null, 'workspace');
  if (tree && tree.exists) {
    // Indented by path depth, which is why the API returns plain path order:
    // sorting directories first would separate one from its own contents.
    html += treeEntries.slice(0, 24).map((e) => {
      const parts = e.rel.split('/');
      const depth = parts.length - 1;
      const leaf = parts[parts.length - 1];
      return '<div class="row" data-open="workspace" title="' + esc(e.rel) + '"' +
        ' style="padding-left:' + (12 + depth * 11) + 'px;">' +
        '<span class="ind">' + (e.dir ? '▾' : '·') + '</span>' +
        '<span class="nm"' + (e.excluded ? ' style="color:var(--muted);"' : '') + '>' +
        esc(leaf) + (e.dir ? '/' : '') + '</span>' +
        '<span class="rt">' + (e.excluded ? 'withheld' : (e.dir ? '' : fmtBytes(e.bytes))) +
        '</span></div>';
    }).join('');
    if (treeEntries.length > 24) {
      html += '<div class="row none"><span class="nm">' +
        (treeEntries.length - 24) + ' more — open Workspace</span></div>';
    }
  } else {
    html += noneRow('not created yet');
  }

  // --- agents -----------------------------------------------------------------
  // No + here: registering an agent runs its command on the host, so it is the
  // one thing on this sidebar the cockpit deliberately cannot do.
  // A + here is safe ONLY because it opens the catalogue: the browser picks an
  // entry and the daemon owns the command. POST /v1/agents, which takes a
  // caller-supplied path, is still refused by the allowlist.
  html += esec('Agents', S.agents.length, 'agent', 'agents');
  html += S.agents.length ? S.agents.map((a) =>
    '<div class="row' + (S.boundAgent && S.boundAgent.name === a.name ? ' on' : '') +
    '" data-open="agents"><span class="dot' + (a.locality === 'local' ? '' : ' warn') + '"></span>' +
    '<span class="nm">' + esc(a.name) + '</span>' +
    '<span class="rt">' + esc(a.locality || 'unknown') + '</span></div>').join('')
    : noneRow('none — click + to connect one');

  $('side').innerHTML = html;
}

function renderTabs() {
  if (!S.tabs.length) openTabsDefault();
  $('tabs').innerHTML = S.tabs.map((t) =>
    '<div class="tab' + (t.id === S.activeTab ? ' on' : '') + '" data-tab="' + esc(t.id) + '">' +
    esc(t.label) + '<span class="x" data-close="' + esc(t.id) + '">✕</span></div>').join('') +
    '<div class="tab add" data-newtab="1">+</div>';
}

function openTabsDefault() {
  S.tabs = [{ id: 'sandboxes', kind: 'sandboxes', label: 'sandboxes' }];
  S.activeTab = 'sandboxes';
}

const SCREENS = {};

function renderWork() {
  const tab = S.tabs.find((t) => t.id === S.activeTab);
  const work = $('work');
  if (!tab) { work.innerHTML = '<div class="empty">No tab open.</div>'; return; }
  const screen = SCREENS[tab.kind];
  if (!screen) { work.innerHTML = '<div class="empty">Unknown screen.</div>'; return; }
  work.innerHTML = screen(tab.arg);
  if (tab.kind === 'shell') afterShellRender();
}

function renderDrawer() {
  const tabs = [
    ['shell', 'Shell'],
    ['trace', 'Trace'],
    ['changes', 'Changes'],
    ['policy', 'Policy'],
  ];
  $('dtabs').innerHTML = tabs.map(([id, label]) =>
    '<span class="t' + (S.drawerTab === id ? ' on' : '') + '" data-dtab="' + id + '">' +
    esc(label) + '</span>').join('') +
    '<span class="sp spacer"></span>' +
    (S.drawerTab === 'shell'
      ? '<span class="t" data-shellpop="1" title="open in a full tab">⤢</span>'
      : '') +
    '<span class="t" data-drawer="1">' + (S.drawerShut ? '▴' : '▾') + '</span>';
  $('drawer').className = 'drawer' + (S.drawerShut ? ' shut' : '') +
    (S.drawerTab === 'shell' ? ' tall' : '');

  const body = $('trace');
  if (S.drawerTab === 'shell') { body.innerHTML = shellHTML(); afterShellRender(); return; }
  if (S.drawerTab === 'changes') { body.innerHTML = drawerChanges(); return; }
  if (S.drawerTab === 'policy') { body.innerHTML = drawerPolicy(); return; }
  body.innerHTML = drawerTrace();
}

function drawerTrace() {
  // The drawer shows what the daemon can actually attest to. A per-session trace
  // needs a session; with none running there is nothing signed to display, and
  // inventing a plausible timeline here would undermine the one surface whose
  // whole value is that it is not invented.
  const live = S.sessions.filter(inScope);
  if (!live.length) {
    return '<div class="empty" style="padding:14px;">' +
      'No sandbox running in this scope, so there is no trace segment to show.<br>' +
      '<span class="tag">A trace is per-session and hash-chained from its ' +
      'session.start; it appears here once a sandbox starts.</span></div>';
  }
  return live.map((sx) =>
    '<div class="tli"><span class="ts">' + esc(sx.age || '—') + ' ago</span>' +
    '<span class="ty" style="color:var(--ok);">session.start</span>' +
    '<span class="de">sandbox ' + esc(short(sx.id, 8)) + ' · tier ' + esc(sx.tier || '—') +
    ' · mode ' + esc(sx.mode || '—') + '</span></div>').join('') +
    '<div class="tli"><span class="ts"></span><span class="ty" style="color:var(--muted);">' +
    'verify</span><span class="de">opslify verify ' + esc(short(live[0].id, 8)) +
    ' — the chain is checked by the CLI, not asserted here</span></div>';
}

function drawerChanges() {
  const rows = S.changes.filter(inScope);
  if (!rows.length) return '<div class="empty" style="padding:14px;">No changes in this scope.</div>';
  return rows.map((c) =>
    '<div class="tli" data-open="change:' + esc(c.id) + '" style="cursor:pointer;">' +
    '<span class="ts">' + esc(c.status) + '</span>' +
    '<span class="ty" style="color:var(--' +
    (c.status === 'awaiting_approval' ? 'warn' : c.status === 'applied' ? 'ok' : 'muted') + ');">' +
    esc(short(c.id, 20)) + '</span>' +
    '<span class="de">' + esc(c.intent || '') + '</span></div>').join('');
}

function drawerPolicy() {
  if (!S.policy) return '<div class="empty" style="padding:14px;">Policy unavailable.</div>';
  return '<div class="tli"><span class="ts">hash</span><span class="ty">' +
    esc(short(S.policy.hash, 16)) + '</span><span class="de">binds into the next session</span></div>' +
    (S.policy.layers || []).map((l) =>
      '<div class="tli"><span class="ts">' + (l.editable ? 'editable' : 'locked') + '</span>' +
      '<span class="ty" style="color:var(--' + (l.editable ? 'accent' : 'muted') + ');">' +
      esc(l.layer) + '</span><span class="de">' + esc(l.note || '') + '</span></div>').join('');
}

/* ----------------------------------------------------------------- shell --- */

const shellSession = () => {
  const live = S.sessions.filter(inScope);
  if (S.shell.sessionID && live.some((x) => x.id === S.shell.sessionID)) {
    return live.find((x) => x.id === S.shell.sessionID);
  }
  return live[0] || null;
};

function shellHTML() {
  const sx = shellSession();
  const live = S.sessions.filter(inScope);

  if (!sx) {
    // No host shell here, and this says so rather than leaving the operator to
    // wonder why the box is empty. See the note on shellRun.
    return '<div class="shellwrap"><div class="empty" style="padding:18px;">' +
      '<h3>No sandbox to attach to</h3>' +
      'This shell runs inside a sandbox — gVisor or runc, default-deny egress, ' +
      'dropped capabilities, read-only rootfs. It is not a shell on this host, and ' +
      'the daemon has no route that would give the browser one.' +
      '<div style="margin-top:14px;">' +
      '<button class="primary lg" data-add="session">Start a sandbox</button></div>' +
      '<div class="cli">opslify session create --project ' + esc(S.projectID || '&lt;id&gt;') +
      '</div></div></div>';
  }

  const sel = live.length > 1
    ? '<select id="shellsess" class="projsel">' + live.map((x) =>
        '<option value="' + esc(x.id) + '"' + (x.id === sx.id ? ' selected' : '') + '>' +
        esc(short(x.id, 10)) + ' · ' + esc(x.tier || '') + '</option>').join('') + '</select>'
    : '<span class="mono" style="font-size:10.5px;">' + esc(short(sx.id, 10)) + '</span>';

  const pend = S.shell.pending;

  return '<div class="shellwrap">' +
    '<div class="capbar">sandbox ' + sel + ' · tier <b>' + esc(sx.tier || '—') + '</b> · ' +
    'commands run as <b>argv, not a shell</b>, so the policy classifier sees what you ' +
    'actually ran · <b>no credential is inside this sandbox</b></div>' +
    '<div class="term" id="shellout">' +
    (S.shell.lines.length
      ? S.shell.lines.map((l) => '<span class="' + esc(l.k) + '">' + esc(l.t) + '</span>').join('')
      : '<span class="o">Type a command. It runs inside sandbox ' + esc(short(sx.id, 8)) +
        '.\nGated commands pause here for approval instead of running.\n\n</span>') +
    '</div>' +
    (pend
      ? '<div class="shellgate"><div class="h">paused — ' + esc(pend.rule || 'approval gate') +
        '</div><div class="d">' + esc(pend.reason || 'this command needs a human') +
        '</div><div class="arow">' +
        '<button class="approve" data-execdecide="approve">Approve and run</button>' +
        '<button class="deny" data-execdecide="deny">Deny</button></div></div>'
      : '') +
    '<div class="shellin">' +
    '<span class="ps1">' + esc(short(sx.id, 8)) + ' $</span>' +
    '<input id="shellcmd" class="mono" autocomplete="off" spellcheck="false"' +
    (S.shell.busy || pend ? ' disabled' : '') +
    ' placeholder="' + (pend ? 'waiting on the gate above' : 'kubectl get pods') + '">' +
    '<button data-shellrun="1"' + (S.shell.busy || pend ? ' disabled' : '') + '>Run</button>' +
    '</div></div>';
}

function afterShellRender() {
  const out = $('shellout');
  if (out) out.scrollTop = out.scrollHeight;
  const inp = $('shellcmd');
  if (inp && !inp.disabled && S.drawerTab === 'shell') inp.focus();
}

const shellPush = (kind, text) => {
  S.shell.lines.push({ k: kind, t: text });
  // Bounded: a command that prints forever should not take the tab with it.
  if (S.shell.lines.length > 900) S.shell.lines.splice(0, S.shell.lines.length - 900);
};

// shellRun streams the daemon's NDJSON exec frames. It deliberately does NOT
// offer a host shell: the cockpit is a web page, and a route that ran commands
// on this machine would make the launch token the only thing between a stray
// browser tab and the host the sandboxes exist to protect. `opslify exec` in the
// terminal you launched this from is the host shell.
async function shellRun(line) {
  const sx = shellSession();
  if (!sx) return;
  let argv;
  try { argv = splitArgv(line); } catch (e) { shellPush('e', e.message + '\n'); renderDrawer(); return; }

  S.shell.history.push(line); S.shell.hpos = -1;
  shellPush('p', short(sx.id, 8) + ' $ ' + line + '\n');
  S.shell.busy = true; renderDrawer();

  try {
    const res = await fetch('/v1/sessions/' + encodeURIComponent(sx.id) + '/exec', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ argv }),
    });
    if (!res.ok) {
      let msg = await res.text();
      try { msg = JSON.parse(msg).error || msg; } catch (_) { /* plain text */ }
      shellPush('e', msg + '\n');
      S.shell.busy = false; renderDrawer(); return;
    }

    // Frames arrive as newline-delimited JSON and are rendered as they land, so a
    // long command shows progress rather than nothing until it finishes.
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const raw = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (!raw.trim()) continue;
        let f;
        try { f = JSON.parse(raw); } catch (_) { continue; }
        if (f.status === 'pending') {
          S.shell.pending = { execID: f.exec_id, rule: f.rule, reason: f.reason, sessionID: sx.id };
          shellPush('w', 'PAUSED — ' + (f.rule || 'approval gate') +
            '. Nothing ran; a human decides.\n');
        } else if (f.error) {
          shellPush('e', f.error + '\n');
        } else if (f.truncated) {
          shellPush('w', '[' + (f.stream || 'output') + ' truncated — output cap reached]\n');
        } else if (f.exit_code !== undefined && f.exit_code !== null) {
          shellPush(f.exit_code === 0 ? 'o' : 'e', '[exit ' + f.exit_code + ']\n\n');
        } else if (f.data) {
          shellPush(f.stream === 'stderr' ? 'e' : 'o', f.data);
        }
        renderDrawer();
      }
    }
  } catch (e) {
    shellPush('e', 'the stream failed: ' + e.message + '\n');
  }
  S.shell.busy = false;
  renderDrawer();
}

async function shellDecide(decision) {
  const p = S.shell.pending;
  if (!p) return;
  await guard(async () => {
    await send('POST', '/v1/sessions/' + encodeURIComponent(p.sessionID) +
      '/approvals/' + encodeURIComponent(p.execID), { decision });
    S.shell.pending = null;
    shellPush(decision === 'approve' ? 'o' : 'w',
      '[' + decision + 'd] ' + (decision === 'approve'
        ? 'running — poll the output with `opslify approvals`\n\n'
        : 'nothing ran\n\n'));
    renderDrawer();
    await refresh();
  });
}

function renderChat() {
  const pending = S.changes.filter((c) => inScope(c) && c.status === 'awaiting_approval');
  const a = S.boundAgent;
  const drivable = !!(a && a.drivable);

  const gates = pending.map((c) =>
    '<div class="m"><div class="a ag">!</div><div class="b">' +
    '<div class="w2">Change · ' + esc(c.policy_rule || 'gated') + '</div>' +
    '<div class="gate"><div class="h">' + esc(short(c.id, 28)) + ' · awaiting your approval</div>' +
    '<div class="d">' + esc(c.intent || '') + '<br>' +
    '<span class="muted">' + esc(c.blast_summary || 'blast radius unstated') + ' · revert = ' +
    (c.revertible ? esc(c.inverse_kind || 'prepared') : 'NOT AVAILABLE') + '</span></div>' +
    '<div class="arow">' +
    '<button class="approve" data-decide="approve" data-chg="' + esc(c.id) + '">Approve</button>' +
    '<button class="deny" data-decide="deny" data-chg="' + esc(c.id) + '">Deny</button>' +
    '<button class="sm" data-open="change:' + esc(c.id) + '">Open</button>' +
    '</div></div></div></div>').join('');

  const turns = S.chat.turns.map((t) => t.role === 'you'
    ? '<div class="m"><div class="a">you</div><div class="b">' +
      '<div class="w2">You</div>' + esc(t.text) + '</div></div>'
    : '<div class="m"><div class="a ag">ag</div><div class="b">' +
      '<div class="w2">' + esc(t.name || 'Agent') +
      (t.done && t.exit ? ' · exited ' + esc(String(t.exit)) : '') + '</div>' +
      '<div class="agentout">' + esc(t.text || '') +
      (t.busy ? '<span class="cursor">▋</span>' : '') + '</div>' +
      (t.err ? '<div class="err" style="margin:6px 0 0;">' + esc(t.err) + '</div>' : '') +
      '</div></div>').join('');

  // Why the composer is unusable, when it is. A disabled box with no reason is a
  // bug report waiting to happen.
  let blocked = null;
  if (!a) blocked = 'No agent is bound to this scope. Bind one from the Agents screen.';
  else if (!drivable) {
    blocked = a.name + ' was registered without a flavour, so the daemon has no recipe ' +
      'for taking away its host tools. Re-add it with --flavour claude|qwen|codex.';
  }

  $('chat').innerHTML =
    '<div class="ch"><span style="font-weight:600;">Agent</span>' +
    (a ? '<span class="badge accent">' + esc(a.name) + '</span>' +
         (a.locality === 'local' ? '<span class="badge ok">on-host</span>'
                                 : '<span class="badge warn">off-host</span>')
       : '<span class="tag">none bound</span>') +
    '<span class="spacer"></span>' +
    (S.chat.turns.length ? '<button class="sm" data-chatclear="1">Clear</button>' : '') +
    '<button class="sm" data-open="agents">' + (a ? 'Switch' : 'Bind') + '</button></div>' +
    '<div class="thr" id="thread">' +
    (turns || gates || '<div class="m"><div class="a">·</div><div class="b">' +
      '<div class="w2">Nothing yet</div>' +
      'Ask the agent to do something. It works only through opslify\'s tools — ' +
      'every command it runs lands in a sandbox, through the same gates and the ' +
      'same trace as anything you run yourself.</div></div>') +
    (turns && gates ? gates : '') +
    '</div>' +
    '<div class="comp"><div class="cbox">' +
    '<textarea id="ask" rows="3" placeholder="' +
    (blocked ? esc(blocked) : 'Ask the agent to do something…') + '"' +
    (blocked || S.chat.busy ? ' disabled' : '') + '></textarea>' +
    '<div class="crow">' +
    // The picker sits where the model picker sits in every other agent UI —
    // beside the box you type in, not on a settings screen. Switching it rebinds
    // the scope, which is the same action `opslify agent use` performs.
    '<select id="agentpick" class="projsel" title="which agent runs this">' +
    S.agents.map((x) =>
      '<option value="' + esc(x.name) + '"' + (a && a.name === x.name ? ' selected' : '') + '>' +
      esc(x.name) + (x.model_hint ? ' · ' + esc(x.model_hint) : '') +
      (x.locality === 'local' ? ' · local' : '') + '</option>').join('') +
    '<option value="__add">+ connect an agent…</option></select>' +
    '<span class="tag" style="font-size:10px;">' +
    esc(S.projectID || '—') + '/' + esc(environment() ? environment().name : '—') +
    (a && a.locality !== 'local'
      ? ' · <span style="color:var(--warn)">off-host</span>'
      : (a ? ' · <span style="color:var(--ok)">on-host</span>' : '')) +
    '</span><span class="spacer"></span>' +
    (S.chat.busy
      ? '<button class="sm danger" data-chatstop="1">Stop</button>'
      : '<button class="sm primary" data-ask="1"' + (blocked ? ' disabled' : '') + '>Send</button>') +
    '</div></div></div>';

  const thr = $('thread');
  if (thr) thr.scrollTop = thr.scrollHeight;

  // renderChat runs on every poll. Without this the box is rebuilt from scratch
  // every five seconds and whatever was half-typed goes with it — which is what
  // made the composer feel like it would not accept more than a few words.
  const box = $('ask');
  if (box) {
    if (S.draft) { box.value = S.draft; autogrow(box); }
    if (document.activeElement !== box && S.draftFocus) { box.focus(); }
  }
}

// autogrow sizes a textarea to its content, up to the CSS max-height.
function autogrow(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, window.innerHeight * 0.4) + 'px';
}

// askAgent streams the agent's output into the thread as it arrives. A model
// working an estate takes minutes; an operator who cannot see what it is doing
// until it finishes cannot stop it doing the wrong thing.
let agentAbort = null;

async function askAgent(text) {
  const a = S.boundAgent;
  if (!a || !a.drivable) return;
  const e = environment();

  S.chat.turns.push({ role: 'you', text });
  const turn = { role: 'agent', name: a.name, text: '', busy: true };
  S.chat.turns.push(turn);
  S.chat.busy = true;
  renderChat();

  agentAbort = new AbortController();
  try {
    const res = await fetch('/v1/agents/' + encodeURIComponent(a.name) + '/run', {
      method: 'POST', credentials: 'same-origin', signal: agentAbort.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt: text,
        project_id: S.projectID || undefined,
        environment_id: e ? e.id : undefined,
      }),
    });
    if (!res.ok) {
      let msg = await res.text();
      try { msg = JSON.parse(msg).error || msg; } catch (_) { /* plain text */ }
      turn.err = msg;
    } else {
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const raw = buf.slice(0, nl); buf = buf.slice(nl + 1);
          if (!raw.trim()) continue;
          let f;
          try { f = JSON.parse(raw); } catch (_) { continue; }
          if (f.error) turn.err = f.error;
          else if (f.exit_code !== undefined && f.exit_code !== null) turn.exit = f.exit_code;
          // stderr is where these CLIs put their progress chatter. It belongs in
          // the thread: hiding it is how a run that is working looks like a hang.
          else if (f.data) turn.text += f.data;
          renderChat();
        }
      }
    }
  } catch (err) {
    turn.err = err.name === 'AbortError' ? 'stopped' : err.message;
  }
  turn.busy = false; turn.done = true;
  S.chat.busy = false; agentAbort = null;
  renderChat();
  // The agent's work shows up as sandboxes, changes and trace entries.
  await refresh();
}

/* --------------------------------------------------------------- screens --- */

function screenHead(title, badges, actions) {
  return '<div class="wbar"><h2>' + esc(title) + '</h2>' +
    (badges || []).map((b) => '<span class="badge">' + esc(b) + '</span>').join('') +
    '<span class="spacer"></span>' + (actions || '') + '</div>';
}

function emptyState(title, body, cli, action) {
  return '<div class="empty"><h3>' + esc(title) + '</h3>' + body +
    (action ? '<div style="margin-top:14px;">' + action + '</div>' : '') +
    (cli ? '<div class="cli">' + esc(cli) + '</div>' : '') + '</div>';
}

SCREENS.sandboxes = () => {
  const rows = S.sessions.filter(inScope);
  return screenHead('sandboxes', [rows.length + ' in scope'],
    '<button class="primary" data-add="session">New sandbox</button>') +
    '<div class="scroll">' + (rows.length
      ? '<table><thead><tr><th>id</th><th>state</th><th>tier</th><th>mode</th>' +
        '<th>scope</th><th>ttl</th><th></th></tr></thead><tbody>' +
        rows.map((s) => '<tr><td class="mono">' + esc(short(s.id, 12)) + '</td>' +
          '<td>' + esc(s.state) + '</td><td>' + esc(s.tier || '—') + '</td>' +
          '<td>' + esc(s.mode || '—') + '</td>' +
          '<td class="mono">' + esc(s.environment_id || s.project_id || '—') + '</td>' +
          '<td>' + esc(s.ttl || '—') + '</td>' +
          '<td><button class="sm danger" data-killsession="' + esc(s.id) + '">kill</button></td>' +
          '</tr>').join('') + '</tbody></table>'
      : emptyState('No sandbox running',
          'A sandbox is a gVisor or runc container with default-deny egress, dropped ' +
          'capabilities and a read-only rootfs. Nothing runs outside one.',
          'opslify session create --project ' + (S.projectID || '<id>'))) + '</div>';
};

SCREENS.changes = () => {
  const rows = S.changes.filter(inScope);
  return screenHead('changes', [rows.length + ' in scope']) +
    '<div class="scroll">' + (rows.length
      ? '<table><thead><tr><th>id</th><th>status</th><th>blast</th><th>revert</th>' +
        '<th>proposer</th><th>intent</th><th></th></tr></thead><tbody>' +
        rows.map((c) => '<tr><td class="mono">' + esc(short(c.id, 24)) + '</td>' +
          '<td><span class="badge ' + (c.status === 'awaiting_approval' ? 'warn'
            : c.status === 'applied' ? 'ok' : c.status === 'denied' ? 'danger' : '') + '">' +
          esc(c.status) + '</span></td>' +
          '<td>' + esc(c.blast_summary || '—') + '</td>' +
          '<td>' + (c.revertible ? '<span class="badge ok">yes</span>'
            : '<span class="badge danger">no</span>') + '</td>' +
          '<td class="mono">' + esc(short(c.proposer_name || '—', 24)) + '</td>' +
          '<td>' + esc(c.intent || '') + '</td>' +
          '<td><button class="sm" data-open="change:' + esc(c.id) + '">open</button></td>' +
          '</tr>').join('') + '</tbody></table>'
      : emptyState('No changes in this scope',
          'A Change is the infrastructure equivalent of a pull request: intent, ' +
          'preview, blast radius, prepared inverse and a pinned plan. Gated execs ' +
          'and widening policy edits create one.',
          'opslify change ls')) + '</div>';
};

SCREENS.change = (id) => {
  const c = S.changes.find((x) => x.id === id);
  if (!c) return screenHead('change', ['not found']) +
    '<div class="scroll">' + emptyState('That change is gone',
      'It may have been decided from another surface. Reload to re-read the list.') + '</div>';

  const pending = c.status === 'awaiting_approval';
  const steps = (c.steps || []).map((s) =>
    '<div class="gitem"><span class="mono">' + esc((s.argv || []).join(' ')) + '</span>' +
    (s.gated ? '<span class="why" style="color:var(--warn)">gated</span>' : '') + '</div>').join('');

  return screenHead('change ' + short(c.id, 26), [c.status],
    pending
      ? '<button class="approve" data-decide="approve" data-chg="' + esc(c.id) + '">Approve</button>' +
        '<button class="deny" data-decide="deny" data-chg="' + esc(c.id) + '">Deny</button>'
      : '') +
    '<div class="meta4">' +
    '<div class="mcell"><div class="k">proposer</div><div class="v">' +
      esc(c.proposer_name || '—') + '</div></div>' +
    '<div class="mcell"><div class="k">policy rule</div><div class="v">' +
      esc(c.policy_rule || '—') + ' · ' + esc(c.policy_effect || '') + '</div></div>' +
    '<div class="mcell"><div class="k">blast radius</div><div class="v">' +
      esc(c.blast_summary || '—') + '</div></div>' +
    '<div class="mcell"><div class="k">plan hash</div><div class="v">' +
      esc(short(c.plan_hash || '—', 16)) + '</div></div>' +
    '</div>' +
    '<div class="scroll">' +
    '<p class="hint">' + esc(c.intent || '') + '</p>' +
    // Revertibility is stated BEFORE approval, not discovered after a failure.
    // Whether a thing can be undone changes what an operator is willing to let
    // through, so it is a headline, not a footnote.
    '<div class="gsec" style="border:1px solid var(--border);border-radius:6px;margin-bottom:14px;">' +
    '<div class="k">revert ' + (c.revertible
      ? '<span class="badge ok">prepared · ' + esc(c.inverse_kind || '') + '</span>'
      : '<span class="badge danger">not available</span>') + '</div>' +
    '<div class="tag">' + esc(c.revert_reason || (c.revertible
      ? 'an inverse is prepared and will be applied by `opslify change revert`'
      : 'no inverse exists for this change')) + '</div></div>' +
    (c.preview ? '<div class="k tag" style="margin-bottom:6px;">preview</div>' +
      '<div class="diff">' + c.preview.split('\n').map((l) =>
        '<span class="' + (l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : 'cx') + '">' +
        esc(l) + '</span>').join('\n') + '</div>' : '') +
    (steps ? '<div class="k tag" style="margin:14px 0 6px;">pinned plan</div>' +
      '<div style="border:1px solid var(--border);border-radius:6px;padding:9px 12px;">' +
      steps + '</div>' +
      '<p class="tag" style="margin-top:8px;">Approving runs exactly this plan. The hash ' +
      'is re-verified at apply, so an approval cannot be spent on a different one.</p>' : '') +
    '</div>';
};

SCREENS.connections = () => {
  const rows = S.connections.filter(inScope);
  const consumersFor = (ref) => S.consumers.filter((c) => c.secret_ref === ref).length;
  return screenHead('connections', [rows.length + ' in scope'],
    '<button class="primary" data-add="conn">Add connection</button>') +
    '<div class="capbar">a connection names a credential by <b>ref</b> · the daemon ' +
    'injects it at the egress proxy · <b>no value reaches the sandbox or this page</b></div>' +
    '<div class="scroll">' + (rows.length
      ? '<table><thead><tr><th>name</th><th>kind</th><th>secret ref</th><th>hosts</th>' +
        '<th>scope</th><th></th></tr></thead><tbody>' +
        rows.map((c) => '<tr><td class="mono">' + esc(c.name) + '</td>' +
          '<td><span class="badge">' + esc(c.kind) + '</span></td>' +
          '<td class="mono">' + esc(c.secret_ref) +
          ' <span class="tag">· ' + consumersFor(c.secret_ref) + ' consumer(s)</span></td>' +
          '<td class="mono">' + esc((c.hosts || []).join(', ') || '—') + '</td>' +
          '<td class="mono">' + esc(c.scope || '—') + '</td>' +
          '<td><button class="sm danger" data-rmconn="' + esc(c.name) + '">rm</button></td>' +
          '</tr>').join('') + '</tbody></table>'
      : emptyState('No connections in this scope',
          'A connection binds a stored credential to a kind (http, kubernetes, ssh) ' +
          'and a set of hosts. The sandbox reaches the host; the daemon holds the value.',
          'opslify connection add --name <n> --kind http --secret-ref <ref>',
          '<button class="primary lg" data-add="conn">Add a connection</button>')) + '</div>';
};

SCREENS.secrets = () => {
  const rows = S.secrets;
  return screenHead('secrets', [rows.length + ' stored'],
    '<button class="primary" data-add="secret">Store a secret</button>') +
    '<div class="capbar">Values are never shown here — this page holds <b>refs and ' +
    'metadata only</b>, no daemon route returns a value, and deletion and rotation ' +
    'are CLI-only</div>' +
    '<div class="scroll">' + (rows.length
      ? '<table><thead><tr><th>ref</th><th>provider</th><th>scope</th><th>created</th>' +
        '<th>consumers</th></tr></thead><tbody>' +
        rows.map((s) => {
          const used = S.consumers.filter((c) => c.secret_ref === s.ref);
          return '<tr><td class="mono">' + esc(s.ref) + '</td>' +
            '<td>' + esc(s.provider || '—') + '</td>' +
            '<td class="mono">' + esc(s.scope || 'global') + '</td>' +
            '<td>' + esc(fmtAge(s.created_at)) + ' ago</td>' +
            '<td class="mono">' + (used.length
              ? esc(used.map((c) => c.name || c.connection || '?').join(', '))
              : '<span class="tag">unused</span>') + '</td></tr>';
        }).join('') + '</tbody></table>' +
        '<p class="tag" style="margin-top:12px;">Removing a credential breaks every ' +
        'connection bound to it, so it is refused here and available from the CLI, ' +
        'which prints the consumer list first: <span class="mono">opslify secrets rm &lt;ref&gt;</span>.</p>'
      : emptyState('No secrets stored',
          'A secret is stored once, encrypted under the daemon\'s vault key, and ' +
          'referenced by name forever after. Nothing reads it back out.',
          'opslify secrets add <ref> --provider <p>',
          '<button class="primary lg" data-add="secret">Store a secret</button>')) + '</div>';
};

SCREENS.policy = () => {
  const p = S.policy;
  if (!p) return screenHead('policy') + '<div class="scroll">' +
    emptyState('Policy is unavailable', 'The daemon did not return a resolved policy.') + '</div>';
  return screenHead('policy', ['hash ' + short(p.hash, 12)]) +
    '<div class="capbar">daemon → project → environment → workspace · ' +
    '<b>each layer may only narrow the one above it</b></div>' +
    '<div class="scroll">' +
    '<div class="grid3" style="margin-bottom:16px;">' +
    (p.layers || []).map((l) => '<div class="tool' + (l.editable ? '' : '') + '">' +
      '<div class="top"><span class="nm">' + esc(l.layer) + '</span>' +
      '<span class="spacer"></span>' +
      (l.editable ? '<span class="badge accent">editable</span>'
                  : '<span class="badge">locked</span>') + '</div>' +
      '<div class="ds">' + esc(l.note || '') + '</div></div>').join('') +
    '</div>' +
    // Narrowing applies now; widening becomes a Change. That asymmetry is the
    // point of F8.7 and is stated on the form, not buried in the response.
    '<div class="gsec" style="border:1px solid var(--border);border-radius:6px;">' +
    '<div class="k">edit this environment\'s policy</div>' +
    '<div class="grid3" style="gap:14px;">' +
    '<div><label class="fld"><span class="lb">add an approval gate (narrowing)</span>' +
    '<input id="pol-gate" class="mono" placeholder="^kubectl delete"></label>' +
    '<button data-poledit="gate">Add gate — applies immediately</button>' +
    '<div class="hint" style="margin-top:6px;">Tightening never waits for an approver: ' +
    'in an incident that delay is the incident.</div></div>' +
    '<div><label class="fld"><span class="lb">allow an egress host (widening)</span>' +
    '<input id="pol-egress" class="mono" placeholder="gitlab.example.com"></label>' +
    '<button data-poledit="egress">Request — creates a Change</button>' +
    '<div class="hint" style="margin-top:6px;">Opening egress needs approval. The ' +
    'daemon refuses to apply it directly; this button cannot bypass that.</div></div>' +
    '<div><label class="fld"><span class="lb">reason (recorded either way)</span>' +
    '<input id="pol-reason" placeholder="why"></label></div>' +
    '</div></div>' +
    '<p class="tag" style="margin-top:12px;">An applied edit changes the policy hash and ' +
    'binds into the NEXT session. Sandboxes already running keep the hash they started with.</p>' +
    '</div>';
};

SCREENS.shell = () => {
  const sx = shellSession();
  return screenHead('shell', sx ? [short(sx.id, 10), sx.tier || ''] : ['no sandbox']) +
    '<div class="shellfull">' + shellHTML() + '</div>';
};

SCREENS.workspace = () => {
  const t = S.tree;
  if (!t || !t.exists) {
    return screenHead('workspace') + '<div class="scroll">' +
      emptyState('No workspace yet',
        'A workspace is the project\'s directory on this host, mounted read-write at ' +
        '/workspace in every sandbox. Repos you or the agent clone live here, and so does ' +
        '.opslify/memory. It is created when the project first needs one.',
        (t && t.path) ? t.path : 'opslify session create --project ' + (S.projectID || '<id>')) +
      '</div>';
  }
  const entries = t.entries || [];
  return screenHead('workspace', [entries.length + ' entr(ies)']) +
    '<div class="capbar">this is a <b>listing</b> — names and sizes only · raw workspace ' +
    'bytes never reach the browser, and credential-shaped files are withheld entirely</div>' +
    '<div class="scroll">' +
    '<div class="mcell" style="margin-bottom:14px;border:1px solid var(--border);border-radius:6px;">' +
    '<div class="k">host path</div><div class="v">' + esc(t.path) + '</div></div>' +
    '<table><thead><tr><th>path</th><th>kind</th><th>size</th></tr></thead><tbody>' +
    entries.map((e) => {
      const parts = e.rel.split('/');
      const depth = parts.length - 1;
      const leaf = parts[parts.length - 1];
      return '<tr><td class="mono" style="padding-left:' + (9 + depth * 16) + 'px;">' +
        (e.dir ? '<span class="muted">▾ </span>' : '') + esc(leaf) + (e.dir ? '/' : '') +
        '</td>' +
        '<td>' + (e.dir ? 'dir' : 'file') + '</td>' +
        '<td>' + (e.excluded
          ? '<span class="badge warn">withheld — credential-shaped</span>'
          : (e.dir ? '' : esc(fmtBytes(e.bytes)))) + '</td></tr>';
    }).join('') +
    '</tbody></table>' +
    (t.truncated
      ? '<p class="tag" style="color:var(--warn);margin-top:10px;">Listing truncated at the ' +
        'entry cap — there are more files than shown. Open the directory on the host.</p>'
      : '') +
    '<p class="tag" style="margin-top:12px;">Everything here is visible to the sandbox at ' +
    '/workspace and to you on the host. Nothing secret belongs in it — credentials live in ' +
    'the vault and are injected at the egress proxy, never written here.</p>' +
    '</div>';
};

SCREENS.memory = () => {
  const docs = S.memory;
  const hits = S.memHits;
  return screenHead('memory', [docs.length + ' document(s)']) +
    '<div class="capbar">memory is <b>retrieved, not injected</b> — the agent searches it and ' +
    'cites what it used · a rule it must always follow is a <b>skill</b>; a document it might ' +
    'need to consult is <b>memory</b></div>' +
    '<div class="scroll">' +
    '<div class="envedit" style="margin-bottom:16px;">' +
    '<label class="fld" style="flex:1 1 320px;"><span class="lb">search this memory as the agent does</span>' +
    '<input id="memq" class="mono" value="' + esc(S.memQuery) + '" ' +
    'placeholder="how do we roll back a bad release"></label>' +
    '<button class="primary" data-memsearch="1">Search</button>' +
    (hits ? '<button data-memclear="1">Clear</button>' : '') +
    '</div>' +
    (hits
      ? (hits.length
          ? '<div class="k tag" style="margin-bottom:8px;">' + hits.length +
            ' excerpt(s), best first — this is exactly what the agent receives</div>' +
            hits.map((e) =>
              '<div class="envcard" style="display:block;margin-bottom:11px;">' +
              '<div style="display:flex;align-items:center;gap:9px;margin-bottom:7px;">' +
              '<span class="nm">' + esc(e.doc) + ':' + e.start_line + '-' + e.end_line + '</span>' +
              (e.heading ? '<span class="badge">' + esc(e.heading) + '</span>' : '') +
              (e.truncated ? '<span class="badge warn">truncated</span>' : '') +
              '</div>' +
              '<div class="agentout" style="color:var(--muted);">' + esc(e.text) + '</div>' +
              '</div>').join('')
          : '<p class="tag">no matches for ' + esc(S.memQuery) + '</p>')
      : '') +
    (docs.length
      ? '<div class="k tag" style="margin:16px 0 6px;">documents</div>' +
        '<table><thead><tr><th>document</th><th>title</th><th>chunks</th><th>bytes</th>' +
        '<th>state</th><th></th></tr></thead><tbody>' +
        docs.map((d) => '<tr><td class="mono">' + esc(d.rel) + '</td>' +
          '<td>' + esc(d.title || '') + '</td>' +
          '<td>' + esc(String(d.chunks)) + '</td>' +
          '<td>' + esc(String(d.bytes)) + '</td>' +
          '<td>' + (d.enabled ? '<span class="badge ok">enabled</span>'
                              : '<span class="badge danger">disabled</span>') + '</td>' +
          '<td><button class="sm" data-memtoggle="' + esc(d.rel) + '" ' +
          'data-memon="' + (d.enabled ? '0' : '1') + '">' +
          (d.enabled ? 'disable' : 'enable') + '</button></td></tr>').join('') +
        '</tbody></table>'
      : emptyState('No memory documents',
          'Put markdown in the project workspace under .opslify/memory/ (or .claude/memory/, ' +
          'docs/memory/, memory/) and it is indexed on the next search. Clone it with the repo ' +
          'so the runbooks travel with the code.',
          'opslify memory ls --project ' + (S.projectID || '<id>'))) +
    '<p class="tag" style="margin-top:14px;">There is no upload button, deliberately. Memory is ' +
    'reviewed files in the repository; a second path into what the agent reads would be a way ' +
    'around that review. The agent can search this and nothing else — it has no write path.</p>' +
    '</div>';
};

SCREENS.tools = () => {
  const p = project();
  if (!p) return screenHead('tools') + '<div class="scroll">' +
    emptyState('No project selected', 'Tools are recorded per project.') + '</div>';
  const caps = p.capabilities || {};
  const roles = Object.keys(caps).sort();
  const known = (tool) => TOOLS.find((t) => t.id === tool);

  return screenHead('tools · ' + p.name, [roles.length + ' recorded'],
    '<button class="primary" data-add="tool">Add a tool</button>') +
    '<div class="capbar">a tool is a <b>role → tool</b> entry on the project · F8.4 routes ' +
    'skill packs off it and F8.2 binds connections to it · <b>it is not a guardrail</b></div>' +
    '<div class="scroll">' + (roles.length
      ? '<table><thead><tr><th>role</th><th>tool</th><th>implies</th><th></th></tr></thead><tbody>' +
        roles.map((r) => {
          const k = known(caps[r]);
          // Whether this tool can actually reach anything is the column that
          // matters. A tool with no credential is a label; the button next to it
          // is how it stops being one.
          const ref = k && k.secret ? k.secret.ref : '';
          const stored = ref && S.secrets.some((x) => x.ref === ref);
          const wired = ref && S.connections.some((c) => c.secret_ref === ref && inScope(c));
          return '<tr><td class="mono">' + esc(r) + '</td>' +
            '<td class="mono">' + esc(caps[r]) + '</td>' +
            '<td>' + (k
              ? (k.gates.length ? '<span class="badge warn">' + k.gates.length + ' gate(s)</span> ' : '') +
                (k.hosts.length ? '<span class="badge">' + k.hosts.length + ' host(s)</span> ' : '')
              : '<span class="tag">not in the catalogue</span>') + '</td>' +
            '<td>' + (!k || !k.secret
              ? '<span class="tag">none needed</span>'
              : wired
                ? '<span class="badge ok">connected · ' + esc(ref) + '</span>'
                : stored
                  ? '<span class="badge warn">secret stored, not bound</span>'
                  : '<span class="badge danger">no credential</span>') + '</td>' +
            '<td>' + (k && k.secret
              ? '<button class="sm primary" data-toolcred="' + esc(k.id) + '">' +
                (wired ? 'replace' : 'add credential') + '</button> '
              : '') +
            '<button class="sm danger" data-rmtool="' + esc(r) + '">rm</button></td></tr>';
        }).join('') + '</tbody></table>' +
        '<p class="tag" style="margin-top:12px;">Recording a tool does not open anything. ' +
        'The gates and egress it implies are separate policy edits — narrowing applies at ' +
        'once, widening becomes a Change.</p>'
      : emptyState('No tools recorded',
          'A tool says which CLI this project uses for a role — git=gitlab, iac=terraform. ' +
          'It is how skills and connections find each other.',
          'opslify project tools add ' + p.id + ' git=gitlab',
          '<button class="primary lg" data-add="tool">Add a tool</button>')) + '</div>';
};

SCREENS.agents = () => {
  const rows = S.agents;
  return screenHead('agents', [rows.length + ' registered']) +
    '<div class="capbar">registering an agent <b>runs its command on this host</b>, so it ' +
    'is CLI-only · binding an already-registered one executes nothing and is allowed here</div>' +
    '<div class="scroll">' + (rows.length
      ? '<table><thead><tr><th>name</th><th>model</th><th>locality</th><th>command</th>' +
        '<th>description</th><th></th></tr></thead><tbody>' +
        rows.map((a) => '<tr><td class="mono">' + esc(a.name) + '</td>' +
          '<td>' + esc(a.model_hint || '—') + '</td>' +
          '<td>' + (a.locality === 'local'
            ? '<span class="badge ok">on-host</span>'
            : '<span class="badge warn">' + esc(a.locality || 'unknown') + ' · off-host</span>') + '</td>' +
          '<td class="mono">' + esc(a.flavour || '—') + '</td>' +
          '<td>' + (a.drivable
            ? '<span class="badge ok">yes</span>'
            : '<span class="badge">no — registered without a flavour</span>') + '</td>' +
          '<td><button class="sm" data-bind="' + esc(a.name) + '">bind</button></td>' +
          '</tr>').join('') + '</tbody></table>' +
        '<p class="tag" style="margin-top:12px;">An agent whose locality is unknown is ' +
        'shown as off-host. Claiming a prompt stayed on this machine when nobody said ' +
        'so is the one thing this table must not do.</p>'
      : emptyState('No agents registered',
          'An agent is an MCP-speaking command. Registering one probes it with a real ' +
          'handshake, which means running it — so that stays on the CLI, where the ' +
          'launch token is not the only thing between a web page and host execution.',
          'opslify agent add <name> --command <cmd>')) + '</div>';
};

/* ---------------------------------------------------------------- wizard --- */

// The tool catalogue. Each entry says what selecting it IMPLIES — the gates it
// adds, the hosts it needs, the credential it wants. Those implications are
// shown before the project is created, because a guardrail the operator did not
// know they were accepting is not a guardrail they will keep.
const TOOLS = [
  { id: 'gitlab', role: 'git', name: 'GitLab', desc: 'Repos, MRs, pipelines',
    hosts: ['gitlab.com'], secret: { ref: 'gitlab-token', kind: 'http', provider: 'gitlab' },
    gates: [], note: 'MR-only mode available' },
  { id: 'kubernetes', role: 'k8s', name: 'Kubernetes', desc: 'kubectl against a cluster',
    hosts: [], secret: { ref: 'kubeconfig', kind: 'kubernetes', provider: 'kubeconfig' },
    // A kubernetes connection needs exactly one host — the cluster API — and only
    // the operator knows it. Asked for rather than guessed.
    needsHost: true, hostLabel: 'cluster API host',
    gates: ['^kubectl delete', '^kubectl scale', '^kubectl patch'], note: '3 approval gates' },
  { id: 'terraform', role: 'iac', name: 'Terraform', desc: 'Plan and apply infrastructure',
    hosts: ['registry.terraform.io'], secret: null,
    gates: ['^terraform apply', '^terraform destroy'], note: 'plan pinning' },
  { id: 'argocd', role: 'deploy', name: 'ArgoCD', desc: 'GitOps sync',
    hosts: [], secret: { ref: 'argocd-token', kind: 'http', provider: 'argocd' },
    needsHost: true, hostLabel: 'ArgoCD server host',
    gates: ['^argocd app delete'], note: '1 approval gate' },
  { id: 'aws', role: 'cloud', name: 'AWS', desc: 'STS AssumeRole, scoped per session',
    hosts: ['sts.amazonaws.com'], secret: { ref: 'aws-creds', kind: 'http', provider: 'aws' },
    gates: ['^aws .* delete'], note: 'scope-down required' },
  { id: 'azure', role: 'cloud', name: 'Azure', desc: 'az CLI with scoped creds',
    hosts: ['management.azure.com'], secret: { ref: 'azure-sp', kind: 'http', provider: 'azure' },
    gates: ['^az group delete'], note: 'scope-down required' },
  { id: 'helm', role: 'charts', name: 'Helm', desc: 'Chart templating and upgrades',
    hosts: [], secret: null, gates: ['^helm uninstall'], note: '' },
  { id: 'docker', role: 'build', name: 'Docker', desc: 'Build and push images',
    hosts: ['registry-1.docker.io'], secret: null, gates: [], note: '' },
];

const W = {
  open: false, step: 0,
  name: '', repo: '', wsPath: '',
  envs: [{ name: 'staging', production: false }, { name: 'prod', production: true }],
  tools: {},
  creds: {},   // toolID -> {mode:'existing'|'new', ref, value}
  busy: false,
};

const wizTools = () => TOOLS.filter((t) => W.tools[t.id]);
const wizGates = () => wizTools().reduce((a, t) => a.concat(t.gates), []);
const wizHosts = () => wizTools().reduce((a, t) => {
  const c = W.creds[t.id] || {};
  // An operator-supplied host needs egress just as much as a catalogue one.
  return a.concat(t.hosts, c.host ? [c.host] : []);
}, []);
const wizSecrets = () => wizTools().filter((t) => t.secret);

const STEPS = ['Project', 'Environments', 'Tools & guardrails', 'Credentials'];

function renderWizard() {
  if (!W.open) { $('overlay').innerHTML = ''; return; }
  const stepsBar = STEPS.map((s, i) =>
    '<div class="step' + (i === W.step ? ' on' : i < W.step ? ' done' : '') + '">' +
    '<span class="num">' + (i < W.step ? '✓' : i + 1) + '</span>' + esc(s) + '</div>' +
    (i < STEPS.length - 1 ? '<div class="sep"></div>' : '')).join('');

  $('overlay').innerHTML = '<div class="wizwrap">' +
    '<div class="hdr"><h1>opslify</h1><span class="tag">new project</span>' +
    (W.name ? '<span class="rule"></span><span class="crumb">' + esc(W.name) + '</span>' : '') +
    '<span class="spacer"></span>' +
    '<span class="tag">step ' + (W.step + 1) + ' of ' + STEPS.length + '</span>' +
    '<button class="sm" data-wizcancel="1">Cancel</button></div>' +
    '<div class="steps">' + stepsBar + '</div>' +
    '<div class="wizbody">' +
    '<div class="wizleft">' + wizLeft() + '</div>' +
    '<div class="wizright">' + wizRight() + '</div>' +
    '</div>' +
    '<div class="ftr">' +
    '<button class="lg" data-wizback="1"' + (W.step === 0 ? ' disabled' : '') + '>Back</button>' +
    '<span class="spacer"></span>' +
    '<span class="tag" id="wizmsg"></span>' +
    '<button class="primary lg" data-wiznext="1"' + (W.busy ? ' disabled' : '') + '>' +
    (W.step === STEPS.length - 1 ? (W.busy ? 'Creating…' : 'Create project') : 'Continue') +
    '</button></div></div>';
}

function wizLeft() {
  if (W.step === 0) {
    return '<h2>Name the project</h2>' +
      '<p class="hint">A project groups environments, connections, policy and changes. ' +
      'Everything else in the cockpit hangs off it.</p>' +
      '<label class="fld"><span class="lb">project name</span>' +
      '<input id="w-name" class="mono" value="' + esc(W.name) + '" placeholder="tripon" autofocus>' +
      '<span class="hint">Lowercase letters, digits and dashes.</span></label>' +
      '<label class="fld"><span class="lb">repository url (optional)</span>' +
      '<input id="w-repo" class="mono" value="' + esc(W.repo) + '" ' +
      'placeholder="gitlab.example.com/team/infra"></label>' +
      '<label class="fld"><span class="lb">workspace directory (optional)</span>' +
      '<input id="w-ws" class="mono" value="' + esc(W.wsPath) + '" ' +
      'placeholder="/home/you/opslify-workspace/' + esc(W.name || 'project') + '">' +
      '<span class="hint">A host directory mounted at /workspace in every sandbox for this ' +
      'project. The agent clones and edits here; you open the same files in your editor. ' +
      'Leave blank and the daemon manages one.<br><br>' +
      'Use a DEDICATED directory, not your home. A bind mount has no credential filter, so ' +
      'everything in it is readable by every sandbox — including a .env or a .ssh that ' +
      'happens to be sitting there.</span></label>';
  }
  if (W.step === 1) {
    return '<h2>Environments</h2>' +
      '<p class="hint">Each environment resolves its own policy and may only narrow the ' +
      'project\'s. Marking one production is not cosmetic — it is what later gates key off.</p>' +
      '<div class="envlist">' + W.envs.map((e, i) =>
        '<div class="envcard' + (e.production ? ' prod' : '') + '">' +
        '<span class="nm">' + esc(e.name) + '</span>' +
        (e.production ? '<span class="badge danger">production</span>'
                      : '<span class="badge">non-production</span>') +
        '<span class="spacer"></span>' +
        '<button class="sm danger" data-wizrmenv="' + i + '">remove</button></div>').join('') +
      '</div>' +
      '<div class="envedit">' +
      '<label class="fld"><span class="lb">add an environment</span>' +
      '<input id="w-env" class="mono" placeholder="staging"></label>' +
      '<label class="check"><input type="checkbox" id="w-envprod"> production</label>' +
      '<button data-wizaddenv="1">Add</button></div>' +
      (W.envs.length ? '' : '<p class="hint" style="color:var(--warn)">At least one environment.</p>');
  }
  if (W.step === 2) {
    return '<h2>Which tools does this project use?</h2>' +
      '<p class="hint">Selecting a tool records a capability on the project and proposes the ' +
      'guardrails that go with it. Everything proposed is shown on the right before anything ' +
      'is created.</p>' +
      '<div class="grid3">' + TOOLS.map((t) =>
        '<div class="tool' + (W.tools[t.id] ? ' on' : '') + '" data-wiztool="' + t.id + '">' +
        '<div class="top"><span class="box">✓</span><span class="nm">' + esc(t.name) + '</span></div>' +
        '<div class="ds">' + esc(t.desc) + '</div>' +
        (t.note ? '<div class="im">+ ' + esc(t.note) + '</div>' : '') +
        '</div>').join('') + '</div>';
  }
  // Step 4 — credentials
  const needed = wizSecrets();
  if (!needed.length) {
    return '<h2>Credentials</h2>' +
      '<p class="hint">None of the selected tools needs a stored credential. You can add ' +
      'connections later from the Connections screen.</p>';
  }
  return '<h2>Credentials to bind</h2>' +
    '<p class="hint">A value typed here is encrypted under the daemon\'s vault key and ' +
    'referenced by name forever after. No route — not this page, not the sandbox — reads ' +
    'one back out.</p>' +
    needed.map((t) => {
      const c = W.creds[t.id] || {};
      const existing = S.secrets.some((s) => s.ref === (c.ref || t.secret.ref));
      return '<div class="envcard" style="display:block;margin-bottom:11px;">' +
        '<div style="display:flex;align-items:center;gap:9px;margin-bottom:9px;">' +
        '<span class="nm">' + esc(t.name) + '</span>' +
        '<span class="badge">' + esc(t.secret.kind) + '</span>' +
        (existing ? '<span class="badge ok">ref exists — will reuse</span>'
                  : '<span class="badge warn">needs a value</span>') + '</div>' +
        '<label class="fld"><span class="lb">secret ref</span>' +
        '<input class="mono" data-wizref="' + t.id + '" value="' +
        esc(c.ref || t.secret.ref) + '"></label>' +
        (existing ? '<div class="hint">A secret with this ref is already stored. Leave it ' +
                    'to reuse; change the ref to store a separate one.</div>'
                  : '<label class="fld"><span class="lb">value</span>' +
                    '<input type="password" class="mono" data-wizval="' + t.id + '" value="' +
                    esc(c.value || '') + '" placeholder="paste the token"></label>') +
        (t.needsHost
          ? '<label class="fld"><span class="lb">' + esc(t.hostLabel || 'host') + '</span>' +
            '<input class="mono" data-wizhost="' + t.id + '" value="' + esc(c.host || '') +
            '" placeholder="api.cluster.example.com"></label>'
          : '') +
        '<div class="hint">Leave blank to skip. The tool is still recorded on the project — ' +
        'you can add the credential later from the Tools screen, and nothing here is ' +
        'half-created.</div>' +
        '</div>';
    }).join('');
}

function wizRight() {
  const gates = wizGates(); const hosts = wizHosts(); const tools = wizTools();

  if (W.step < 2) {
    return '<div class="rhdr"><h3>What gets created</h3>' +
      '<span class="badge auto">preview</span></div>' +
      '<div class="rbody"><div class="gsec">' +
      '<div class="k">project</div>' +
      '<div class="gitem"><span class="mono">' + esc(W.name || '<name>') + '</span></div>' +
      (W.repo ? '<div class="gitem"><span class="mono muted">' + esc(W.repo) + '</span></div>' : '') +
      (W.wsPath
        ? '<div class="gitem"><span class="mono">' + esc(W.wsPath) + '</span>' +
          '<span class="why">your directory</span></div>'
        : '<div class="gitem muted">workspace managed by the daemon</div>') +
      '</div><div class="gsec"><div class="k">environments</div>' +
      (W.envs.length ? W.envs.map((e) => '<div class="gitem"><span class="mono">' + esc(e.name) +
        '</span>' + (e.production ? '<span class="why" style="color:var(--danger)">production</span>'
        : '') + '</div>').join('') : '<div class="gitem muted">none yet</div>') +
      '</div></div>';
  }

  return '<div class="rhdr"><h3>Guardrails</h3>' +
    '<span class="badge auto">generated from ' + tools.length + ' tool' +
    (tools.length === 1 ? '' : 's') + '</span></div>' +
    '<div class="rbody">' +
    '<div class="gsec"><div class="k">Requires human approval ' +
    '<span class="badge warn">' + gates.length + ' rules</span></div>' +
    (gates.length ? gates.map((g) => '<div class="gitem"><span class="gate">' + esc(g) + '</span>' +
      '<span class="why">' + esc((tools.find((t) => t.gates.includes(g)) || {}).id || '') +
      '</span></div>').join('')
      : '<div class="gitem muted">none — no selected tool proposes one</div>') +
    '<div class="hint" style="margin-top:8px;">Gates NARROW the policy, so they apply the ' +
    'moment the project is created. No approval needed to tighten.</div>' +
    '</div>' +
    '<div class="gsec"><div class="k">Network the sandbox may reach ' +
    '<span class="badge ' + (hosts.length ? 'warn' : '') + '">' + hosts.length + ' hosts</span></div>' +
    (hosts.length ? hosts.map((h) => '<div class="gitem"><span class="mono">' + esc(h) + '</span>' +
      '<span class="why">' + esc((tools.find((t) => t.hosts.includes(h)) || {}).id || '') +
      '</span></div>').join('')
      : '<div class="gitem muted">nothing — egress stays default-deny</div>') +
    // This is the honest part. Opening egress is a widening edit, and the daemon
    // will refuse to apply it without approval. Saying so here means the pending
    // Changes at the end are expected, not a surprise.
    (hosts.length ? '<div class="hint" style="margin-top:8px;color:var(--warn)">' +
      'Allowing a host WIDENS the policy, so each of these becomes a Change awaiting ' +
      'approval. The project and its gates are created immediately; egress is not open ' +
      'until you approve them.</div>' : '') +
    '</div>' +
    '<div class="gsec"><div class="k">Credentials to bind ' +
    '<span class="badge">step 4</span></div>' +
    (wizSecrets().length ? wizSecrets().map((t) => {
      const ref = (W.creds[t.id] || {}).ref || t.secret.ref;
      const have = S.secrets.some((s) => s.ref === ref);
      return '<div class="gitem"><span class="mono">' + esc(ref) + '</span>' +
        '<span class="why" style="color:var(--' + (have ? 'ok' : 'warn') + ')">' +
        (have ? 'reuse existing' : 'needs value') + '</span></div>';
    }).join('') : '<div class="gitem muted">none required</div>') +
    '</div>' +
    '<div class="gsec"><div class="k">resulting capabilities</div>' +
    '<div class="yaml">' + (tools.length
      ? tools.map((t) => '<span class="yk">' + esc(t.role) + '</span>: <span class="yv">' +
          esc(t.id) + '</span>').join('\n')
      : '<span class="yc"># no tools selected</span>') + '</div></div>' +
    '</div>';
}

function wizCollect() {
  if (W.step === 0) {
    const n = $('w-name'); const r = $('w-repo'); const ws = $('w-ws');
    if (n) W.name = n.value.trim();
    if (r) W.repo = r.value.trim();
    if (ws) W.wsPath = ws.value.trim();
  }
  if (W.step === 3) {
    document.querySelectorAll('[data-wizref]').forEach((el) => {
      const id = el.getAttribute('data-wizref');
      W.creds[id] = Object.assign({}, W.creds[id], { ref: el.value.trim() });
    });
    document.querySelectorAll('[data-wizval]').forEach((el) => {
      const id = el.getAttribute('data-wizval');
      W.creds[id] = Object.assign({}, W.creds[id], { value: el.value });
    });
    document.querySelectorAll('[data-wizhost]').forEach((el) => {
      const id = el.getAttribute('data-wizhost');
      W.creds[id] = Object.assign({}, W.creds[id], { host: el.value.trim() });
    });
  }
}

function wizValidate() {
  if (W.step === 0) {
    if (!W.name) return 'a project needs a name';
    if (!/^[a-z0-9][a-z0-9-]*$/.test(W.name)) {
      return 'lowercase letters, digits and dashes, starting with a letter or digit';
    }
    if (S.projects.some((p) => p.id === W.name || p.name === W.name)) {
      return 'a project called "' + W.name + '" already exists';
    }
  }
  if (W.step === 1 && !W.envs.length) return 'at least one environment';
  return null;
}

// wizCreate does the whole flow in the order that leaves the least mess if a
// later step fails: the project first (everything else references it), then
// secrets, then connections, then the narrowing gates, and only then the egress
// requests, which do not apply anyway. A failure part-way leaves a real project
// the operator can finish by hand, not a half-object.
async function wizCreate() {
  W.busy = true; renderWizard();
  const done = []; const failed = [];

  try {
    const caps = {};
    wizTools().forEach((t) => { caps[t.role] = t.id; });
    const created = await send('POST', '/v1/projects', {
      name: W.name,
      repo_url: W.repo || undefined,
      workspace_path: W.wsPath || undefined,
      capabilities: Object.keys(caps).length ? caps : undefined,
      environments: W.envs.map((e) => ({ name: e.name, production: e.production })),
    });
    done.push('project ' + W.name + ' with ' + W.envs.length + ' environment(s)');
    // A bind mount has no credential filter, so this is the one moment the
    // operator can be told what they just exposed.
    const warn = (created && created.workspace_warnings) || [];
    if (warn.length) {
      toast(warn.length + ' credential-shaped file(s) in that directory — the agent can read ' +
        'all of them: ' + warn.slice(0, 4).map((f) => f.rel).join(', ') +
        (warn.length > 4 ? ', …' : '') + '. Move them out or use a directory of only code.', 'bad');
    }
  } catch (e) {
    W.busy = false; renderWizard();
    toast('could not create the project: ' + e.message, 'bad');
    return;
  }

  for (const t of wizSecrets()) {
    const c = W.creds[t.id] || {};
    const ref = c.ref || t.secret.ref;
    if (S.secrets.some((s) => s.ref === ref)) continue;   // reuse
    if (!c.value) continue;                               // skipped deliberately
    try {
      await send('POST', '/v1/secrets', {
        ref, provider: t.secret.provider, value_b64: b64(c.value),
      });
      done.push('secret ' + ref);
    } catch (e) { failed.push('secret ' + ref + ': ' + e.message); }
  }

  // A connection is created only when it can actually work.
  //
  // The first version made one for every selected tool regardless, which failed
  // outright for Kubernetes: that kind needs exactly one host — the cluster API —
  // and the catalogue has none to offer, so picking Kubernetes in the wizard
  // ended in a 400 after the project had already been created. A half-finished
  // onboarding that reports an error is worse than one that says plainly what is
  // still missing.
  const skipped = [];
  for (const t of wizSecrets()) {
    const c = W.creds[t.id] || {};
    const ref = c.ref || t.secret.ref;
    const haveSecret = S.secrets.some((x) => x.ref === ref) || !!c.value;
    const hosts = t.hosts.length ? t.hosts.slice() : (c.host ? [c.host] : []);
    if (!haveSecret) { skipped.push(t.name + ' (no credential given)'); continue; }
    if (t.needsHost && !hosts.length) { skipped.push(t.name + ' (no ' + (t.hostLabel || 'host') + ')'); continue; }
    try {
      await send('POST', '/v1/connections', {
        name: t.id, kind: t.secret.kind, secret_ref: ref,
        hosts: hosts.length ? hosts : undefined,
        project_id: W.name,
      });
      done.push('connection ' + t.id);
    } catch (e) { failed.push('connection ' + t.id + ': ' + e.message); }
  }

  const gates = wizGates();
  if (gates.length) {
    try {
      await send('POST', '/v1/policy/edit', {
        project_id: W.name, reason: 'guardrails generated when the project was created',
        add_gates: gates,
      });
      done.push(gates.length + ' approval gate(s), applied');
    } catch (e) { failed.push('gates: ' + e.message); }
  }

  const hosts = wizHosts();
  let pending = 0;
  if (hosts.length) {
    try {
      const r = await send('POST', '/v1/policy/edit', {
        project_id: W.name, reason: 'egress for the tools selected at project creation',
        add_egress: hosts,
      });
      if (r && r.applied) { done.push(hosts.length + ' egress host(s), applied'); }
      else { pending = hosts.length; done.push(hosts.length + ' egress host(s) → change ' + (r && r.change_id ? short(r.change_id, 24) : 'awaiting approval')); }
    } catch (e) { failed.push('egress: ' + e.message); }
  }

  W.busy = false; W.open = false;
  S.projectID = W.name; S.envID = null;
  await refresh();

  toast('created: ' + done.join('; '), 'ok');
  if (skipped.length) {
    toast('still to do: ' + skipped.join(', ') +
      ' — add these from the Tools screen when you have them', null);
  }
  if (pending) {
    toast(pending + ' egress host(s) need approval before the sandbox can reach them — ' +
      'see Changes.', null);
    openTab('changes', null, 'changes');
  }
  if (failed.length) toast('some steps failed: ' + failed.join('; '), 'bad');
}

function wizReset() {
  W.step = 0; W.name = ''; W.repo = ''; W.wsPath = '';
  W.envs = [{ name: 'staging', production: false }, { name: 'prod', production: true }];
  W.tools = {}; W.creds = {}; W.busy = false;
}

/* ----------------------------------------------------------------- modals -- */

function modal(title, bodyHTML, okLabel, onOK) {
  $('overlay').innerHTML = '<div class="modalwrap"><div class="modal">' +
    '<div class="mh"><h3>' + esc(title) + '</h3><span class="spacer"></span>' +
    '<button class="sm" data-modalcancel="1">✕</button></div>' +
    '<div class="mb">' + bodyHTML + '</div>' +
    '<div class="mf"><span class="spacer"></span>' +
    '<button data-modalcancel="1">Cancel</button>' +
    '<button class="primary" data-modalok="1">' + esc(okLabel) + '</button></div>' +
    '</div></div>';
  $('overlay').__ok = onOK;
}

const closeOverlay = () => { $('overlay').innerHTML = ''; $('overlay').__ok = null; };

function addEnvModal() {
  const p = project();
  if (!p) return;
  modal('Add an environment to ' + p.name,
    '<label class="fld"><span class="lb">name</span>' +
    '<input id="m-env" class="mono" placeholder="staging" autofocus></label>' +
    '<label class="check"><input type="checkbox" id="m-prod"> production</label>' +
    '<p class="hint" style="margin-top:11px;">An environment may only narrow the project\'s ' +
    'policy, never widen it.</p>',
    'Add', async () => {
      const name = $('m-env').value.trim();
      if (!name) throw new Error('a name is required');
      await send('POST', '/v1/projects/' + encodeURIComponent(p.id) + '/environments',
        { name, production: $('m-prod').checked });
      toast('environment ' + name + ' added', 'ok');
    });
}

function addConnModal() {
  const refs = S.secrets.map((s) => '<option value="' + esc(s.ref) + '">' + esc(s.ref) + '</option>');
  modal('Add a connection',
    (refs.length ? '' : '<div class="err">No secret is stored yet. A connection references ' +
      'a credential by ref, so store one first.</div>') +
    '<label class="fld"><span class="lb">name</span><input id="m-cname" class="mono" autofocus></label>' +
    '<label class="fld"><span class="lb">kind</span><select id="m-ckind">' +
    '<option value="http">http</option><option value="kubernetes">kubernetes</option>' +
    '<option value="ssh">ssh</option></select></label>' +
    '<label class="fld"><span class="lb">secret ref</span><select id="m-cref">' +
    refs.join('') + '</select>' +
    '<span class="hint">The daemon injects this at the egress proxy. The value never ' +
    'enters the sandbox.</span></label>' +
    '<label class="fld"><span class="lb">hosts (comma separated)</span>' +
    '<input id="m-chosts" class="mono" placeholder="gitlab.example.com"></label>',
    'Add', async () => {
      const name = $('m-cname').value.trim();
      const ref = $('m-cref').value;
      if (!name) throw new Error('a name is required');
      if (!ref) throw new Error('a secret ref is required — store a secret first');
      const hosts = $('m-chosts').value.split(',').map((h) => h.trim()).filter(Boolean);
      await send('POST', '/v1/connections', {
        name, kind: $('m-ckind').value, secret_ref: ref,
        hosts: hosts.length ? hosts : undefined,
        project_id: S.projectID || undefined,
      });
      toast('connection ' + name + ' added', 'ok');
    });
}

function addSecretModal() {
  modal('Store a secret',
    '<label class="fld"><span class="lb">ref</span>' +
    '<input id="m-sref" class="mono" placeholder="gitlab-token" autofocus>' +
    '<span class="hint">The name you will reference forever after.</span></label>' +
    '<label class="fld"><span class="lb">provider (optional)</span>' +
    '<input id="m-sprov" class="mono" placeholder="gitlab"></label>' +
    '<label class="fld"><span class="lb">value</span>' +
    '<input id="m-sval" type="password" class="mono" placeholder="paste the token"></label>' +
    '<p class="hint">Encrypted under the daemon\'s vault key on arrival. No route returns ' +
    'it — not to this page, not to a sandbox. Rotation and deletion are CLI-only, because ' +
    'both break whatever already holds the old value.</p>',
    'Store', async () => {
      const ref = $('m-sref').value.trim();
      const val = $('m-sval').value;
      if (!ref) throw new Error('a ref is required');
      if (!val) throw new Error('a value is required');
      await send('POST', '/v1/secrets', {
        ref, provider: $('m-sprov').value.trim() || undefined, value_b64: b64(val),
      });
      toast('secret ' + ref + ' stored', 'ok');
    });
}

// addToolModal writes the WHOLE capability map back, because that is what the
// daemon route takes. Reading the current map and sending the result keeps the
// page honest about what it is replacing.
function addToolModal() {
  const p = project();
  if (!p) { toast('select a project first', 'bad'); return; }
  const caps = p.capabilities || {};
  const picked = TOOLS.filter((t) => caps[t.role] !== t.id);

  modal('Add a tool to ' + p.name,
    '<p class="hint">Pick one from the catalogue, or name a role and tool yourself. ' +
    'What the tool implies — gates, egress, a credential — is shown, and none of it is ' +
    'applied here: this records the capability only.</p>' +
    '<div class="grid3" style="margin-bottom:14px;">' + picked.map((t) =>
      '<div class="tool" data-picktool="' + esc(t.id) + '">' +
      '<div class="top"><span class="box">✓</span><span class="nm">' + esc(t.name) + '</span></div>' +
      '<div class="ds">' + esc(t.role) + ' = ' + esc(t.id) + '</div>' +
      (t.gates.length || t.hosts.length
        ? '<div class="im">' + (t.gates.length ? t.gates.length + ' gate(s) ' : '') +
          (t.hosts.length ? t.hosts.length + ' host(s)' : '') + '</div>'
        : '') +
      '</div>').join('') +
    (picked.length ? '' : '<p class="tag">every catalogue tool is already recorded</p>') +
    '</div>' +
    '<label class="fld"><span class="lb">role</span>' +
    '<input id="m-trole" class="mono" placeholder="git"></label>' +
    '<label class="fld"><span class="lb">tool</span>' +
    '<input id="m-ttool" class="mono" placeholder="gitlab"></label>' +
    '<label class="check"><input type="checkbox" id="m-tguard" checked> ' +
    'also add the approval gates this tool implies</label>' +
    '<div class="hint" style="margin-top:6px;">Gates narrow the policy, so they apply ' +
    'immediately. Egress is never added here — that widens, and needs a Change.</div>',
    'Add', async () => {
      const role = $('m-trole').value.trim();
      const tool = $('m-ttool').value.trim();
      if (!role || !tool) throw new Error('a role and a tool are both required');
      const next = Object.assign({}, caps);
      next[role] = tool;
      await send('PUT', '/v1/projects/' + encodeURIComponent(p.id) + '/capabilities',
        { capabilities: next });

      const cat = TOOLS.find((t) => t.id === tool);
      if (cat && cat.gates.length && $('m-tguard').checked) {
        try {
          await send('POST', '/v1/policy/edit', {
            project_id: p.id, reason: 'guardrails for tool ' + tool,
            add_gates: cat.gates,
          });
          toast('tool ' + role + '=' + tool + ' added, with ' + cat.gates.length +
            ' gate(s) applied', 'ok');
          return;
        } catch (e) {
          // The capability landed; say so rather than implying the whole thing failed.
          toast('tool added, but its gates did not apply: ' + e.message, 'bad');
          return;
        }
      }
      toast('tool ' + role + '=' + tool + ' added', 'ok');
    });
}

// addAgentModal offers the daemon's catalogue. The browser sends an ENTRY ID; the
// daemon resolves the binary from its own compile-time list and probes it. A
// caller cannot name a command, which is what makes this reachable from a page at
// all — registering an agent runs it.
function addAgentModal() {
  const entries = S.catalogue;
  if (!entries.length) {
    modal('Connect an agent',
      '<div class="err">The daemon returned no catalogue. It may be an older build.</div>' +
      '<p class="hint">Register by path instead:</p>' +
      '<div class="cli">opslify agent add claude --command /usr/bin/claude --arg mcp --arg serve \\<br>' +
      '&nbsp;&nbsp;--flavour claude --locality hosted</div>',
      'Close', async () => {});
    return;
  }
  modal('Connect an agent',
    '<p class="hint">opslify drives the agent you already have. Your subscription or API key ' +
    'stays inside that CLI — the daemon never sees it, and never asks for one.</p>' +
    '<div class="grid3" style="margin-bottom:14px;">' + entries.map((e) =>
      '<div class="tool' + (e.found ? '' : ' off') + '" data-pickagent="' + esc(e.id) + '">' +
      '<div class="top"><span class="box">✓</span><span class="nm">' + esc(e.title) + '</span></div>' +
      '<div class="ds">' + esc(e.description) + '</div>' +
      '<div class="im" style="color:var(--' + (e.found ? 'ok' : 'warn') + ');">' +
      (e.found ? 'found: ' + esc(e.path) : 'not installed here') + '</div>' +
      '<div class="im">' + (e.locality === 'local'
        ? 'prompts stay on this host'
        : 'command output goes off-host to the provider') + '</div>' +
      '</div>').join('') + '</div>' +
    '<label class="fld"><span class="lb">agent</span>' +
    '<select id="m-aentry">' + entries.map((e) =>
      '<option value="' + esc(e.id) + '"' + (e.found ? '' : ' disabled') + '>' +
      esc(e.title) + (e.found ? '' : ' — not installed') + '</option>').join('') +
    '</select></label>' +
    '<label class="fld"><span class="lb">name in the registry</span>' +
    '<input id="m-aname" class="mono" placeholder="(default)"></label>' +
    '<label class="fld"><span class="lb">model</span>' +
    '<input id="m-amodel" class="mono" placeholder="(default)">' +
    '<span class="hint" id="m-ahelp"></span></label>' +
    '<div id="m-aurlwrap" style="display:none;">' +
    '<label class="fld"><span class="lb">endpoint (OpenAI-compatible)</span>' +
    '<input id="m-aurl" class="mono">' +
    '<span class="hint" id="m-aurlhelp"></span></label>' +
    '<label class="fld"><span class="lb">api key — secret ref (optional)</span>' +
    '<select id="m-akey"><option value="">none needed (a local server)</option>' +
    S.secrets.map((x) => '<option value="' + esc(x.ref) + '">' + esc(x.ref) + '</option>').join('') +
    '</select><span class="hint">A REF, never the key itself. Store it first from ' +
    'Secrets; a local Ollama needs none.</span></label>' +
    '</div>' +
    '<p class="hint">Connecting runs a real MCP handshake against the command before ' +
    'anything is stored, so a broken install is reported now rather than at your first task. ' +
    'It may take a few seconds.</p>',
    'Connect', async () => {
      const entry = $('m-aentry').value;
      const out = await send('POST', '/v1/agents/install', {
        entry,
        name: $('m-aname').value.trim() || undefined,
        model: $('m-amodel').value.trim() || undefined,
        base_url: ($('m-aurl') || {}).value ? $('m-aurl').value.trim() : undefined,
        api_key_ref: ($('m-akey') || {}).value || undefined,
      });
      toast('connected ' + (out && out.name ? out.name : entry) +
        ' — ' + (out && out.disclosure ? out.disclosure : ''), 'ok');
    });
  // Prefill from whichever entry is selected.
  const sync = () => {
    const e = entries.find((x) => x.id === ($('m-aentry') || {}).value);
    if (!e) return;
    if ($('m-amodel')) $('m-amodel').placeholder = e.default_model || '(default)';
    if ($('m-ahelp')) $('m-ahelp').textContent = e.model_help || '';
    const wrap = $('m-aurlwrap');
    if (wrap) wrap.style.display = e.needs_base_url ? 'block' : 'none';
    if (e.needs_base_url && $('m-aurl')) {
      $('m-aurl').value = e.default_base_url || '';
      if ($('m-aurlhelp')) $('m-aurlhelp').textContent = e.base_url_help || '';
    }
    document.querySelectorAll('[data-pickagent]').forEach((el) =>
      el.classList.toggle('on', el.getAttribute('data-pickagent') === e.id));
  };
  const sel = $('m-aentry');
  if (sel) {
    const first = entries.find((e) => e.found);
    if (first) sel.value = first.id;
    sel.addEventListener('change', sync);
  }
  sync();
}

// toolCredModal does the whole credential step for one tool in one dialog: store
// the value in the vault, then bind a connection to it by REF.
//
// Two actions rather than one because they are genuinely two — a secret outlives
// the connection that uses it — but an operator onboarding kubernetes should not
// have to know that, or visit two screens to finish one thought.
function toolCredModal(toolID) {
  const t = TOOLS.find((x) => x.id === toolID);
  const p = project();
  if (!t || !t.secret || !p) return;
  const existing = S.secrets.some((x) => x.ref === t.secret.ref);

  modal('Credential for ' + t.name,
    '<p class="hint">' + esc(t.desc) + '</p>' +
    '<div class="capbar" style="margin:0 0 14px;border-radius:6px;">the value is encrypted ' +
    'under the daemon\'s vault key and injected at the egress proxy · <b>it never enters a ' +
    'sandbox and no route returns it</b></div>' +
    '<label class="fld"><span class="lb">secret ref</span>' +
    '<input id="m-cref" class="mono" value="' + esc(t.secret.ref) + '">' +
    (existing ? '<span class="hint">A secret with this ref already exists. Leave the value ' +
      'blank to reuse it, or type a new one to replace it.</span>'
              : '<span class="hint">The name you will reference forever after.</span>') +
    '</label>' +
    '<label class="fld"><span class="lb">value' + (existing ? ' (blank = keep the stored one)' : '') +
    '</span><input id="m-cval" type="password" class="mono" placeholder="paste the token"></label>' +
    '<label class="fld"><span class="lb">hosts this reaches</span>' +
    '<input id="m-chosts" class="mono" value="' + esc((t.hosts || []).join(', ')) + '" ' +
    'placeholder="api.example.com"></label>' +
    (t.hosts && t.hosts.length
      ? '<p class="hint" style="color:var(--warn)">Reaching a host also needs it on the egress ' +
        'allowlist, which WIDENS the policy and becomes a Change for approval. Adding the ' +
        'credential here does not open the network.</p>'
      : ''),
    'Save', async () => {
      const ref = $('m-cref').value.trim();
      const val = $('m-cval').value;
      if (!ref) throw new Error('a secret ref is required');
      if (!val && !existing) throw new Error('a value is required the first time');
      if (val) {
        await send('POST', '/v1/secrets', {
          ref, provider: t.secret.provider || undefined, value_b64: b64(val),
        });
      }
      const hosts = $('m-chosts').value.split(',').map((h) => h.trim()).filter(Boolean);
      try {
        await send('POST', '/v1/connections', {
          name: t.id, kind: t.secret.kind, secret_ref: ref,
          hosts: hosts.length ? hosts : undefined,
          project_id: p.id,
        });
      } catch (e) {
        // A connection that already exists is not a failure of this dialog — the
        // secret it points at has just been updated, which was the point.
        if (!/exists/i.test(e.message)) throw e;
      }
      toast(t.name + ' credential stored and bound as ' + ref, 'ok');
    });
}

function newSessionModal() {
  const e = environment();
  modal('New sandbox',
    '<label class="fld"><span class="lb">scope</span>' +
    '<input class="mono" value="' + esc(e ? e.id : (S.projectID || '')) + '" disabled></label>' +
    '<label class="fld"><span class="lb">mode</span><select id="m-mode">' +
    '<option value="scratch">scratch — an empty /workspace</option>' +
    '<option value="workspace">workspace — the project workspace mounted</option>' +
    '</select></label>' +
    '<p class="hint">The sandbox starts with this environment\'s resolved policy and keeps ' +
    'that hash for its whole life, even if the policy is edited underneath it.</p>',
    'Create', async () => {
      // createRequest takes `project` and `environment` — NOT the project_id /
      // environment_id spelling the other P8 routes use. decodeJSON rejects
      // unknown fields, so the wrong names are a 400, not a silently unscoped
      // sandbox. That is the right strictness; this is just the cost of it.
      const out = await send('POST', '/v1/sessions', {
        project: S.projectID || undefined,
        environment: e ? e.id : undefined,
        mode: $('m-mode').value,
      });
      // Attach the Shell to what was just created; that is why it was created.
      const id = out && (out.session_id || out.id);
      if (id) { S.shell.sessionID = id; S.shell.lines = []; S.drawerTab = 'shell'; }
      toast('sandbox ' + (id ? short(id, 8) : '') + ' created', 'ok');
    });
}

/* ---------------------------------------------------------------- events --- */

async function guard(fn) {
  try { await fn(); } catch (e) { toast(e.message, 'bad'); }
}

document.addEventListener('click', async (ev) => {
  const t = ev.target.closest('[data-wizard],[data-env],[data-add],[data-open],[data-tab],' +
    '[data-close],[data-newtab],[data-drawer],[data-killsession],[data-decide],[data-rmconn],' +
    '[data-dtab],[data-shellrun],[data-shellpop],[data-execdecide],' +
    '[data-ask],[data-chatstop],[data-chatclear],' +
    '[data-memsearch],[data-memclear],[data-memtoggle],[data-pickagent],[data-toolcred],' +
    '[data-rmtool],[data-picktool],[data-bind],[data-poledit],[data-wiztool],' +
    '[data-wizaddenv],[data-wizrmenv],[data-wiznext],[data-wizback],[data-wizcancel],' +
    '[data-modalok],[data-modalcancel]');
  if (!t) return;
  const a = (k) => t.getAttribute(k);
  ev.preventDefault();

  if (a('data-env')) { S.envID = a('data-env'); render(); return; }
  if (a('data-drawer')) { S.drawerShut = !S.drawerShut; renderDrawer(); return; }
  if (a('data-dtab')) { S.drawerTab = a('data-dtab'); S.drawerShut = false; renderDrawer(); return; }
  if (a('data-shellpop')) { openTab('shell', null, 'shell'); return; }
  if (a('data-shellrun')) {
    const inp = $('shellcmd');
    if (inp && inp.value.trim()) { const v = inp.value; inp.value = ''; await shellRun(v); }
    return;
  }
  if (a('data-execdecide')) { await shellDecide(a('data-execdecide')); return; }
  if (a('data-ask')) {
    const box = $('ask');
    if (box && box.value.trim()) {
      const v = box.value.trim();
      box.value = ''; S.draft = ''; autogrow(box);
      await askAgent(v);
    }
    return;
  }
  if (a('data-chatstop')) { if (agentAbort) agentAbort.abort(); return; }
  if (a('data-chatclear')) { S.chat.turns = []; renderChat(); return; }

  if (a('data-memsearch')) {
    const q = ($('memq') || {}).value || '';
    if (!q.trim()) { toast('type something to search for', 'bad'); return; }
    await guard(async () => {
      const r = await api('/v1/memory/search?q=' + encodeURIComponent(q) +
        (S.projectID ? '&project=' + encodeURIComponent(S.projectID) : ''));
      S.memQuery = q;
      S.memHits = (r && r.excerpts) || [];
      render();
    });
    return;
  }
  if (a('data-memclear')) { S.memHits = null; S.memQuery = ''; render(); return; }
  if (a('data-toolcred')) { toolCredModal(a('data-toolcred')); return; }
  if (a('data-pickagent')) {
    const sel = $('m-aentry');
    if (sel) { sel.value = a('data-pickagent'); sel.dispatchEvent(new Event('change')); }
    return;
  }
  if (a('data-memtoggle')) {
    const doc = a('data-memtoggle'); const on = a('data-memon') === '1';
    await guard(async () => {
      await send('POST', '/v1/memory/enable', {
        project: S.projectID || undefined, doc, enabled: on,
      });
      toast(doc + (on ? ' enabled' : ' disabled — it will not be returned by search'), 'ok');
      await refresh();
    });
    return;
  }
  if (a('data-wizard')) { wizReset(); W.open = true; renderWizard(); return; }

  // One dispatcher for every + in the explorer, so a section header and its
  // screen's button cannot drift into opening different things.
  if (a('data-add')) {
    ({
      env: addEnvModal, tool: addToolModal, conn: addConnModal,
      secret: addSecretModal, session: newSessionModal,
      policy: () => openTab('policy', null, 'policy'),
      agent: addAgentModal,
    }[a('data-add')] || (() => toast('nothing to add there', 'bad')))();
    return;
  }

  // Picking a catalogue tile fills the role/tool fields rather than submitting:
  // the operator still sees what they are about to add, and can change it.
  if (a('data-picktool')) {
    const cat = TOOLS.find((x) => x.id === a('data-picktool'));
    if (cat) {
      if ($('m-trole')) $('m-trole').value = cat.role;
      if ($('m-ttool')) $('m-ttool').value = cat.id;
      document.querySelectorAll('[data-picktool]').forEach((el) =>
        el.classList.toggle('on', el.getAttribute('data-picktool') === cat.id));
    }
    return;
  }

  if (a('data-rmtool')) {
    const role = a('data-rmtool');
    const p = project();
    if (!p) return;
    await guard(async () => {
      const next = Object.assign({}, p.capabilities || {});
      delete next[role];
      await send('PUT', '/v1/projects/' + encodeURIComponent(p.id) + '/capabilities',
        { capabilities: next });
      toast('tool ' + role + ' removed — the gates it added stay, and are removed from Policy', 'ok');
      await refresh();
    });
    return;
  }

  if (a('data-open')) {
    const v = a('data-open');
    const [kind, arg] = v.split(':');
    openTab(kind, arg, arg ? kind + ' ' + short(arg, 14) : kind);
    return;
  }
  if (a('data-tab')) { S.activeTab = a('data-tab'); render(); return; }
  if (a('data-close')) { ev.stopPropagation(); closeTab(a('data-close')); return; }
  if (a('data-newtab')) {
    modal('Open a screen',
      '<div class="grid3">' +
      ['sandboxes', 'changes', 'connections', 'secrets', 'policy', 'agents'].map((k) =>
        '<div class="tool" data-open="' + k + '"><div class="top"><span class="nm">' +
        k + '</span></div></div>').join('') + '</div>', 'Close', async () => {});
    return;
  }

  if (a('data-killsession')) {
    const id = a('data-killsession');
    await guard(async () => {
      await send('DELETE', '/v1/sessions/' + encodeURIComponent(id));
      toast('sandbox ' + short(id, 8) + ' killed', 'ok');
      await refresh();
    });
    return;
  }

  if (a('data-decide')) {
    const id = a('data-chg'); const decision = a('data-decide');
    await guard(async () => {
      await send('POST', '/v1/changes/' + encodeURIComponent(id) + '/decision', { decision });
      toast('change ' + short(id, 20) + ' ' + decision + 'd', 'ok');
      await refresh();
    });
    return;
  }

  if (a('data-rmconn')) {
    const name = a('data-rmconn');
    await guard(async () => {
      // The scope is part of the identity: connections are stored per project, so
      // a bare name resolves only for a global one and 404s for every other. The
      // rm button was dead for exactly the connections an operator actually has.
      const e = environment();
      let u = '/v1/connections/' + encodeURIComponent(name);
      const q = [];
      if (S.projectID) q.push('project=' + encodeURIComponent(S.projectID));
      if (e) q.push('environment=' + encodeURIComponent(e.id));
      if (q.length) u += '?' + q.join('&');
      await send('DELETE', u);
      toast('connection ' + name + ' removed', 'ok');
      await refresh();
    });
    return;
  }

  if (a('data-bind')) {
    const name = a('data-bind');
    await guard(async () => {
      await send('POST', '/v1/agents/' + encodeURIComponent(name) + '/bind', {
        project_id: S.projectID || undefined,
        environment_id: environment() ? environment().id : undefined,
      });
      toast('bound ' + name, 'ok');
      await refresh();
    });
    return;
  }

  if (a('data-poledit')) {
    const which = a('data-poledit');
    const reason = ($('pol-reason') || {}).value || '';
    const e = environment();
    await guard(async () => {
      const body = {
        project_id: S.projectID || undefined,
        environment_id: e ? e.id : undefined,
        reason: reason || undefined,
      };
      if (which === 'gate') {
        const v = ($('pol-gate') || {}).value.trim();
        if (!v) throw new Error('enter a gate pattern');
        body.add_gates = [v];
      } else {
        const v = ($('pol-egress') || {}).value.trim();
        if (!v) throw new Error('enter a host');
        body.add_egress = [v];
      }
      const r = await send('POST', '/v1/policy/edit', body);
      if (r && r.applied) toast('applied now (narrowing) — policy hash changed', 'ok');
      else toast('not applied: this widens the guardrails. Change ' +
        short((r && r.change_id) || '', 24) + ' is awaiting approval.', null);
      await refresh();
      if (r && !r.applied) openTab('changes', null, 'changes');
    });
    return;
  }

  // --- wizard ---
  if (a('data-wiztool')) {
    const id = a('data-wiztool');
    W.tools[id] = !W.tools[id];
    renderWizard();
    return;
  }
  if (a('data-wizaddenv')) {
    const name = ($('w-env') || {}).value.trim();
    if (!name) { toast('name the environment', 'bad'); return; }
    if (W.envs.some((e) => e.name === name)) { toast('already listed', 'bad'); return; }
    W.envs.push({ name, production: $('w-envprod').checked });
    renderWizard();
    return;
  }
  if (a('data-wizrmenv')) { W.envs.splice(Number(a('data-wizrmenv')), 1); renderWizard(); return; }
  if (a('data-wizback')) { wizCollect(); W.step = Math.max(0, W.step - 1); renderWizard(); return; }
  if (a('data-wizcancel')) { W.open = false; closeOverlay(); return; }
  if (a('data-wiznext')) {
    wizCollect();
    const bad = wizValidate();
    if (bad) { toast(bad, 'bad'); return; }
    if (W.step < STEPS.length - 1) { W.step += 1; renderWizard(); return; }
    await wizCreate();
    return;
  }

  // --- modal ---
  if (a('data-modalcancel')) { closeOverlay(); return; }
  if (a('data-modalok')) {
    const ok = $('overlay').__ok;
    if (!ok) { closeOverlay(); return; }
    await guard(async () => { await ok(); closeOverlay(); await refresh(); });
    return;
  }
});

// Keep the draft in state as it is typed, and grow the box with it.
document.addEventListener('input', (ev) => {
  if (ev.target && ev.target.id === 'ask') {
    S.draft = ev.target.value;
    S.draftFocus = true;
    autogrow(ev.target);
  }
});

document.addEventListener('change', async (ev) => {
  if (ev.target && ev.target.id === 'agentpick') {
    const v = ev.target.value;
    if (v === '__add') { addAgentModal(); return; }
    const e = environment();
    await guard(async () => {
      await send('POST', '/v1/agents/' + encodeURIComponent(v) + '/bind', {
        project_id: S.projectID || undefined,
        environment_id: e ? e.id : undefined,
      });
      toast(v + ' now runs work in this scope', 'ok');
      await refresh();
    });
    return;
  }
  if (ev.target && ev.target.id === 'shellsess') {
    S.shell.sessionID = ev.target.value;
    S.shell.lines = [];
    renderDrawer();
    return;
  }
  if (ev.target && ev.target.id === 'projsel') {
    S.projectID = ev.target.value;
    S.envID = null;
    S.tabs = [];
    await refresh();
  }
});

document.addEventListener('keydown', async (ev) => {
  const inp = ev.target;
  if (inp && inp.id === 'shellcmd') {
    if (ev.key === 'Enter' && inp.value.trim()) {
      ev.preventDefault();
      const v = inp.value; inp.value = '';
      await shellRun(v);
      return;
    }
    // Shell history, because retyping a long kubectl line to fix one flag is how
    // an operator ends up pasting it somewhere else instead.
    if (ev.key === 'ArrowUp' || ev.key === 'ArrowDown') {
      const h = S.shell.history;
      if (!h.length) return;
      ev.preventDefault();
      if (S.shell.hpos < 0) S.shell.hpos = h.length;
      S.shell.hpos += (ev.key === 'ArrowUp' ? -1 : 1);
      if (S.shell.hpos < 0) S.shell.hpos = 0;
      if (S.shell.hpos >= h.length) { S.shell.hpos = -1; inp.value = ''; return; }
      inp.value = h[S.shell.hpos];
      return;
    }
    return;
  }
  if (inp && inp.id === 'ask' && ev.key === 'Enter' && !ev.shiftKey) {
    ev.preventDefault();
    if (inp.value.trim() && !S.chat.busy) {
      const v = inp.value.trim();
      inp.value = ''; S.draft = ''; autogrow(inp);
      await askAgent(v);
    }
    return;
  }
  if (ev.key === 'Escape') {
    if (W.open) { W.open = false; }
    closeOverlay();
  }
});

/* ------------------------------------------------------------------ boot --- */

(async function boot() {
  // The launch token arrives in the URL and the server sets an HttpOnly cookie.
  // Strip it from the address bar so the token does not sit in history, or get
  // copied out of it into a chat window by an operator sharing "the link".
  if (location.search.includes('token=')) {
    history.replaceState(null, '', location.pathname);
  }
  // loadAll and render fail for different reasons and need different advice.
  // Collapsing them told an operator "Could not reach the daemon · renderRail is
  // not defined" — a bug in this file, reported as a daemon outage, sending them
  // to `opslify status` on a daemon that was answering perfectly.
  try {
    await loadAll();
  } catch (e) {
    document.body.innerHTML = '<div class="empty" style="margin-top:80px;">' +
      '<h3>Could not reach the daemon</h3>' + esc(e.message) +
      '<div class="cli">opslify status</div></div>';
    return;
  }
  try {
    render();
  } catch (e) {
    document.body.innerHTML = '<div class="empty" style="margin-top:80px;">' +
      '<h3>The cockpit failed to render</h3>' +
      'The daemon is reachable — this is a bug in the page itself.' +
      '<div class="cli">' + esc(e.message) + '</div>' +
      '<div class="cli">please report it with the line above</div></div>';
    return;
  }
  // Poll rather than hold a socket open: the cockpit is a viewer of daemon state
  // and a dropped websocket that silently stops updating is a worse failure than
  // a refresh that visibly lags.
  setInterval(() => {
    loadAll().then(render).catch((e) => {
      // A failed poll is usually the daemon restarting and is not worth shouting
      // about; a failed RENDER is a bug that would otherwise freeze the page
      // silently, so it surfaces.
      if (e && e.message && !/fetch|network|load failed/i.test(e.message)) {
        toast('render failed: ' + e.message, 'bad');
      }
    });
  }, 5000);
})();
