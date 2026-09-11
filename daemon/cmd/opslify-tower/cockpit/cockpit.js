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
};

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
  S.sessions = sessions || [];
  S.connections = connections || [];
  S.secrets = secrets || [];
  S.consumers = consumers || [];
  S.agents = (agents && agents.agents) || [];
  S.boundAgent = (agents && agents.bound) || S.agents.find((a) => a.bound) || null;
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
  renderRail();
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

  // --- agents -----------------------------------------------------------------
  // No + here: registering an agent runs its command on the host, so it is the
  // one thing on this sidebar the cockpit deliberately cannot do.
  html += esec('Agents', S.agents.length, null, 'agents');
  html += S.agents.length ? S.agents.map((a) =>
    '<div class="row' + (S.boundAgent && S.boundAgent.name === a.name ? ' on' : '') +
    '" data-open="agents"><span class="dot' + (a.locality === 'local' ? '' : ' warn') + '"></span>' +
    '<span class="nm">' + esc(a.name) + '</span>' +
    '<span class="rt">' + esc(a.locality || 'unknown') + '</span></div>').join('')
    : noneRow('none — opslify agent add');

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
}

function renderDrawer() {
  $('dtabs').innerHTML = '<span class="t on">Trace</span>' +
    '<span class="t" data-open="changes">Changes</span>' +
    '<span class="t" data-open="policy">Policy</span>' +
    '<span class="sp spacer"></span>' +
    '<span class="t" data-drawer="1">' + (S.drawerShut ? '▴' : '▾') + '</span>';
  $('drawer').className = 'drawer' + (S.drawerShut ? ' shut' : '');

  // The drawer shows what the daemon can actually attest to. A per-session trace
  // needs a session; with none running there is nothing signed to display, and
  // inventing a plausible timeline here would undermine the one surface whose
  // whole value is that it is not invented.
  const live = S.sessions.filter(inScope);
  if (!live.length) {
    $('trace').innerHTML = '<div class="empty" style="padding:14px;">' +
      'No sandbox running in this scope, so there is no trace segment to show.<br>' +
      '<span class="tag">A trace is per-session and hash-chained from its ' +
      'session.start; it appears here once a sandbox starts.</span></div>';
    return;
  }
  $('trace').innerHTML = live.map((s) =>
    '<div class="tli"><span class="ts">' + esc(fmtAge(s.started)) + ' ago</span>' +
    '<span class="ty" style="color:var(--ok);">session.start</span>' +
    '<span class="de">sandbox ' + esc(short(s.id, 8)) + ' · tier ' + esc(s.tier || '—') +
    ' · mode ' + esc(s.mode || '—') + '</span></div>').join('') +
    '<div class="tli"><span class="ts"></span><span class="ty" style="color:var(--muted);">' +
    'verify</span><span class="de">opslify verify ' + esc(short(live[0].id, 8)) +
    ' — the chain is checked by the CLI, not asserted here</span></div>';
}

function renderChat() {
  const pending = S.changes.filter((c) => inScope(c) && c.status === 'awaiting_approval');
  const a = S.boundAgent;

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

  $('chat').innerHTML =
    '<div class="ch"><span style="font-weight:600;">Agent</span>' +
    (a ? '<span class="badge accent">' + esc(a.name) + '</span>' : '<span class="tag">none bound</span>') +
    '<span class="spacer"></span>' +
    '<button class="sm" data-open="agents">' + (a ? 'Switch' : 'Bind') + '</button></div>' +
    '<div class="thr">' +
    (gates || '<div class="m"><div class="a">·</div><div class="b">' +
      '<div class="w2">Nothing awaiting you</div>' +
      'Gated changes arrive here for approval, with their blast radius and whether ' +
      'a revert exists — stated before you approve, not after it fails.</div></div>') +
    '</div>' +
    // The composer is disabled and says why. A box that looks like it drives the
    // agent but silently does nothing is worse than one that admits the wiring is
    // absent: the operator would think the instruction had been sent.
    '<div class="comp"><div class="cbox">' +
    '<textarea placeholder="Driving the agent from the cockpit is not wired yet — ' +
    'start it against the daemon over MCP." disabled></textarea>' +
    '<div class="crow"><span class="tag" style="font-size:10px;">' +
    esc(S.projectID || '—') + ' / ' + esc(environment() ? environment().name : '—') +
    '</span><span class="spacer"></span>' +
    '<button class="sm" disabled>Send</button></div>' +
    '</div></div>';
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
          return '<tr><td class="mono">' + esc(r) + '</td>' +
            '<td class="mono">' + esc(caps[r]) + '</td>' +
            '<td>' + (k
              ? (k.gates.length ? '<span class="badge warn">' + k.gates.length + ' gate(s)</span> ' : '') +
                (k.hosts.length ? '<span class="badge">' + k.hosts.length + ' host(s)</span> ' : '') +
                (k.secret ? '<span class="badge accent">' + esc(k.secret.ref) + '</span>' : '')
              : '<span class="tag">not in the catalogue</span>') + '</td>' +
            '<td><button class="sm danger" data-rmtool="' + esc(r) + '">rm</button></td></tr>';
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
          '<td class="mono">' + esc(a.command || '—') + '</td>' +
          '<td>' + esc(a.description || '') + '</td>' +
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
    gates: ['^kubectl delete', '^kubectl scale', '^kubectl patch'], note: '3 approval gates' },
  { id: 'terraform', role: 'iac', name: 'Terraform', desc: 'Plan and apply infrastructure',
    hosts: ['registry.terraform.io'], secret: null,
    gates: ['^terraform apply', '^terraform destroy'], note: 'plan pinning' },
  { id: 'argocd', role: 'deploy', name: 'ArgoCD', desc: 'GitOps sync',
    hosts: [], secret: { ref: 'argocd-token', kind: 'http', provider: 'argocd' },
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
  name: '', repo: '',
  envs: [{ name: 'staging', production: false }, { name: 'prod', production: true }],
  tools: {},
  creds: {},   // toolID -> {mode:'existing'|'new', ref, value}
  busy: false,
};

const wizTools = () => TOOLS.filter((t) => W.tools[t.id]);
const wizGates = () => wizTools().reduce((a, t) => a.concat(t.gates), []);
const wizHosts = () => wizTools().reduce((a, t) => a.concat(t.hosts), []);
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
      'placeholder="gitlab.example.com/team/infra"></label>';
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
                    esc(c.value || '') + '" placeholder="paste the token"></label>' +
                    '<div class="hint">Leave blank to skip — the connection is created ' +
                    'without it and will not work until you store one.</div>') +
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
    const n = $('w-name'); const r = $('w-repo');
    if (n) W.name = n.value.trim();
    if (r) W.repo = r.value.trim();
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
    await send('POST', '/v1/projects', {
      name: W.name,
      repo_url: W.repo || undefined,
      capabilities: Object.keys(caps).length ? caps : undefined,
      environments: W.envs.map((e) => ({ name: e.name, production: e.production })),
    });
    done.push('project ' + W.name + ' with ' + W.envs.length + ' environment(s)');
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

  for (const t of wizSecrets()) {
    const ref = (W.creds[t.id] || {}).ref || t.secret.ref;
    try {
      await send('POST', '/v1/connections', {
        name: t.id, kind: t.secret.kind, secret_ref: ref,
        hosts: t.hosts.length ? t.hosts : undefined,
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
  if (pending) {
    toast(pending + ' egress host(s) need approval before the sandbox can reach them — ' +
      'see Changes.', null);
    openTab('changes', null, 'changes');
  }
  if (failed.length) toast('some steps failed: ' + failed.join('; '), 'bad');
}

function wizReset() {
  W.step = 0; W.name = ''; W.repo = '';
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

function newSessionModal() {
  const e = environment();
  modal('New sandbox',
    '<label class="fld"><span class="lb">scope</span>' +
    '<input class="mono" value="' + esc(e ? e.id : (S.projectID || '')) + '" disabled></label>' +
    '<label class="fld"><span class="lb">mode</span><select id="m-mode">' +
    '<option value="interactive">interactive</option><option value="agent">agent</option>' +
    '</select></label>' +
    '<p class="hint">The sandbox starts with this environment\'s resolved policy and keeps ' +
    'that hash for its whole life, even if the policy is edited underneath it.</p>',
    'Create', async () => {
      await send('POST', '/v1/sessions', {
        project_id: S.projectID || undefined,
        environment_id: e ? e.id : undefined,
        mode: $('m-mode').value,
      });
      toast('sandbox created', 'ok');
    });
}

/* ---------------------------------------------------------------- events --- */

async function guard(fn) {
  try { await fn(); } catch (e) { toast(e.message, 'bad'); }
}

document.addEventListener('click', async (ev) => {
  const t = ev.target.closest('[data-wizard],[data-env],[data-add],[data-open],[data-tab],' +
    '[data-close],[data-newtab],[data-drawer],[data-killsession],[data-decide],[data-rmconn],' +
    '[data-rmtool],[data-picktool],[data-bind],[data-poledit],[data-wiztool],' +
    '[data-wizaddenv],[data-wizrmenv],[data-wiznext],[data-wizback],[data-wizcancel],' +
    '[data-modalok],[data-modalcancel]');
  if (!t) return;
  const a = (k) => t.getAttribute(k);
  ev.preventDefault();

  if (a('data-env')) { S.envID = a('data-env'); render(); return; }
  if (a('data-drawer')) { S.drawerShut = !S.drawerShut; renderDrawer(); return; }
  if (a('data-wizard')) { wizReset(); W.open = true; renderWizard(); return; }

  // One dispatcher for every + in the explorer, so a section header and its
  // screen's button cannot drift into opening different things.
  if (a('data-add')) {
    ({
      env: addEnvModal, tool: addToolModal, conn: addConnModal,
      secret: addSecretModal, session: newSessionModal,
      policy: () => openTab('policy', null, 'policy'),
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
      await send('DELETE', '/v1/connections/' + encodeURIComponent(name));
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

document.addEventListener('change', async (ev) => {
  if (ev.target && ev.target.id === 'projsel') {
    S.projectID = ev.target.value;
    S.envID = null;
    S.tabs = [];
    await refresh();
  }
});

document.addEventListener('keydown', (ev) => {
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
  try {
    await loadAll();
    render();
  } catch (e) {
    document.body.innerHTML = '<div class="empty" style="margin-top:80px;">' +
      '<h3>Could not reach the daemon</h3>' + esc(e.message) +
      '<div class="cli">opslify status</div></div>';
    return;
  }
  // Poll rather than hold a socket open: the cockpit is a viewer of daemon state
  // and a dropped websocket that silently stops updating is a worse failure than
  // a refresh that visibly lags.
  setInterval(() => { loadAll().then(render).catch(() => {}); }, 5000);
})();
