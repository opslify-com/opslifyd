// The cockpit is a viewer. Every mutation it offers is a POST to the same daemon
// endpoint the CLI calls, so the policy classifier, the approval gates and the
// audit trail apply identically. There is no second path to get wrong.
'use strict';

const $ = (id) => document.getElementById(id);

// api wraps fetch with the one rule that matters here: a non-2xx is an ERROR with
// the daemon's own message, never a silently empty panel. An operator seeing a
// blank Connections page cannot tell "none defined" from "the request was
// refused", and those need different actions.
async function api(path, opts) {
  const res = await fetch(path, Object.assign({ credentials: 'same-origin' }, opts || {}));
  const text = await res.text();
  if (!res.ok) {
    let msg = text;
    try { msg = JSON.parse(text).error || text; } catch (_) {}
    throw new Error(msg || (res.status + ' ' + res.statusText));
  }
  return text ? JSON.parse(text) : null;
}

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function table(cols, rows, render) {
  if (!rows || !rows.length) return '<p class="muted">nothing here yet</p>';
  return '<table><thead><tr>' + cols.map((c) => '<th>' + esc(c) + '</th>').join('') +
    '</tr></thead><tbody>' + rows.map(render).join('') + '</tbody></table>';
}

// --- sections ---------------------------------------------------------------
//
// Each section is read-only unless the daemon offers a mutation for it, and the
// mutations are exactly the ones the CLI has.

const sections = [
  {
    id: 'sandboxes', label: 'Sandboxes',
    async render() {
      const list = await api('/v1/sessions');
      // Isolation facts, not a name and a status light: tier, mode and TTL are
      // what tell an operator how contained a thing actually is.
      return table(['id', 'state', 'tier', 'mode', 'scope', 'ttl', ''], list, (s) => `
        <tr>
          <td class="mono">${esc(s.id).slice(0, 12)}</td>
          <td>${esc(s.state)}</td>
          <td>${esc(s.tier)}</td>
          <td>${esc(s.mode)}</td>
          <td>${esc(s.environment_id || s.project_id || '—')}</td>
          <td>${esc(s.ttl || '—')}</td>
          <td><button data-kill="${esc(s.id)}">kill</button></td>
        </tr>`);
    },
  },
  {
    id: 'changes', label: 'Changes',
    async render() {
      const list = await api('/v1/changes');
      return table(['id', 'status', 'blast', 'revert', 'proposed by', 'intent'], list, (c) => `
        <tr>
          <td class="mono"><a href="#" data-change="${esc(c.id)}">${esc(c.id)}</a></td>
          <td>${esc(c.status)}</td>
          <td>${esc(c.blast_summary)}</td>
          <td class="${c.revertible ? 'ok' : 'danger'}">${c.revertible ? 'yes' : 'NO'}</td>
          <td>${esc(c.proposer_name)}${c.proposer_model ? ' <span class="muted">(' + esc(c.proposer_model) + ')</span>' : ''}</td>
          <td>${esc(c.intent)}</td>
        </tr>`);
    },
  },
  {
    id: 'connections', label: 'Connections',
    async render() {
      const list = await api('/v1/connections');
      // "sandbox receives" is rendered per kind because it is the claim the whole
      // feature makes, and an operator should not have to read the source to
      // learn what a connection hands over.
      const receives = {
        http: 'nothing (header added upstream)',
        kubernetes: 'a kubeconfig with no credential in it',
        ssh: 'an agent socket (signatures only)',
      };
      return table(['name', 'kind', 'scope', 'hosts', 'secret ref', 'sandbox receives'], list, (c) => `
        <tr>
          <td>${esc(c.name)}</td>
          <td>${esc(c.kind)}</td>
          <td>${esc(c.scope || '—')}</td>
          <td class="mono">${esc((c.hosts || []).join(', '))}</td>
          <td class="mono">${esc(c.secret_ref)}</td>
          <td class="muted">${esc(receives[c.kind] || 'unknown kind')}</td>
        </tr>`);
    },
  },
  {
    id: 'secrets', label: 'Secrets',
    async render() {
      const list = await api('/v1/secrets/consumers');
      // Refs and consumers only. There is no value column because there is no
      // value field on the wire — the daemon has no route that returns one.
      return '<div class="notice">Values are never shown here, and no route returns one. ' +
        'This page shows which credentials exist and what would break if you removed them.</div>' +
        table(['ref', 'provider', 'in use', 'used by', 'last used'], list, (s) => `
        <tr>
          <td class="mono">${esc(s.ref)}</td>
          <td>${esc(s.provider || '—')}</td>
          <td class="${s.in_use ? 'warn' : 'muted'}">${s.in_use ? 'yes' : 'no'}</td>
          <td class="muted">${esc((s.consumers || []).map((c) => c.kind + ':' + c.name).join(', ') || '—')}</td>
          <td class="muted">${esc(s.last_used || 'never')}</td>
        </tr>`);
    },
  },
  {
    id: 'policy', label: 'Policy',
    async render() {
      const p = await api('/v1/policy' + scopeQuery());
      const layers = table(['layer', 'editable', 'note'], p.layers, (l) => `
        <tr><td>${esc(l.layer)}</td>
            <td class="${l.editable ? 'ok' : 'muted'}">${l.editable ? 'yes' : 'read-only'}</td>
            <td class="muted">${esc(l.note)}</td></tr>`);
      const clamps = (p.clamps || []).length
        ? '<div class="notice danger"><strong>clamped</strong><br>' +
          p.clamps.map(esc).join('<br>') + '</div>'
        : '';
      return `<p class="mono muted">policy hash ${esc(p.hash)}</p>
        <div class="notice">Tightening applies immediately. <strong>Widening becomes a change
        and needs approval</strong> — the cockpit cannot apply one directly, because the daemon
        refuses it, not because this page declines to offer it.</div>
        ${clamps}
        <h3>egress</h3><p class="mono">${esc((p.egress_domains || []).join(', ') || '(none)')}</p>
        <h3>approval gates</h3><p class="mono">${esc((p.approval_required || []).join(', ') || '(none)')}</p>
        <h3>precedence</h3>${layers}`;
    },
  },
  {
    id: 'instructions', label: 'Instructions',
    async render() {
      // Instructions are read through the CLI (`opslify context show`): the
      // assembled text can carry estate detail, and there is no daemon route that
      // returns it. Saying so beats an empty panel.
      return '<div class="notice">The assembled instruction set is inspected from the CLI:' +
        '<p class="mono">opslify context show --env &lt;environment&gt;</p>' +
        'It is not served to the browser: the assembled text can carry estate detail ' +
        '(hostnames, who to page) and the daemon exposes only its hash in the trace.</div>';
    },
  },
  {
    id: 'agents', label: 'Agents',
    async render() {
      const res = await api('/v1/agents');
      const agents = table(['name', 'model', 'locality', 'prompts'], res.agents, (a) => `
        <tr><td>${esc(a.name)}</td><td>${esc(a.model_hint || '—')}</td>
            <td><span class="pill ${esc(a.locality)}">${esc(a.locality)}</span></td>
            <td class="muted">${esc(a.disclosure)}</td></tr>`);
      const bindings = table(['scope', 'agent'], res.bindings || [], (b) => `
        <tr><td>${esc(b.scope)}</td><td>${esc(b.agent)}</td></tr>`);
      return '<h3>registered</h3>' + agents + '<h3>bindings</h3>' + bindings;
    },
  },
];

// --- scope ------------------------------------------------------------------

let scope = { project: '', env: '' };
function scopeQuery() {
  const q = new URLSearchParams();
  if (scope.project) q.set('project', scope.project);
  if (scope.env) q.set('env', scope.env);
  const s = q.toString();
  return s ? '?' + s : '';
}

async function loadScopes() {
  const sel = $('scope-select');
  try {
    const projects = await api('/v1/projects');
    sel.innerHTML = '<option value="">all scopes</option>';
    for (const p of projects || []) {
      for (const e of p.environments || [{ id: p.id, name: p.id }]) {
        const o = document.createElement('option');
        o.value = JSON.stringify({ project: p.id, env: e.id });
        o.textContent = p.id + ' / ' + (e.name || e.id);
        sel.appendChild(o);
      }
    }
  } catch (err) {
    sel.innerHTML = '<option value="">(scopes unavailable)</option>';
    note(err.message);
  }
  sel.onchange = async () => {
    scope = sel.value ? JSON.parse(sel.value) : { project: '', env: '' };
    await loadAgent();
    await show(current);
  };
}

// --- the agent indicator ----------------------------------------------------

async function loadAgent() {
  const el = $('agent');
  try {
    const res = await api('/v1/agents');
    const bound = (res.bindings || []).find((b) => b.scope === (scope.env || scope.project)) ||
      (res.bindings || []).find((b) => b.scope === '_fallback');
    if (!bound) {
      el.classList.remove('bound');
      $('agent-name').textContent = 'no agent bound';
      $('agent-model').textContent = '';
      $('agent-locality').textContent = '';
      $('agent-locality').className = 'pill';
      return;
    }
    const a = (res.agents || []).find((x) => x.name === bound.agent) || { name: bound.agent };
    el.classList.add('bound');
    $('agent-name').textContent = a.name;
    $('agent-model').textContent = a.model_hint || '';
    // Locality is shown permanently, because "where do prompts go" is a standing
    // fact about the session an operator is about to start, not a detail.
    $('agent-locality').textContent = a.locality || 'unknown';
    $('agent-locality').className = 'pill ' + (a.locality || 'unknown');
    $('agent-locality').title = a.disclosure || '';
  } catch (err) {
    note(err.message);
  }
}

// --- shell ------------------------------------------------------------------

let current = 'sandboxes';

function note(msg) { $('conn').textContent = msg; }

async function show(id) {
  current = id;
  for (const li of $('sections').children) li.classList.toggle('active', li.dataset.id === id);
  const sec = sections.find((s) => s.id === id);
  const panel = $('panel');
  panel.innerHTML = '<p class="muted">loading…</p>';
  try {
    panel.innerHTML = await sec.render();
    note('connected');
  } catch (err) {
    // The error is SHOWN, not swallowed into an empty table.
    panel.innerHTML = '<div class="notice danger"><strong>could not load ' + esc(sec.label) +
      '</strong><br>' + esc(err.message) + '</div>';
    note('error');
  }
}

$('panel').addEventListener('click', async (ev) => {
  const kill = ev.target.getAttribute && ev.target.getAttribute('data-kill');
  if (kill) {
    if (!confirm('Kill sandbox ' + kill + '? Anything running in it stops.')) return;
    try {
      await api('/v1/sessions/' + encodeURIComponent(kill), { method: 'DELETE' });
      await show('sandboxes');
    } catch (err) { note(err.message); }
    return;
  }
  const chg = ev.target.getAttribute && ev.target.getAttribute('data-change');
  if (chg) {
    ev.preventDefault();
    try {
      const c = await api('/v1/changes/' + encodeURIComponent(chg));
      $('panel').innerHTML = renderChange(c);
    } catch (err) { note(err.message); }
  }
});

function renderChange(c) {
  const steps = (c.steps || []).map((s) =>
    '<div class="mono">' + (s.gated ? '→ ' : '&nbsp;&nbsp;') + esc(s.argv.join(' ')) + '</div>').join('');
  // Revertibility is stated BEFORE the approve button, not after a failed revert:
  // whether a change can be undone is part of deciding to approve it.
  const revert = c.revertible
    ? '<div class="notice">This change can be reverted (' + esc(c.inverse_kind) + ').</div>'
    : '<div class="notice danger"><strong>This change cannot be reverted.</strong><br>' +
      esc(c.revert_reason) + '</div>';
  return `<h2>${esc(c.id)} <span class="muted">${esc(c.status)}</span></h2>
    <p>${esc(c.intent)}</p>
    <p class="muted">proposed by ${esc(c.proposer_name)}${c.proposer_model ? ' (' + esc(c.proposer_model) + ')' : ''}
      · blast radius ${esc(c.blast_summary)}</p>
    ${revert}
    <h3>plan <span class="muted mono">pinned as ${esc((c.plan_hash || '').slice(0, 12))}</span></h3>
    ${steps}
    ${c.preview ? '<h3>preview</h3><pre class="mono">' + esc(c.preview) + '</pre>' : ''}
    <p class="muted">Approve or deny from the CLI: <span class="mono">opslify change approve ${esc(c.id)}</span></p>`;
}

function boot() {
  const ul = $('sections');
  for (const s of sections) {
    const li = document.createElement('li');
    li.textContent = s.label;
    li.dataset.id = s.id;
    li.onclick = () => show(s.id);
    ul.appendChild(li);
  }
  loadScopes().then(loadAgent).then(() => show(current));
}
boot();
