// opslify local UI — vanilla ES module, zero dependencies, fully self-contained.
//
// Data sources (existing daemon API only, proxied via the localhost UI server to
// the daemon's Unix socket — the browser never talks to the socket directly):
//   GET    /v1/sessions                          — live session list (polled)
//   GET    /v1/sessions/history                   — ended sessions (durable store, F3.6)
//   GET    /v1/sessions/{id}/trace  (SSE)         — event stream + backfill (from_seq); replay=0
//   GET    /v1/sessions/{id}/verify               — server-side integrity verdict (F3.6)
//   DELETE /v1/sessions/{id}                       — Kill
//   POST   /v1/sessions/{id}/approvals/{exec_id}   — approve|deny a gated command (F3.6/F4.3)
//
// The verify verdict is computed DAEMON-SIDE against the trusted identity; the
// browser only renders ✓/✗ and can never fabricate a pass. Approve/Deny is the
// only privileged mutation, reachable solely over this loopback + Host-guarded UI.
//
// Terminal renderer: a lightweight ANSI-aware <pre>, NOT xterm.js. Rationale in
// F3.5 report: vendoring xterm.js fully offline is heavy (~250KB of JS/CSS to
// embed + audit); exec.output payloads are plain text chunks, so escaping HTML +
// stripping ANSI control sequences into a <pre> is a faithful v1 that keeps the
// bundle trivially self-contained and grep-verifiable for "no external refs".
//
// Only the already-redacted stream (F3.3 runs before persist) is ever rendered —
// this UI has no path to raw secrets.

const $ = (s) => document.querySelector(s);
const sessionsEl = $("#sessions");
const historyEl = $("#history");
const terminalEl = $("#terminal");
const timelineEl = $("#timeline");
const selIdEl = $("#sel-id");
const killBtn = $("#btn-kill");
const replayBtn = $("#btn-replay");
const connEl = $("#conn");
const verifyBadge = $("#verifyBadge");
const approvalsEl = $("#approvals");
const liveTable = $("#live-table");
const historyTable = $("#history-table");
const modeLiveBtn = $("#mode-live");
const modeHistoryBtn = $("#mode-history");

const state = {
  selected: null,     // selected session id
  stream: null,       // AbortController for the active trace stream
  lastSeq: -1,        // highest seq rendered (for reconnect resume)
  events: [],         // rendered timeline events
  mode: "live",       // "live" | "history"
  approvals: {},       // exec_id -> pending approval payload (per selected session)
};

// ---- session list (poll every 2s so state changes surface live) ----

async function pollSessions() {
  try {
    const r = await fetch("/v1/sessions", { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    renderSessions(await r.json());
    connEl.textContent = "● live";
    connEl.style.color = "var(--ok)";
  } catch (e) {
    connEl.textContent = "● daemon unreachable";
    connEl.style.color = "var(--danger)";
  } finally {
    setTimeout(pollSessions, 2000);
  }
}

function fmtSecs(s) {
  s = Math.max(0, s | 0);
  if (s < 60) return s + "s";
  const m = (s / 60) | 0, r = s % 60;
  if (m < 60) return r ? `${m}m${r}s` : `${m}m`;
  return `${(m / 60) | 0}h${m % 60}m`;
}

function renderSessions(list) {
  if (!list || list.length === 0) {
    sessionsEl.innerHTML = `<tr><td colspan="5" class="empty">no active sessions</td></tr>`;
    return;
  }
  const ids = new Set(list.map((s) => s.session_id));
  // If the selected LIVE session vanished (ended between renders), disable Kill.
  // (In history mode the selection is intentionally not in the live list.)
  if (state.mode === "live" && state.selected && !ids.has(state.selected)) markSelectionGone();

  sessionsEl.innerHTML = "";
  for (const s of list) {
    const tr = document.createElement("tr");
    tr.className = "session" + (s.session_id === state.selected ? " sel" : "");
    const ttl = s.ttl_remaining_seconds > 0 ? fmtSecs(s.ttl_remaining_seconds) : "—";
    tr.innerHTML =
      `<td title="${esc(s.session_id)}"><code>${esc(shortId(s.session_id))}</code></td>` +
      `<td><span class="state ${esc(s.state)}">${esc(s.state)}</span></td>` +
      `<td>${esc(s.tier || "")}</td>` +
      `<td>${fmtSecs(s.age_seconds)}</td>` +
      `<td>${ttl}</td>`;
    tr.onclick = () => selectSession(s.session_id);
    sessionsEl.appendChild(tr);
  }
}

function shortId(id) { return id.length > 18 ? id.slice(0, 18) + "…" : id; }
function markSelectionGone() {
  killBtn.disabled = true;
  connEl.title = "selected session ended";
}

// ---- selection + live trace stream ----

function selectSession(id) {
  if (state.selected === id) return;
  state.selected = id;
  selIdEl.textContent = id;
  // Kill only makes sense for a live session; a historical replay is read-only.
  killBtn.disabled = state.mode === "history";
  replayBtn.disabled = false;
  state.approvals = {};
  renderApprovals();
  openStream(id, 0);
  fetchVerify(id);
  // Re-highlight rows on next poll; also do it immediately.
  document.querySelectorAll("tr.session").forEach((tr) => {
    tr.classList.toggle("sel", tr.querySelector("td")?.title === id);
  });
}

// ---- verify badge (server-side verdict; the browser only renders it) ----

async function fetchVerify(id) {
  setVerifyBadge("pending", "verify: …");
  try {
    const r = await fetch(`/v1/sessions/${encodeURIComponent(id)}/verify`, {
      headers: { Accept: "application/json" },
    });
    if (state.selected !== id) return; // selection moved on
    if (!r.ok) { setVerifyBadge("pending", "verify: n/a"); return; }
    const v = await r.json();
    if (v.verified) {
      setVerifyBadge("ok", `✓ verified (${v.events} events)`);
    } else {
      const seq = (v.broken_seq === undefined || v.broken_seq === null) ? "?" : v.broken_seq;
      setVerifyBadge("bad", `✗ tampered @ seq ${seq}`, v.reason || "");
    }
  } catch {
    if (state.selected === id) setVerifyBadge("pending", "verify: n/a");
  }
}

function setVerifyBadge(kind, text, title) {
  verifyBadge.className = "badge " + kind;
  verifyBadge.textContent = text;
  verifyBadge.title = title || "Integrity verdict computed server-side against the trusted daemon identity";
}

// openStream tails a session's trace over SSE. fromSeq lets replay (0) and
// reconnect (lastSeq+1) resume without gaps or dupes.
function openStream(id, fromSeq) {
  if (state.stream) state.stream.abort();
  if (fromSeq === 0) { terminalEl.textContent = ""; timelineEl.innerHTML = ""; state.events = []; state.lastSeq = -1; }

  const ac = new AbortController();
  state.stream = ac;

  fetch(`/v1/sessions/${encodeURIComponent(id)}/trace?from_seq=${fromSeq}`, {
    headers: { Accept: "text/event-stream" },
    signal: ac.signal,
  }).then(async (r) => {
    if (!r.ok || !r.body) return;
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      // SSE frames are terminated by a blank line.
      let idx;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        handleFrame(id, frame);
      }
    }
  }).catch(() => {}).finally(() => {
    // Reconnect only if this is still the active stream + selected session.
    if (state.stream === ac && state.selected === id) {
      setTimeout(() => {
        if (state.selected === id) openStream(id, state.lastSeq + 1);
      }, 1000);
    }
  });
}

function handleFrame(id, frame) {
  // Extract the `data:` payload lines from one SSE frame.
  const data = frame.split("\n").filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim()).join("");
  if (!data) return;
  let ev;
  try { ev = JSON.parse(data); } catch { return; }
  if (typeof ev.seq === "number") {
    if (ev.seq <= state.lastSeq) return; // dedupe on reconnect overlap
    state.lastSeq = ev.seq;
  }
  renderEvent(ev);
}

// ---- rendering: terminal + timeline ----

function renderEvent(ev) {
  const p = ev.payload || {};
  if (ev.type === "exec.output") {
    if (p.truncated) {
      appendTerminal(`\n[opslify: ${p.stream || "stdout"} output truncated at cap]\n`);
    } else if (typeof p.chunk === "string") {
      appendTerminal(p.chunk);
    }
  } else if (ev.type === "approval.requested" && p.exec_id) {
    // A gated command paused (F4.3). Render the prompt with the F4.4 preview diff
    // and Approve/Deny buttons. Only shown while viewing a LIVE session — a
    // historical replay of the same event is read-only evidence, not actionable.
    if (state.mode === "live") {
      state.approvals[p.exec_id] = p;
      renderApprovals();
    }
  }
  addTimeline(ev);
}

// ---- approval prompts (F3.6/F4.3): render + Approve/Deny ----

function renderApprovals() {
  const pending = Object.values(state.approvals).filter((a) => !a._resolved);
  if (pending.length === 0) { approvalsEl.innerHTML = ""; return; }
  approvalsEl.innerHTML = "";
  for (const a of pending) approvalsEl.appendChild(approvalCard(a));
}

function approvalCard(a) {
  const div = document.createElement("div");
  div.className = "approval";
  const status = a.preview_status || "none";
  const diff = a.preview_diff
    ? `<pre class="diff">${esc(a.preview_diff)}</pre>`
    : `<div class="resolved">no dry-run preview available (status=${esc(status)})</div>`;
  div.innerHTML =
    `<h3>APPROVAL REQUIRED <span class="badge">rule <span class="rule">${esc(a.rule || "?")}</span></span>` +
    `<span class="badge">preview: ${esc(status)}</span></h3>` +
    `<div class="argv">$ ${esc(a.argv_summary || "")}</div>` +
    (a.reason ? `<div class="resolved">${esc(a.reason)}</div>` : "") +
    diff +
    `<div class="row">` +
    `<input class="comment" type="text" placeholder="optional comment (recorded in the trace)">` +
    `<button class="approve">Approve</button>` +
    `<button class="danger deny">Deny</button>` +
    `</div>` +
    `<div class="resolved" style="display:none"></div>`;
  const comment = div.querySelector("input.comment");
  const note = div.querySelector(".resolved:last-child");
  div.querySelector("button.approve").onclick = () => resolveApproval(a, "approve", comment.value, div, note);
  div.querySelector("button.deny").onclick = () => resolveApproval(a, "deny", comment.value, div, note);
  return div;
}

async function resolveApproval(a, decision, comment, card, note) {
  const id = state.selected;
  if (!id) return;
  card.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    const r = await fetch(`/v1/sessions/${encodeURIComponent(id)}/approvals/${encodeURIComponent(a.exec_id)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision, comment: comment || "" }),
    });
    if (!r.ok) {
      const msg = await r.text().catch(() => "");
      note.style.display = "";
      note.textContent = `resolve failed: HTTP ${r.status} ${msg}`;
      card.querySelectorAll("button").forEach((b) => (b.disabled = false));
      return;
    }
    a._resolved = decision;
    renderApprovals();
  } catch (e) {
    note.style.display = "";
    note.textContent = "resolve failed: " + e.message;
    card.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}

function appendTerminal(text) {
  const atBottom = terminalEl.scrollHeight - terminalEl.scrollTop - terminalEl.clientHeight < 40;
  terminalEl.textContent += stripAnsi(text);
  if (atBottom) terminalEl.scrollTop = terminalEl.scrollHeight;
}

// stripAnsi removes CSI/OSC control sequences so the <pre> shows clean text.
function stripAnsi(s) {
  return s
    .replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "")
    .replace(/\x1b[@-Z\\-_]/g, "");
}

function addTimeline(ev) {
  const li = document.createElement("li");
  const cls = ev.type.split(".")[0];
  const detail = summarize(ev);
  li.innerHTML =
    `<span class="ts">${esc(fmtTs(ev.ts))}</span>` +
    `<span class="ty ${cls}">${esc(ev.type)}</span>` +
    `<span class="detail">${detail}</span>`;
  timelineEl.appendChild(li);
  state.events.push(ev);
}

function summarize(ev) {
  const p = ev.payload || {};
  switch (ev.type) {
    case "session.start": return esc(`tier=${p.tier || ""} mode=${p.mode || ""}`);
    case "session.end":   return esc(`reason=${p.reason || ""}`);
    case "exec.start":    return esc(`$ ${(p.argv || []).join(" ")}`);
    case "exec.end":      return esc(`exit=${p.exit_code} ${p.duration_ms}ms`);
    case "exec.output":   return p.truncated ? `<em>truncated</em>` : esc(`${p.stream || "stdout"} +${(p.chunk || "").length}b`);
    case "file.write":    return esc(`${p.path} (${p.size}b)`);
    case "policy.decision": return `<span class="ty redact">${esc(JSON.stringify(p))}</span>`;
    default:              return esc(JSON.stringify(p));
  }
}

function fmtTs(ts) { try { return new Date(ts).toLocaleTimeString(); } catch { return ts || ""; } }
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// ---- actions: Kill + Replay ----

killBtn.onclick = async () => {
  const id = state.selected;
  if (!id) return;
  if (!confirm(`Kill session ${id}? This terminates the sandbox.`)) return;
  killBtn.disabled = true;
  try {
    const r = await fetch(`/v1/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
    // A session that ended between list-render and Kill returns 404 — treat as
    // already-gone, not an error.
    if (!r.ok && r.status !== 404) alert("kill failed: HTTP " + r.status);
  } catch (e) {
    alert("kill failed: " + e.message);
  }
};

replayBtn.onclick = () => { if (state.selected) openStream(state.selected, 0); };

// ---- tabs ----

document.querySelectorAll(".tabs button").forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll(".tabs button").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.dataset.view === b.dataset.tab));
  };
});

// ---- Live / History mode switch ----

function setMode(mode) {
  if (state.mode === mode) return;
  state.mode = mode;
  modeLiveBtn.classList.toggle("active", mode === "live");
  modeHistoryBtn.classList.toggle("active", mode === "history");
  liveTable.style.display = mode === "live" ? "" : "none";
  historyTable.style.display = mode === "history" ? "" : "none";
  if (mode === "history") loadHistory();
}

modeLiveBtn.onclick = () => setMode("live");
modeHistoryBtn.onclick = () => setMode("history");

// loadHistory lists ENDED sessions from the durable trace store (F3.6). Each row
// carries a per-session verify badge fetched from the server-side verdict.
async function loadHistory() {
  try {
    const r = await fetch("/v1/sessions/history", { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    renderHistory(await r.json());
  } catch (e) {
    historyEl.innerHTML = `<tr><td colspan="4" class="empty">history unavailable: ${esc(e.message)}</td></tr>`;
  }
}

function renderHistory(list) {
  if (!list || list.length === 0) {
    historyEl.innerHTML = `<tr><td colspan="4" class="empty">no persisted sessions</td></tr>`;
    return;
  }
  historyEl.innerHTML = "";
  for (const s of list) {
    const tr = document.createElement("tr");
    tr.className = "session" + (s.session_id === state.selected ? " sel" : "");
    tr.innerHTML =
      `<td title="${esc(s.session_id)}"><code>${esc(shortId(s.session_id))}</code></td>` +
      `<td>${esc(s.tier || "")}</td>` +
      `<td>${s.event_count | 0}</td>` +
      `<td><span class="badge pending" data-verify="${esc(s.session_id)}">…</span></td>`;
    tr.onclick = () => selectSession(s.session_id);
    historyEl.appendChild(tr);
    fetchRowVerify(s.session_id);
  }
}

// fetchRowVerify populates one history row's verify badge from the server-side
// verdict (never a browser-computed pass).
async function fetchRowVerify(id) {
  const cell = () => historyEl.querySelector(`[data-verify="${cssEsc(id)}"]`);
  try {
    const r = await fetch(`/v1/sessions/${encodeURIComponent(id)}/verify`, { headers: { Accept: "application/json" } });
    const el = cell();
    if (!el) return;
    if (!r.ok) { el.className = "badge pending"; el.textContent = "n/a"; return; }
    const v = await r.json();
    if (v.verified) { el.className = "badge ok"; el.textContent = "✓"; el.title = `verified — ${v.events} events`; }
    else {
      const seq = (v.broken_seq === undefined || v.broken_seq === null) ? "?" : v.broken_seq;
      el.className = "badge bad"; el.textContent = `✗ @${seq}`; el.title = v.reason || "tampered";
    }
  } catch {
    const el = cell();
    if (el) { el.className = "badge pending"; el.textContent = "n/a"; }
  }
}

// cssEsc escapes an id for use in a CSS attribute selector (session ids are
// daemon-generated, but be defensive against selector metacharacters).
function cssEsc(s) {
  return (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/["\\]/g, "\\$&");
}

// ================= F7.4: full CLI parity panes =================
//
// Every call below is same-origin, so the F7.1 HttpOnly auth cookie authenticates
// automatically — no token is ever read or stored in JS. Each maps to a widened
// allowlist route (create/exec/secrets/workspaces/policy) or the host-side
// /ui/link endpoint. No secret VALUE is ever fetched back: the secrets pane lists
// names/metadata only and the value input is write-only.

// ---- screen navigation ----
const screens = document.querySelectorAll(".screen");
const navBtns = document.querySelectorAll("#nav button");
function showScreen(name) {
  navBtns.forEach((b) => b.classList.toggle("active", b.dataset.screen === name));
  screens.forEach((s) => s.classList.toggle("active", s.dataset.screen === name));
  if (name === "secrets") loadSecrets();
  if (name === "workspaces") loadWorkspaces();
  if (name === "policy") loadPolicy();
  if (name === "link") loadLinks();
}
navBtns.forEach((b) => (b.onclick = () => showScreen(b.dataset.screen)));

function setNote(el, msg, kind) {
  el.className = "note" + (kind ? " " + kind : "");
  el.textContent = msg || "";
}

// ---- create session ----
$("#cs-go").onclick = async () => {
  const note = $("#cs-note");
  const body = {
    mode: $("#cs-mode").value,
    name: $("#cs-name").value || undefined,
    tier: $("#cs-tier").value || undefined,
    ttl: $("#cs-ttl").value || undefined,
  };
  setNote(note, "creating…");
  try {
    const r = await fetch("/v1/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const txt = await r.text();
    if (!r.ok) { setNote(note, `create failed: HTTP ${r.status} ${txt}`, "err"); return; }
    let j = {}; try { j = JSON.parse(txt); } catch {}
    setNote(note, `created ${j.session_id || ""} (${j.state || "?"})`, "ok");
    $("#ex-id").value = j.session_id || $("#ex-id").value;
    $("#lk-id").value = j.session_id || $("#lk-id").value;
  } catch (e) { setNote(note, "create failed: " + e.message, "err"); }
};

// ---- exec runner (streams the daemon's NDJSON frames) ----
$("#ex-go").onclick = async () => {
  const note = $("#ex-note"), out = $("#ex-out");
  const id = $("#ex-id").value.trim();
  const argv = $("#ex-argv").value.trim().split(/\s+/).filter(Boolean);
  if (!id || argv.length === 0) { setNote(note, "need a session id and a command", "err"); return; }
  out.textContent = "";
  setNote(note, "running…");
  try {
    const r = await fetch(`/v1/sessions/${encodeURIComponent(id)}/exec`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ argv }),
    });
    if (!r.ok) { setNote(note, `exec failed: HTTP ${r.status} ${await r.text()}`, "err"); return; }
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (line.trim()) handleExecFrame(line, note, out);
      }
    }
    if (buf.trim()) handleExecFrame(buf, note, out);
  } catch (e) { setNote(note, "exec failed: " + e.message, "err"); }
};

function handleExecFrame(line, note, out) {
  let f; try { f = JSON.parse(line); } catch { return; }
  if (f.status === "pending") {
    // Gated by the F4 approval path — NOT a bypass. Approve it in the Sessions view.
    setNote(note, `pending approval (rule ${f.rule || "?"}, exec ${f.exec_id || "?"}) — approve in the Sessions view`, "err");
    return;
  }
  if (f.error) { setNote(note, "runtime error: " + f.error, "err"); return; }
  if (f.truncated) { out.textContent += `\n[opslify: ${f.stream || "stdout"} output truncated]\n`; return; }
  if (typeof f.exit_code === "number") { setNote(note, `exit ${f.exit_code}`, f.exit_code === 0 ? "ok" : "err"); return; }
  if (typeof f.data === "string") out.textContent += stripAnsi(f.data);
}

// ---- secrets (names only) ----
async function loadSecrets() {
  const rows = $("#sec-rows");
  try {
    const r = await fetch("/v1/secrets", { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const list = await r.json();
    if (!list || list.length === 0) { rows.innerHTML = `<tr><td colspan="5" class="empty">no secrets</td></tr>`; return; }
    rows.innerHTML = "";
    for (const s of list) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td class="mono">${esc(s.ref)}</td><td>${esc(s.provider || "")}</td>` +
        `<td>${esc(s.scope || "")}</td><td>${esc(s.created_at || "")}</td>` +
        `<td><button class="danger">Remove</button></td>`;
      tr.querySelector("button").onclick = () => removeSecret(s.ref);
      rows.appendChild(tr);
    }
  } catch (e) { rows.innerHTML = `<tr><td colspan="5" class="empty">unavailable: ${esc(e.message)}</td></tr>`; }
}

$("#sec-add").onclick = async () => {
  const note = $("#sec-note");
  const ref = $("#sec-ref").value.trim();
  const value = $("#sec-value").value;
  if (!ref || !value) { setNote(note, "need a ref and a value", "err"); return; }
  // The value travels IN once (base64) and is never returned; clear it immediately.
  const value_b64 = btoa(unescape(encodeURIComponent(value)));
  try {
    const r = await fetch("/v1/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ref, provider: $("#sec-provider").value || undefined, value_b64 }),
    });
    if (!r.ok) { setNote(note, `add failed: HTTP ${r.status} ${await r.text()}`, "err"); return; }
    $("#sec-value").value = ""; $("#sec-ref").value = ""; $("#sec-provider").value = "";
    setNote(note, `added ${ref}`, "ok");
    loadSecrets();
  } catch (e) { setNote(note, "add failed: " + e.message, "err"); }
};

async function removeSecret(ref) {
  const note = $("#sec-note");
  if (!confirm(`Remove secret ${ref}?`)) return;
  try {
    const r = await fetch(`/v1/secrets/${ref.split("/").map(encodeURIComponent).join("/")}`, { method: "DELETE" });
    if (!r.ok && r.status !== 404) { setNote(note, `remove failed: HTTP ${r.status}`, "err"); return; }
    setNote(note, `removed ${ref}`, "ok");
    loadSecrets();
  } catch (e) { setNote(note, "remove failed: " + e.message, "err"); }
}

// ---- workspaces ls/rm ----
async function loadWorkspaces() {
  const rows = $("#ws-rows");
  try {
    const r = await fetch("/v1/workspaces", { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const list = await r.json();
    if (!list || list.length === 0) { rows.innerHTML = `<tr><td colspan="4" class="empty">no workspaces</td></tr>`; return; }
    rows.innerHTML = "";
    for (const wsp of list) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td class="mono">${esc(wsp.name)}</td><td>${wsp.snapshots | 0}</td>` +
        `<td>${esc(wsp.latest_time || String(wsp.latest_tag || ""))}</td>` +
        `<td><button class="danger">Remove</button></td>`;
      tr.querySelector("button").onclick = () => removeWorkspace(wsp.name);
      rows.appendChild(tr);
    }
  } catch (e) { rows.innerHTML = `<tr><td colspan="4" class="empty">unavailable: ${esc(e.message)}</td></tr>`; }
}

async function removeWorkspace(name) {
  const note = $("#ws-note");
  if (!confirm(`Remove workspace ${name}? This deletes its snapshots.`)) return;
  try {
    const r = await fetch(`/v1/workspaces/${encodeURIComponent(name)}`, { method: "DELETE" });
    if (!r.ok && r.status !== 404) { setNote(note, `remove failed: HTTP ${r.status} ${await r.text()}`, "err"); return; }
    setNote(note, `removed ${name}`, "ok");
    loadWorkspaces();
  } catch (e) { setNote(note, "remove failed: " + e.message, "err"); }
}

// ---- active policy view ----
async function loadPolicy() {
  const out = $("#pol-out");
  try {
    const r = await fetch("/v1/policy", { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    out.textContent = JSON.stringify(await r.json(), null, 2);
  } catch (e) { out.textContent = "policy unavailable: " + e.message; }
}

// ---- link a host dir + toggle F7.3 sync (host process) ----
$("#lk-on").onclick = () => setLink(true);
$("#lk-off").onclick = () => setLink(false);

async function setLink(on) {
  const note = $("#lk-note");
  const session_id = $("#lk-id").value.trim();
  const dir = $("#lk-dir").value.trim();
  if (!session_id || (on && !dir)) { setNote(note, "need a session id" + (on ? " and a host dir" : ""), "err"); return; }
  try {
    const r = await fetch("/ui/link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id, dir, on }),
    });
    const txt = await r.text();
    if (!r.ok) { setNote(note, txt || `HTTP ${r.status}`, "err"); return; }
    setNote(note, on ? "linked + syncing" : "sync stopped", "ok");
    loadLinks();
  } catch (e) { setNote(note, "link failed: " + e.message, "err"); }
}

let linkTimer = null;
async function loadLinks() {
  const rows = $("#lk-rows"), log = $("#lk-log");
  if (linkTimer) clearTimeout(linkTimer);
  try {
    const r = await fetch("/ui/link/status", { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const list = await r.json();
    if (!list || list.length === 0) { rows.innerHTML = `<tr><td colspan="4" class="empty">no linked directories</td></tr>`; log.textContent = ""; }
    else {
      rows.innerHTML = "";
      let lines = [];
      for (const l of list) {
        const tr = document.createElement("tr");
        const sync = l.running ? `<span class="badge ok">on</span>` : `<span class="badge">off</span>`;
        tr.innerHTML =
          `<td class="mono">${esc(shortId(l.session_id))}</td><td class="mono">${esc(l.dir)}</td>` +
          `<td>${sync}</td><td>${l.conflicts | 0}${l.error ? ` <span class="badge bad" title="${esc(l.error)}">err</span>` : ""}</td>`;
        rows.appendChild(tr);
        if (l.recent) lines = lines.concat(l.recent);
      }
      log.textContent = lines.slice(-100).join("\n");
    }
  } catch (e) { rows.innerHTML = `<tr><td colspan="4" class="empty">status unavailable: ${esc(e.message)}</td></tr>`; }
  // Poll while the link screen is visible so status/conflicts stay live.
  if ($(".screen[data-screen=link]").classList.contains("active")) {
    linkTimer = setTimeout(loadLinks, 2000);
  }
}

pollSessions();
