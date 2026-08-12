// opslify local UI — vanilla ES module, zero dependencies, fully self-contained.
//
// Data sources (existing daemon API only, proxied via the localhost UI server to
// the daemon's Unix socket — the browser never talks to the socket directly):
//   GET    /v1/sessions                       — live session list (polled)
//   GET    /v1/sessions/{id}/trace  (SSE)     — live event stream + backfill (from_seq)
//   DELETE /v1/sessions/{id}                   — Kill (the ONLY mutation this UI issues)
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
const terminalEl = $("#terminal");
const timelineEl = $("#timeline");
const selIdEl = $("#sel-id");
const killBtn = $("#btn-kill");
const replayBtn = $("#btn-replay");
const connEl = $("#conn");

const state = {
  selected: null,     // selected session id
  stream: null,       // AbortController for the active trace stream
  lastSeq: -1,        // highest seq rendered (for reconnect resume)
  events: [],         // rendered timeline events
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
  // If the selected session vanished (ended between renders), disable actions.
  if (state.selected && !ids.has(state.selected)) markSelectionGone();

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
  killBtn.disabled = false;
  replayBtn.disabled = false;
  openStream(id, 0);
  // Re-highlight rows on next poll; also do it immediately.
  document.querySelectorAll("tr.session").forEach((tr) => {
    tr.classList.toggle("sel", tr.querySelector("td")?.title === id);
  });
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
  }
  addTimeline(ev);
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

pollSessions();
