#!/usr/bin/env python3
"""Compose the six .dc.html screens into one hosted design-review page.

Each screen keeps its own document (iframe srcdoc) so their identical class
names can never collide. Escaping is done by json.dumps, not by hand.
"""
import json
import re
import pathlib

HERE = pathlib.Path(__file__).parent

SCREENS = [
    ("cockpit", "Cockpit.dc.html"),
    ("instructions", "AgentInstructions.dc.html"),
    ("platform", "WizardPlatform.dc.html"),
    ("skills", "WizardSkills.dc.html"),
    ("agent", "WizardAgent.dc.html"),
    ("secrets", "Secrets.dc.html"),
    ("connections", "Connections.dc.html"),
    ("policy", "Policy.dc.html"),
    ("sandboxes", "Sandboxes.dc.html"),
    ("change", "ChangeDetail.dc.html"),
]


def extract(path: pathlib.Path) -> str:
    """Pull the helmet <style> and the artboard markup into a standalone doc."""
    src = path.read_text(encoding="utf-8")
    style = re.search(r"<helmet>\s*(<style>.*?</style>)\s*</helmet>", src, re.S)
    body = re.search(r"</helmet>\s*(.*?)\s*</x-dc>", src, re.S)
    if not style or not body:
        raise SystemExit(f"{path.name}: could not find helmet/markup")
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        + style.group(1)
        + "<style>html,body{overflow:hidden;}</style>"
        + "</head><body>"
        + body.group(1)
        + "</body></html>"
    )


docs = {key: extract(HERE / name) for key, name in SCREENS}

TEMPLATE = """<title>Control Tower Directions</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap">
<style>
  :root {
    --wall:#e9ecf2; --surface:#ffffff; --sunk:#dfe3ec;
    --ink:#161a21; --muted:#5b6573; --rule:#d3d8e1;
    --accent:#2f6fd0; --gate:#9a6b00; --ok:#2f7d4f;
    --sans:"IBM Plex Sans","Segoe UI",system-ui,sans-serif;
    --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
    --bezel:#c9cfda;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --wall:#12141a; --surface:#191c23; --sunk:#0f1115;
      --ink:#dfe3ea; --muted:#8b93a3; --rule:#262a33;
      --accent:#5aa0ff; --gate:#e6b800; --ok:#4bd07f;
      --bezel:#2a2f3a;
    }
  }
  :root[data-theme="dark"] {
    --wall:#12141a; --surface:#191c23; --sunk:#0f1115;
    --ink:#dfe3ea; --muted:#8b93a3; --rule:#262a33;
    --accent:#5aa0ff; --gate:#e6b800; --ok:#4bd07f;
    --bezel:#2a2f3a;
  }

  * { box-sizing: border-box; }
  body {
    margin:0; background:var(--wall); color:var(--ink);
    font-family:var(--sans); font-size:16px; line-height:1.55;
    -webkit-font-smoothing:antialiased;
  }
  .wrap { max-width:1560px; margin:0 auto; padding:0 28px 84px; }

  /* ---- masthead ---- */
  header.top { padding:56px 0 34px; border-bottom:1px solid var(--rule); }
  .eyebrow {
    font-family:var(--mono); font-size:11.5px; font-weight:500;
    letter-spacing:.13em; text-transform:uppercase; color:var(--muted);
  }
  h1 {
    font-size:clamp(30px,4.6vw,50px); line-height:1.08; margin:14px 0 0;
    font-weight:600; letter-spacing:-.022em; text-wrap:balance; max-width:22ch;
  }
  .lede { margin:18px 0 0; max-width:64ch; font-size:17px; color:var(--muted); }
  .lede strong { color:var(--ink); font-weight:600; }

  /* ---- a direction ---- */
  section.dir { padding:52px 0; border-bottom:1px solid var(--rule); }
  .dirgrid { display:grid; grid-template-columns:300px minmax(0,1fr); gap:34px; align-items:start; }
  @media (max-width: 1080px) { .dirgrid { grid-template-columns:1fr; gap:20px; } }

  .rail { position:sticky; top:22px; display:flex; flex-direction:column; gap:16px; }
  @media (max-width: 1080px) { .rail { position:static; } }
  .letter {
    font-family:var(--mono); font-size:12px; font-weight:600; letter-spacing:.1em;
    color:var(--accent); text-transform:uppercase;
  }
  .rail h2 {
    font-size:24px; line-height:1.16; margin:0; font-weight:600;
    letter-spacing:-.012em; text-wrap:balance;
  }
  .rail .pitch { margin:0; font-size:14.5px; color:var(--muted); }
  .verdict { display:flex; flex-direction:column; gap:11px; }
  .vrow { display:grid; grid-template-columns:82px minmax(0,1fr); gap:12px; font-size:13.5px; }
  .vrow .vk {
    font-family:var(--mono); font-size:10.5px; letter-spacing:.08em; text-transform:uppercase;
    color:var(--muted); padding-top:3px;
  }
  .vrow.best .vv { color:var(--ink); }
  .vrow.trade .vv { color:var(--muted); }
  .pick {
    align-self:flex-start; font-family:var(--mono); font-size:10.5px; font-weight:600;
    letter-spacing:.09em; text-transform:uppercase; color:var(--ok);
    border:1px solid currentColor; border-radius:2px; padding:3px 8px;
  }

  /* ---- screen mount ---- */
  .mount { min-width:0; }
  .mounthdr {
    display:flex; align-items:baseline; gap:12px; margin-bottom:10px;
    font-family:var(--mono); font-size:11px; letter-spacing:.06em;
    text-transform:uppercase; color:var(--muted);
  }
  .mounthdr .spacer { flex:1; }
  .zoom {
    font-family:var(--mono); font-size:11px; letter-spacing:.05em; color:var(--muted);
    background:none; border:1px solid var(--rule); border-radius:3px;
    padding:3px 9px; cursor:pointer;
  }
  .zoom:hover { color:var(--ink); border-color:var(--muted); }
  .zoom:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .bezel {
    background:var(--sunk); border:1px solid var(--bezel); border-radius:7px;
    padding:7px; overflow:auto;
  }
  .stage { position:relative; overflow:hidden; }
  .stage iframe {
    width:1440px; height:900px; border:0; display:block;
    transform-origin:top left; background:#0f1115;
  }
  .bezel.full .stage { overflow:visible; }

  /* ---- closing ---- */
  section.close { padding:52px 0 0; }
  .close h2 { font-size:26px; margin:0 0 18px; font-weight:600; letter-spacing:-.014em; }
  .close p { max-width:66ch; color:var(--muted); font-size:16px; }
  .close p strong { color:var(--ink); font-weight:600; }
  .asks { display:flex; flex-direction:column; gap:14px; margin:26px 0 0; padding:0; list-style:none; max-width:70ch; }
  .asks li { display:grid; grid-template-columns:26px minmax(0,1fr); gap:14px; align-items:start; }
  .asks .q {
    font-family:var(--mono); font-size:11px; font-weight:600; color:var(--accent);
    border:1px solid var(--rule); border-radius:2px; text-align:center; padding:2px 0; margin-top:3px;
  }
  .asks .t { font-size:15.5px; }
  .asks .t b { font-weight:600; }
  code { font-family:var(--mono); font-size:.9em; color:var(--ink); }
  .tablewrap { overflow-x:auto; margin:24px 0 0; border:1px solid var(--rule); border-radius:7px; background:var(--surface); }
  table { border-collapse:collapse; width:100%; min-width:760px; font-size:14px; }
  th, td { text-align:left; padding:11px 15px; border-bottom:1px solid var(--rule); vertical-align:top; }
  th { font-family:var(--mono); font-size:10.5px; letter-spacing:.07em; text-transform:uppercase;
       color:var(--muted); font-weight:500; background:var(--sunk); }
  tbody tr:last-child td { border-bottom:0; }
  td b { font-family:var(--mono); font-size:12.5px; font-weight:600; color:var(--accent); }
  td:nth-child(3) { color:var(--ok); }
  @media (prefers-reduced-motion: reduce) { * { animation:none !important; transition:none !important; } }
</style>

<div class="wrap">

  <header class="top">
    <div class="eyebrow">opslify · design review</div>
    <h1>The cockpit, and the wizard that fills it</h1>
    <p class="lede">Settled: <strong>C's three-pane cockpit with A's sidebar</strong>, every section a
      dropdown. Below it, onboarding now runs platform → tools → <strong>skills</strong> → agent, so a
      new project ends up knowing your fleet and running on the model you choose. The two ideas worth
      arguing about are the per-tool skill files and bring-your-own-agent.</p>
  </header>

  __SECTIONS__

  <section class="close">
    <h2>The idea underneath: a connection is a capability, not a secret</h2>
    <p>SSH looked like a special case, but it is the same move you already make for HTTP. The daemon
      keeps the credential and hands the sandbox <strong>the smallest thing that still works</strong>.
      Once that is the rule, every connection kind becomes one row in the same table — and the
      right-hand column is the entire security argument.</p>

    <div class="tablewrap">
      <table>
        <thead>
          <tr><th>Kind</th><th>Mechanism</th><th>The sandbox receives</th><th>Audit event</th></tr>
        </thead>
        <tbody>
          <tr><td><b>http</b></td><td>L7 egress proxy injects the header upstream</td>
              <td>nothing</td><td><code>cred.resolve</code></td></tr>
          <tr><td><b>kubernetes</b></td><td>generated kubeconfig points at the session proxy; token added upstream</td>
              <td>a kubeconfig with no credential in it</td><td><code>k8s.request</code></td></tr>
          <tr><td><b>ssh</b></td><td>daemon-held agent, socket forwarded, key constrained to named hosts</td>
              <td>an agent socket — signatures only</td><td><code>ssh.sign</code></td></tr>
          <tr><td><b>cloud</b></td><td>STS AssumeRole / SA impersonation with a scope-down policy</td>
              <td>short-lived scoped credentials</td><td><code>cred.resolve</code></td></tr>
          <tr><td><b>database</b></td><td>auth proxy completes the handshake upstream</td>
              <td>a local socket, no password</td><td><code>db.session</code></td></tr>
          <tr><td><b>network</b></td><td>daemon holds the tunnel; sandbox routes through the gateway</td>
              <td>a route, no tunnel key</td><td><code>net.route</code></td></tr>
        </tbody>
      </table>
    </div>

    <p style="margin-top:24px;">The SSH row is the one worth dwelling on, and it now has sources
      behind it. The agent protocol has <strong>no export operation</strong> — add, remove, list, sign,
      lock — so key material genuinely cannot cross the socket. OpenSSH 8.9 added
      <strong>destination-constrained keys</strong> (<code>ssh-add -h host -H known_hosts</code>) for
      exactly the hostile-forwarding case, and the binding is anchored by
      <code>session-bind@openssh.com</code>, which carries the server's signature over the session
      identifier <em>using its host key</em>. OpenSSH's own wording: “the final destination cannot be
      forged because of the binding between the signature and the server hostkey.” A compromised
      sandbox cannot lie about where it is pointing the key — which is what makes the refused
      <code>db-02</code> line in Connections real rather than decorative.</p>

    <p>One more thing falls out of it. <code>ssh-add -c</code> makes every signature require
      confirmation, evaluated <em>agent-side</em> — in the daemon, outside the sandbox. That feature is
      unusable for humans, who would drown in prompts. An agent will happily wait for a policy engine on
      every single authentication. A feature nobody wants becomes a feature this product is built on.</p>

    <h2 style="margin-top:44px;">What this does <em>not</em> protect you from</h2>
    <p>Blinding the transport is not the whole job, and the design should say so. The largest remaining
      hole is not a credential problem at all:</p>
    <ul class="asks" style="margin-top:18px;">
      <li><span class="q">!</span><span class="t"><b>Exfiltration by authorised read.</b> An agent
        allowed to run <code>vault kv get</code>, <code>kubectl get secret</code> or
        <code>terraform show</code> reads plaintext secrets through a channel you deliberately opened.
        No amount of transport blindness helps. The answer is <b>response-side filtering</b> at the
        proxy — feasible for HTTP and kubeconfig because we already terminate them, impossible for SSH
        and database content without becoming a jump host.</span></li>
      <li><span class="q">!</span><span class="t"><b>Terraform state.</b> State files routinely hold
        plaintext secrets, so read access to the backend hands them over regardless.</span></li>
      <li><span class="q">!</span><span class="t"><b>SSH session content.</b> End-to-end encrypted. We
        see every authentication and every command we launch, but not what happens inside an
        interactive session unless we terminate the protocol.</span></li>
      <li><span class="q">!</span><span class="t"><b>A caveat worth knowing before build:</b>
        <code>kubectl exec</code>, <code>attach</code>, <code>port-forward</code> and <code>cp</code>
        use HTTP Upgrade. A proxy that mishandles hop-by-hop headers breaks exactly those four verbs and
        nothing else — a confusing failure to debug later, trivial to test for now.</span></li>
    </ul>

    <p style="margin-top:22px;">And an honest competitive note: <strong>Teleport, Boundary and
      StrongDM already do credential-blind SSH, database and Kubernetes access</strong> — with session
      recording, replay and revocation we would not match for years. What is different here is the
      inversion: every one of those products assumes a trusted client defending against a hostile
      target. <strong>Here the client is the threat.</strong> That is why an exotic, barely-adopted
      OpenSSH feature is our first-class primitive, why scope drops from per-session to per-tool-call,
      and why the audit stream is an input to the control loop rather than a compliance artifact.
      Integrating Boundary or Teleport as the SSH certificate authority is very likely a better use of
      effort than reimplementing one.</p>

    <h2 style="margin-top:44px;">What I need from you</h2>
    <ul class="asks">
      <li><span class="q">1</span><span class="t"><b>Does the layering hold up?</b> I answered my own
        last question in the design: house rules daemon-held and read-only, everything else in the repo
        so it versions and reviews. The open part is whether five layers is one too many — the
        environment overlay could fold into the project file with prod/staging headings.</span></li>
      <li><span class="q">2</span><span class="t"><b>Is <em>Connections</em> the right name?</b> It has
        to cover a token, a kubeconfig, an SSH key and a VPN route. Alternatives: Access, Targets,
        Bindings.</span></li>
      <li><span class="q">3</span><span class="t"><b>Which connection kinds ship in v1?</b>
        http, kubernetes and ssh cover your stack today. Database and network are real work for fewer
        people — I would defer both unless you need them now.</span></li>
    </ul>
    <p style="margin-top:26px;">Answer those and I will write the P8 spec: the data model
      (Project → Environment → Connection → Skill → Agent → Sandbox → Change), the broker interface each
      connection kind plugs into, and a ruthless MVP — through the same build-then-adversarial-QA gate
      as everything else. Every screen here runs at <code>1440×900</code>; hit <code>1:1</code> to read
      the real density.</p>
  </section>

</div>

<script type="application/json" id="docs">__DOCS__</script>
<script>
  (function () {
    var docs = JSON.parse(document.getElementById("docs").textContent);
    var W = 1440, H = 900;

    document.querySelectorAll(".stage").forEach(function (stage) {
      var frame = document.createElement("iframe");
      frame.setAttribute("title", stage.dataset.label);
      frame.setAttribute("loading", "lazy");
      frame.setAttribute("scrolling", "no");
      frame.srcdoc = docs[stage.dataset.screen];
      stage.appendChild(frame);
    });

    function fit(stage) {
      var bezel = stage.closest(".bezel");
      var frame = stage.querySelector("iframe");
      if (bezel.classList.contains("full")) {
        frame.style.transform = "none";
        stage.style.height = H + "px";
        stage.style.width = W + "px";
        return;
      }
      var avail = bezel.clientWidth - 14;
      var s = Math.min(1, avail / W);
      frame.style.transform = "scale(" + s + ")";
      stage.style.height = Math.round(H * s) + "px";
      stage.style.width = "100%";
    }

    var stages = Array.prototype.slice.call(document.querySelectorAll(".stage"));
    stages.forEach(fit);

    if (window.ResizeObserver) {
      var ro = new ResizeObserver(function () { stages.forEach(fit); });
      document.querySelectorAll(".bezel").forEach(function (b) { ro.observe(b); });
    } else {
      window.addEventListener("resize", function () { stages.forEach(fit); });
    }

    document.querySelectorAll(".zoom").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var bezel = document.getElementById(btn.dataset.for);
        var full = bezel.classList.toggle("full");
        btn.textContent = full ? "fit" : "1:1";
        btn.setAttribute("aria-pressed", String(full));
        fit(bezel.querySelector(".stage"));
        if (full) { bezel.scrollLeft = 0; }
      });
    });
  })();
</script>
"""

DIRECTIONS = [
    dict(
        key="cockpit", letter="The main screen", title="Cockpit — C's layout, A's sidebar",
        pitch="Your call, built: C's explorer replaced by A's rail, and every section is now a "
              "collapsible group (Tools is shown collapsed).",
        best="Environment, live sandbox with kill switch, connections by kind, skills loaded, tools, "
             "workspace — each opening and closing independently so the column never runs out of room "
             "as a project grows.",
        trade="New in the header: a permanent agent pill — which model is driving, over which "
              "transport, with how many tools and skills. You should never have to wonder who is at "
              "the controls.",
        pick="settled", label="Cockpit",
    ),
    dict(
        key="instructions", letter="The screen I had missed", title="Agent instructions",
        pitch="You were right — there was nowhere in the running product to instruct the agent. The "
              "wizard writes skills once; this is where you live afterwards.",
        best="Five layers in precedence order: daemon house rules (locked), project instructions, an "
              "environment overlay, the skill files, and the generated tool contracts. The right rail "
              "assembles them and shows exactly what the agent receives, with the token cost of each.",
        trade="It also answers the question I asked you last round. House rules are daemon-held and "
              "read-only, so an agent with write access to the repo still cannot edit the rule that "
              "says stop before touching db-01. Everything else lives in the repo and reviews in an MR.",
        pick="new", label="Agent instructions",
    ),
    dict(
        key="platform", letter="Onboarding · step 2", title="Platform first",
        pitch="Before tools, the question that determines everything else: where does this project "
              "actually run?",
        best="Pick AWS, Azure, Kubernetes, VMs, GCP, Hetzner, DigitalOcean or your own GitLab — "
              "multi-select, because real projects span several. The right panel answers back live.",
        trade="Each platform declares the connection kinds it needs, the tools it suggests and the "
              "guardrails it writes. Choosing “VMs” is what makes the SSH step appear later — and that "
              "step asks for the hosts a key may reach, then constrains the key to exactly those.",
        pick=None, label="Platform",
    ),
    dict(
        key="skills", letter="Onboarding · step 4", title="Skills — the idea I would fight for",
        pitch="Every tool ships a starter instruction file. You edit it; the agent reads it before it "
              "touches anything.",
        best="The example is real: drain before restarting a web node, one node at a time, db-01 is "
              "the primary so stop and ask a human, 502s here are memory pressure so check free -m "
              "first.",
        trade="This is the difference between an agent that knows DevOps and an agent that knows "
              "YOUR fleet — and it is the cheapest quality lever in the product. Skills are versioned "
              "with the project and named in every change's trace, so you can see which rule shaped a "
              "decision.",
        pick="highest value", label="Skills",
    ),
    dict(
        key="agent", letter="Onboarding · step 5", title="Bring your own agent",
        pitch="opslify ships no model. Claude Code, a local Qwen through Ollama, Codex, or any command "
              "that speaks MCP over stdio.",
        best="Set per project and per environment, with a fallback — prod on a model you trust, a "
              "scratch project on a cheap local one. The shell panel shows the CLI path for anything "
              "not in the list.",
        trade="The point underneath: the sandbox boundary does not move. A local Qwen and a hosted "
              "Claude get the same five tools, the same gates and the same audit trail. The model "
              "changes cost, latency and where your prompts go — never what the agent may do.",
        pick=None, label="Agent",
    ),
    dict(
        key="secrets", letter="New · you asked for this", title="Secrets — where a reference comes from",
        pitch="The missing first step. You store a value once; what you get back is a name.",
        best="Store, and you never see the value again — no API, UI or socket route can return it. "
              "Everything downstream uses the reference, which is why it is safe to write in a config "
              "file or hand to an agent.",
        trade="The table shows which connections consume each secret: one ssh-ops-fleet key backs both "
              "the web fleet and db-01, each with its own destination constraint. That split is why "
              "rotating a key is one action here rather than an edit in six config files.",
        pick="new", label="Secrets",
    ),
    dict(
        key="connections", letter="Underneath", title="Connections",
        pitch="One primitive for kubeconfigs, SSH keys, cloud roles, databases and tokens.",
        best="Every kind with how it is injected and — the load-bearing column — what the agent "
             "receives: nothing, a credential-free kubeconfig, an agent socket that only returns "
             "signatures, a 15-minute token.",
        trade="Now verified: the SSH agent protocol has no export operation, and OpenSSH 8.9's "
              "destination constraints are anchored by the target's own host key, so a compromised "
              "sandbox cannot lie about where it is pointing a key. The refused db-02 line is real.",
        pick=None, label="Connections",
    ),
    dict(
        key="policy", letter="New · you asked for this", title="Policy — including egress",
        pitch="How to create and update the guardrails, per environment, without editing YAML on the "
              "host and restarting a daemon.",
        best="Egress allowlist with the reason each host is there; approval gates; preview-before-apply "
              "rules; session limits. Add a host and it resolves and pins it.",
        trade="The move that matters: editing a guardrail is ITSELF a Change — same diff, same "
              "approval, same signed trace. Widening is gated; narrowing is not. Nobody quietly opens "
              "egress to a host they need, and the house-rules gate is locked even to you.",
        pick="new", label="Policy & egress",
    ),
    dict(
        key="sandboxes", letter="Underneath", title="Sandboxes",
        pitch="Every sandbox, live and recent, with the honest answer to “what can this thing touch "
              "right now?”",
        best="Isolation tier, which agent and change is driving it, TTL, memory, the warm pool. The "
             "rail opens one: exactly what isolation is in force, its bridge address, attached "
             "connections, workspace sync.",
        trade="It is also the kill switch for when the answer is wrong.",
        pick=None, label="Sandboxes",
    ),
    dict(
        key="change", letter="Underneath", title="Change detail & approval",
        pitch="Where trust is earned — unchanged, and still the screen the whole product points at.",
        best="The pinned diff, who asked, the rule that gated it, blast radius, the credential used by "
             "name with value seen by nobody, and the prepared revert.",
        trade="An SSH change reads identically to a Kubernetes one. The unit does not change just "
              "because the connection kind does.",
        pick=None, label="Change detail",
    ),
]


def section(d: dict) -> str:
    pick = f'<span class="pick">{d["pick"]}</span>' if d["pick"] else ""
    bez = f'bez-{d["key"]}'
    # The two key screens describe rather than weigh, so their rows are relabelled.
    is_key = d["letter"] != "The main screen"
    k1, k2 = ("It shows", "Why") if is_key else ("The sidebar", "Also new")
    return f"""
  <section class="dir">
    <div class="dirgrid">
      <div class="rail">
        <div class="letter">{d["letter"]}</div>
        <h2>{d["title"]}</h2>
        <p class="pitch">{d["pitch"]}</p>
        <div class="verdict">
          <div class="vrow best"><span class="vk">{k1}</span><span class="vv">{d["best"]}</span></div>
          <div class="vrow trade"><span class="vk">{k2}</span><span class="vv">{d["trade"]}</span></div>
        </div>
        {pick}
      </div>
      <div class="mount">
        <div class="mounthdr">
          <span>{d["label"]}</span>
          <span class="spacer"></span>
          <button class="zoom" data-for="{bez}" aria-pressed="false">1:1</button>
        </div>
        <div class="bezel" id="{bez}">
          <div class="stage" data-screen="{d["key"]}" data-label="{d["label"]}"></div>
        </div>
      </div>
    </div>
  </section>"""


html = TEMPLATE.replace("__SECTIONS__", "\n".join(section(d) for d in DIRECTIONS))
html = html.replace("__DOCS__", json.dumps(docs))
out = HERE / "control-tower-directions.html"
out.write_text(html, encoding="utf-8")
print(f"wrote {out} ({len(html) / 1024:.0f} KB, {len(docs)} screens)")
