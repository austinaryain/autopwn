"""Live engagement dashboard — local web UI over the engagement DB.

`/dashboard` starts a local HTTP server; the page auto-refreshes every 3 s
and shows targets, recent agent activity, attempts, findings, loot, and
ATT&CK coverage. Read-only; binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .attack_map import coverage
from .db import EngagementDB

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Aegis Dashboard</title>
<style>
body{font-family:system-ui,sans-serif;background:#0e1420;color:#dce6f2;
margin:0;padding:1.5rem}
h1{color:#5aa0ff;font-size:1.3rem} h2{color:#8fb8ef;font-size:1rem;
border-bottom:1px solid #22314a;padding-bottom:.3rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem}
.card{background:#151f30;border:1px solid #22314a;border-radius:8px;padding:1rem}
table{border-collapse:collapse;width:100%;font-size:.82rem}
td,th{padding:.25rem .5rem;text-align:left;border-bottom:1px solid #22314a}
.sev-critical{color:#ff5a5a}.sev-high{color:#ff9a3c}.sev-medium{color:#ffd93c}
.sev-low{color:#6fd3ff}.sev-info{color:#9fb3c8}
.ok{color:#5aff8a}.fail{color:#ff7a7a}.mono{font-family:ui-monospace,monospace;
font-size:.75rem;color:#9fb3c8}
a{color:#5aa0ff;text-decoration:none} a:hover{text-decoration:underline}
pre{white-space:pre-wrap;background:#0b111c;border:1px solid #22314a;
border-radius:6px;padding:.6rem;max-height:26rem;overflow:auto}
.chip{display:inline-block;background:#0b111c;border:1px solid #22314a;
border-radius:4px;padding:.05rem .45rem;margin:.12rem;font-size:.72rem}
</style></head><body>
<h1>🛡 Aegis Workbench — live engagement</h1>
<div class="grid">
<div class="card"><h2>Targets</h2><div id="targets"></div></div>
<div class="card"><h2>ATT&CK Coverage</h2><div id="attack"></div></div>
<div class="card"><h2>Findings</h2><div id="findings"></div></div>
<div class="card"><h2>Loot</h2><div id="loot"></div></div>
</div>
<div class="card" style="margin-top:1.2rem"><h2>Mission Control</h2>
<form onsubmit="launch(event)">
<input id="mhost" placeholder="in-scope target host" required>
<select id="mmode"><option>scan</option><option>attack</option><option>mission</option></select>
<button type="submit">Launch</button></form>
<div id="missions" class="mono"></div></div>
<div class="card" style="margin-top:1.2rem"><h2>Add to Scope</h2>
<form onsubmit="addScope(event)">
<input id="shost" placeholder="IP / host / CIDR" required>
<input id="snetwork" placeholder="network / room label (e.g. THM-Attacks)">
<button type="submit">Authorize</button></form>
<div id="scopemsg" class="mono"></div>
<div class="mono">Adds to authorization.json (audited) and registers the target.</div></div>
<div class="card" style="margin-top:1.2rem"><h2>Playbook Knowledge Base</h2>
<form onsubmit="addKb(event)">
<select id="kbgroup"><option value="version_hints">version exploit</option>
<option value="service_hints">service playbook</option>
<option value="port_hints">port fallback</option></select>
<input id="kbpattern" placeholder="regex on service string, or port (e.g. 6379)" required style="width:34%">
<input id="kbhint" placeholder="attack hint — use TARGET as host placeholder" required style="width:38%">
<button type="submit">Add rule</button></form>
<div id="kbmsg" class="mono"></div>
<div id="kbrules" class="mono"></div></div>
<div class="card" style="margin-top:1.2rem"><h2>Recent activity</h2>
<div id="actions"></div></div>
<div class="card" style="margin-top:1.2rem"><h2>Target Command Center</h2>
<div id="detail" class="mono">click a target above to explore everything known about it</div></div>
<div class="card" style="margin-top:1.2rem"><h2>Action log</h2>
<pre id="logview">press [log] on any action in the command center</pre></div>
<script>
const TOK = new URLSearchParams(location.search).get('token');
const REVEALED = {};  // loot id -> revealed value; survives the 3s refresh
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function launch(e){
  e.preventDefault();
  await fetch('/api/mission/start?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({host: mhost.value, mode: mmode.value})});
}
async function addScope(e){
  e.preventDefault();
  const r = await fetch('/api/scope/add?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({host: shost.value, network: snetwork.value})});
  const j = await r.json();
  document.getElementById('scopemsg').textContent =
    j.added ? '✔ authorized: '+shost.value : '✘ '+(j.error||'failed');
}
async function addKb(e){
  e.preventDefault();
  const r = await fetch('/api/playbook/add?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({group: kbgroup.value, pattern: kbpattern.value,
                          hint: kbhint.value})});
  const j = await r.json();
  document.getElementById('kbmsg').textContent =
    j.added ? '✔ rule added — live for the next planning step'
            : '✘ '+(j.error||'failed');
  if (j.added){ kbpattern.value=''; kbhint.value=''; }
  loadKb();
}
async function kbAction(op, i){
  await fetch('/api/playbook/'+op+'?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({index:i})});
  loadKb();
}
async function loadKb(){
  try {
    const j = await (await fetch('/api/playbook?token='+TOK)).json();
    const b = j.bundled, c = j.custom;
    const custom = (c.version_hints||[]).map(r=>['version',...r])
      .concat((c.service_hints||[]).map(r=>['service',...r]))
      .concat(Object.entries(c.port_hints||{}).map(([k,v])=>['port',k,v]));
    const drafts = (c.drafts||[]);
    document.getElementById('kbrules').innerHTML =
      `<div>${b.version_hints} version + ${b.service_hints} service + `+
      `${b.port_hints} port rules bundled — custom rules fire first, hot-reloaded</div>` +
      (drafts.length ? '<div style="margin-top:.4rem;color:#ffd93c">⏳ learned drafts — review before they go live:</div>' +
        drafts.map((d,i)=>`<div>✎ <b>${d.group}</b> <span class="mono">${esc(d.pattern)}</span> → ${esc(d.hint)}
          <a href="#" onclick="kbAction('promote',${i});return false" style="color:#5aff8a">promote</a>
          <a href="#" onclick="kbAction('dismiss',${i});return false" style="color:#ff7a7a">dismiss</a></div>`).join('') : '') +
      (custom.map(r=>`<div>· <b>${r[0]}</b> <span class="mono">${esc(r[1])}</span> → ${esc(r[2])}</div>`).join('') ||
       '<div>no live custom rules yet</div>');
  } catch(e){ /* transient */ }
}
async function stopMission(id){
  await fetch('/api/mission/stop?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
}
async function revealLoot(id){
  try {
    const r = await fetch('/api/loot?id='+id+'&reveal=1&token='+TOK);
    const j = await r.json();
    REVEALED[id] = j.error ? '⚠ '+j.error
                           : (j.value || j.file_path || '(no value stored)');
  } catch(e) { REVEALED[id] = '⚠ reveal failed: '+e; }
  refresh();
}
function lootLine(l){
  const shown = REVEALED[l.id] !== undefined ? REVEALED[l.id] : (l.value||'');
  const link = REVEALED[l.id] !== undefined ? '' :
    ` <a href="#" onclick="revealLoot(${l.id});return false"
       style="font-size:.75rem">reveal</a>`;
  return `<div>(${esc(l.kind)}) ${esc(l.title)} <span class="mono">${esc(shown)}</span>${link}</div>`;
}
// ---- Target Command Center --------------------------------------------------
let SEL = null;
async function selectTarget(id){ SEL = id; await loadDetail(); }
async function loadDetail(){
  if (SEL == null) return;
  try {
    const d = await (await fetch('/api/target?id='+SEL+'&token='+TOK)).json();
    if (d.error){ document.getElementById('detail').textContent = d.error; return; }
    renderDetail(d);
  } catch(e){ /* transient — next refresh retries */ }
}
async function showLog(id){
  const r = await fetch('/api/action/log?id='+id+'&token='+TOK);
  document.getElementById('logview').textContent = await r.text();
  document.getElementById('logview').scrollIntoView({behavior:'smooth'});
}
function renderDetail(d){
  const t = d.target;
  const svc  = d.intel.filter(i=>i.kind==='service');
  const web  = d.intel.filter(i=>i.kind==='web');
  const os   = d.intel.filter(i=>i.kind==='os');
  const tech = d.intel.filter(i=>i.kind==='tech');
  let h = `<div><b style="font-size:1.05rem">${esc(t.host)}</b>
    <span class="mono">${esc(t.status)}</span>
    <span class="mono">${esc(t.description||'')}</span></div>`;
  if (d.hints && d.hints.length) {
    h += '<h2>Playbook recommendations</h2>' + d.hints.map(x=>
      `<div class="mono" style="margin:.15rem 0">▸ ${esc(x)}</div>`).join('');
  }
  h += '<h2>Infrastructure</h2>';
  h += svc.length
    ? '<table><tr><th>port</th><th>service / version</th></tr>' +
      svc.map(s=>`<tr><td>${esc(s.key)}</td><td>${esc(s.value)}</td></tr>`).join('') +
      '</table>'
    : '<div class="mono">no services identified yet</div>';
  h += web.map(w=>`<span class="chip">🌐 ${esc(w.key)}: ${esc(w.value)}</span>`).join('');
  h += os.map(w=>`<span class="chip">🖥 ${esc(w.value)}</span>`).join('');
  h += tech.map(w=>`<span class="chip">⚙ ${esc(w.value)}</span>`).join('');
  h += '<h2>Findings</h2>' + (d.findings.map(f=>
    `<div class="sev-${f.severity}">[${f.severity.toUpperCase()}] ${esc(f.title)}</div>`
    ).join('') || '<div class="mono">none</div>');
  h += '<h2>Loot</h2>' + (d.loot.map(lootLine).join('') || '<div class="mono">none</div>');
  h += '<h2>Attempts</h2>' + (d.attempts.map(a=>
    `<div class="mono"><span class="${a.success?'ok':'fail'}">${a.success?'✔':'✘'}</span> `+
    `${esc(a.technique)}${a.vector?' via '+esc(a.vector):''} — ${esc((a.result||'').slice(0,140))}</div>`
    ).join('') || '<div class="mono">none</div>');
  h += '<h2>Actions</h2>' + (d.actions.map(a=>
    `<div class="mono">[${a.ts}] ${esc(a.command)} —
     <span class="${a.exit_code==0?'ok':'fail'}">${a.status}${a.exit_code?' (exit '+a.exit_code+')':''}</span>
     <a href="#" onclick="showLog(${a.id});return false" style="font-size:.72rem">log</a></div>` +
    (a.error ? `<div class="fail mono" style="white-space:pre-wrap;margin:0 0 .4rem 1rem">${esc(a.error)}</div>` : '')
    ).join('') || '<div class="mono">none</div>');
  document.getElementById('detail').innerHTML = h;
}
async function refresh(){
  const s = await (await fetch('/api/state?token='+TOK)).json();
  document.getElementById('targets').innerHTML = s.targets.map(t =>
    `<div><b><a href="#" onclick="selectTarget(${t.id});return false">${esc(t.host)}</a></b>
     <span class="mono">${esc(t.status)}</span></div>`).join('') || 'none';
  document.getElementById('attack').innerHTML =
    '<table>' + s.attack.map(a =>
      `<tr><td>${esc(a.tactic)}</td><td>${a.tried}</td><td class="ok">${a.succeeded}</td></tr>`
    ).join('') + '</table>';
  document.getElementById('findings').innerHTML = s.findings.map(f =>
    `<div class="sev-${f.severity}">[${f.severity.toUpperCase()}] ${esc(f.title)}
     <span class="mono">${esc(f.host||'')}</span></div>`).join('') || 'none yet';
  document.getElementById('loot').innerHTML = s.loot.map(lootLine).join('') || 'none yet';
  document.getElementById('actions').innerHTML = s.actions.map(a =>
    `<div class="mono">[${a.ts}] <b>${esc(a.agent)}</b> ${esc(a.command)}
     — <span class="${a.exit_code==0?'ok':'fail'}">${a.status}${
       a.exit_code ? ' (exit '+a.exit_code+')' : ''}</span></div>` +
    (a.error ? `<div class="fail mono" style="white-space:pre-wrap;margin:0 0 .5rem 1rem">${esc(a.error)}</div>` : '')
  ).join('') || 'none yet';
  document.getElementById('missions').innerHTML = Object.entries(s.missions||{})
    .map(([id,m]) => `<div>mission ${id}: <b>${esc(m.mode)}</b> ${esc(m.host)} — ${esc(m.status)}` +
      (m.status==='running' ?
       ` <a href="#" onclick="stopMission(${id});return false"
          style="color:#ff5a5a">■ stop</a>` : '') + `</div>`)
    .join('') || 'no missions yet';
  if (SEL != null) loadDetail();
  loadKb();
}
refresh(); setInterval(refresh, 3000);
</script></body></html>"""


class DashboardServer:
    def __init__(self, db: EngagementDB, host: str = "127.0.0.1",
                 port: int = 8765):
        import secrets
        self.db = db
        self.host = host
        self.port = port
        self.token = secrets.token_urlsafe(24)  # per-session bearer token
        self.missions: dict[int, dict] = {}
        self._mission_counter = 0
        self.mission_handler = None  # callable(host, mode, cancel_event)
        self.scope_handler = None    # callable(host, network) — set by shell
        self.audit = None            # optional AuditLog — set by shell
        self.workspace = "."         # engagement dir (playbook.custom.json)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def _loot_item(self, loot_id: int, reveal: bool) -> dict:
        row = self.db.conn.execute("SELECT * FROM loot WHERE id = ?",
                                   (loot_id,)).fetchone()
        if not row:
            return {"error": "not found"}
        decrypted = self.db._decrypt_row(row)
        value = decrypted["value"] or ""
        if not reveal and decrypted["kind"] in ("credential", "hash"):
            value = "••••••" + value[-4:] if len(value) >= 4 else "••••••"
        if reveal and self.audit is not None:
            self.audit.log("war-room", "loot", "view", {"id": loot_id})
        return {"id": row["id"], "kind": row["kind"], "title": row["title"],
                "value": value, "file_path": row["file_path"],
                "revealed": reveal}

    def launch_mission(self, host: str, mode: str) -> int:
        if self.mission_handler is None:
            raise RuntimeError("no mission handler wired")
        self._mission_counter += 1
        mid = self._mission_counter
        cancel = threading.Event()
        self.missions[mid] = {"host": host, "mode": mode, "status": "running"}

        def work():
            try:
                self.mission_handler(host, mode, cancel)
                if cancel.is_set():
                    self.missions[mid]["status"] = "stopped by operator"
                else:
                    self.missions[mid]["status"] = "complete"
            except Exception as exc:
                self.missions[mid]["status"] = f"error: {exc}"

        threading.Thread(target=work, daemon=True).start()
        self.missions[mid]["_cancel"] = cancel
        return mid

    def stop_mission(self, mid: int) -> bool:
        m = self.missions.get(mid)
        if not m or m["status"] != "running":
            return False
        cancel = m.get("_cancel")
        if cancel is not None:
            cancel.set()
            m["status"] = "stopping…"
            return True
        return False

    def _state(self) -> dict:
        conn = self.db.conn
        targets = [dict(r) for r in self.db.list_targets()]
        actions = [dict(r) for r in conn.execute(
            "SELECT ts, agent, command, exit_code, status, error FROM actions"
            " ORDER BY id DESC LIMIT 25").fetchall()]
        findings = []
        for f in self.db.findings_for():
            row = dict(f)
            t = self.db.get_target(f["target_id"])
            row["host"] = t["host"] if t else ""
            findings.append(row)
        loot = []
        for r in self.db.loot_for():
            row = dict(r)
            if row["kind"] in ("credential", "hash"):
                v = row.get("value") or ""
                row["value"] = "••••••" + v[-4:] if len(v) >= 4 else "••••••"
            loot.append(row)
        cov = coverage(self.db)
        attack = [{"tactic": t, "tried": len(c["tried"]),
                   "succeeded": len(c["succeeded"])}
                  for t, c in cov.items() if c["tried"]]
        missions = {str(k): {kk: vv for kk, vv in v.items()
                             if not kk.startswith("_")}
                    for k, v in self.missions.items()}
        return {"targets": targets, "actions": actions, "findings": findings,
                "loot": loot, "attack": attack, "missions": missions}

    def _target_detail(self, target_id: int) -> dict:
        """Everything known about one target — the command center payload."""
        t = self.db.get_target(target_id)
        if not t:
            return {"error": "target not found"}
        intel = [dict(r) for r in self.db.intel_for(target_id)]
        findings = [dict(f) for f in self.db.findings_for(target_id)]
        loot = []
        for r in self.db.loot_for(target_id):
            row = dict(r)
            if row["kind"] in ("credential", "hash"):
                v = row.get("value") or ""
                row["value"] = "••••••" + v[-4:] if len(v) >= 4 else "••••••"
            loot.append(row)
        attempts = [dict(r) for r in self.db.attempts_for(target_id)]
        actions = [dict(r) for r in self.db.conn.execute(
            "SELECT id, ts, agent, command, exit_code, status, error"
            " FROM actions WHERE target_id = ? ORDER BY id DESC LIMIT 50",
            (target_id,)).fetchall()]
        # what the knowledge base recommends for this exact target right now
        from .playbook import hints_for
        host = t["host"]
        hints = [h.replace("TARGET", host)
                 for h in hints_for(intel, loot=loot, target=host,
                                    workspace=self.workspace)]
        return {"target": dict(t), "intel": intel, "findings": findings,
                "loot": loot, "attempts": attempts, "actions": actions,
                "hints": hints}

    def _playbook_state(self) -> dict:
        from .playbook import list_custom_rules, load_kb
        kb = load_kb(self.workspace)
        return {"bundled": {g: len(kb.get(g, [])) for g in
                            ("version_hints", "service_hints", "port_hints",
                             "wordlists")},
                "custom": list_custom_rules(self.workspace)}

    def _action_log(self, action_id: int) -> str:
        row = self.db.conn.execute(
            "SELECT output_file FROM actions WHERE id = ?",
            (action_id,)).fetchone()
        if not row:
            return "(no such action)"
        if not row["output_file"]:
            return "(no captured output — refused actions have no log)"
        try:
            return Path(row["output_file"]).read_text(
                encoding="utf-8", errors="replace")[-200_000:]
        except OSError as exc:
            return f"(could not read output file: {exc})"

    def start(self) -> str:
        page = PAGE
        self_server = self

        class Handler(BaseHTTPRequestHandler):
            def _authorized(self) -> bool:
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(self.path).query)
                if q.get("token", [None])[0] == self_server.token:
                    return True
                auth = self.headers.get("Authorization", "")
                return auth == f"Bearer {self_server.token}"

            def do_GET(self):
                if not self._authorized():
                    self.send_response(403)
                    self.send_header("Content-Length", "13")
                    self.end_headers()
                    self.wfile.write(b"403 forbidden")
                    return
                path = self.path.split("?", 1)[0]
                if path == "/api/state":
                    body = json.dumps(self_server._state()).encode()
                    ctype = "application/json"
                elif path == "/api/loot":
                    from urllib.parse import urlparse, parse_qs
                    try:
                        q = parse_qs(urlparse(self.path).query)
                        loot_id = int(q.get("id", ["0"])[0])
                        reveal = q.get("reveal", ["0"])[0] == "1"
                        body = json.dumps(
                            self_server._loot_item(loot_id, reveal)).encode()
                    except (ValueError, TypeError) as exc:
                        body = json.dumps({"error": f"bad request: {exc}"}).encode()
                    ctype = "application/json"
                elif path == "/api/target":
                    from urllib.parse import urlparse, parse_qs
                    try:
                        q = parse_qs(urlparse(self.path).query)
                        tid = int(q.get("id", ["0"])[0])
                        body = json.dumps(
                            self_server._target_detail(tid)).encode()
                    except (ValueError, TypeError) as exc:
                        body = json.dumps({"error": f"bad request: {exc}"}).encode()
                    ctype = "application/json"
                elif path == "/api/action/log":
                    from urllib.parse import urlparse, parse_qs
                    try:
                        q = parse_qs(urlparse(self.path).query)
                        aid = int(q.get("id", ["0"])[0])
                        body = self_server._action_log(aid).encode()
                    except (ValueError, TypeError) as exc:
                        body = f"(bad request: {exc})".encode()
                    ctype = "text/plain; charset=utf-8"
                elif path == "/api/playbook":
                    body = json.dumps(self_server._playbook_state()).encode()
                    ctype = "application/json"
                else:
                    body = page.encode()
                    ctype = "text/html"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                from urllib.parse import urlparse
                if not self._authorized():
                    self.send_response(403)
                    self.end_headers()
                    return
                path = urlparse(self.path).path
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length) or b"{}")
                code, body = 404, json.dumps({"error": "unknown route"}).encode()
                if path == "/api/mission/start":
                    try:
                        mid = self_server.launch_mission(
                            str(data.get("host", "")), str(data.get("mode", "scan")))
                        code, body = 200, json.dumps({"mission_id": mid}).encode()
                    except Exception as exc:
                        code, body = 400, json.dumps({"error": str(exc)}).encode()
                elif path == "/api/mission/stop":
                    ok = self_server.stop_mission(int(data.get("id", 0)))
                    code = 200 if ok else 400
                    body = json.dumps({"stopped": ok}).encode()
                elif path == "/api/scope/add":
                    if self_server.scope_handler is None:
                        code, body = 400, json.dumps(
                            {"error": "no scope handler wired"}).encode()
                    else:
                        try:
                            self_server.scope_handler(str(data.get("host", "")),
                                                      str(data.get("network", "")))
                            code, body = 200, json.dumps({"added": True}).encode()
                        except Exception as exc:
                            code, body = 400, json.dumps(
                                {"error": str(exc)}).encode()
                elif path == "/api/playbook/add":
                    from .playbook import add_custom_rule
                    try:
                        group = str(data.get("group", ""))
                        pattern = str(data.get("pattern", ""))
                        hint = str(data.get("hint", ""))
                        add_custom_rule(self_server.workspace, group,
                                        pattern, hint)
                        if self_server.audit is not None:
                            self_server.audit.log(
                                "war-room", "playbook", "add_rule",
                                {"group": group, "pattern": pattern})
                        code, body = 200, json.dumps({"added": True}).encode()
                    except ValueError as exc:
                        code, body = 400, json.dumps(
                            {"error": str(exc)}).encode()
                elif path in ("/api/playbook/promote", "/api/playbook/dismiss"):
                    from .playbook import dismiss_draft, promote_draft
                    try:
                        idx = int(data.get("index", -1))
                        fn = promote_draft if path.endswith("promote") \
                            else dismiss_draft
                        d = fn(self_server.workspace, idx)
                        if self_server.audit is not None:
                            self_server.audit.log(
                                "war-room", "playbook",
                                "promote_rule" if fn is promote_draft
                                else "dismiss_rule",
                                {"pattern": d.get("pattern", "")})
                        code, body = 200, json.dumps({"ok": True}).encode()
                    except (ValueError, TypeError) as exc:
                        code, body = 400, json.dumps(
                            {"error": str(exc)}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # silence
                pass

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return f"http://{self.host}:{self.port}/?token={self.token}"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
