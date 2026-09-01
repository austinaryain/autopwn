"""Live engagement dashboard — local web UI over the engagement DB.

`/dashboard` starts a local HTTP server; the page auto-refreshes every 3 s
and shows targets, recent agent activity, attempts, findings, loot, and
ATT&CK coverage. Read-only; binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
<div class="card" style="margin-top:1.2rem"><h2>Recent activity</h2>
<div id="actions"></div></div>
<script>
const TOK = new URLSearchParams(location.search).get('token');
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
async function stopMission(id){
  await fetch('/api/mission/stop?token='+TOK, {method:'POST',
    headers:{'Content-Type':'application/json'}, body: JSON.stringify({id})});
}
async function revealLoot(id, el){
  const r = await fetch('/api/loot?id='+id+'&reveal=1&token='+TOK);
  const j = await r.json();
  el.outerHTML = '<span class="mono">'+(j.value||j.file_path||'')+'</span>';
}
async function refresh(){
  const s = await (await fetch('/api/state?token='+TOK)).json();
  document.getElementById('targets').innerHTML = s.targets.map(t =>
    `<div><b>${t.host}</b> <span class="mono">${t.status}</span></div>`).join('') || 'none';
  document.getElementById('attack').innerHTML =
    '<table>' + s.attack.map(a =>
      `<tr><td>${a.tactic}</td><td>${a.tried}</td><td class="ok">${a.succeeded}</td></tr>`
    ).join('') + '</table>';
  document.getElementById('findings').innerHTML = s.findings.map(f =>
    `<div class="sev-${f.severity}">[${f.severity.toUpperCase()}] ${f.title}
     <span class="mono">${f.host||''}</span></div>`).join('') || 'none yet';
  document.getElementById('loot').innerHTML = s.loot.map(l =>
    `<div>(${l.kind}) ${l.title} <span class="mono">${l.value}</span>
     <a href="#" onclick="revealLoot(${l.id},this);return false"
        style="color:#5aa0ff;font-size:.75rem">reveal</a></div>`
    ).join('') || 'none yet';
  document.getElementById('actions').innerHTML = s.actions.map(a =>
    `<div class="mono">[${a.ts}] <b>${a.agent}</b> ${a.command}
     — <span class="${a.exit_code==0?'ok':'fail'}">${a.status}</span></div>`
    ).join('') || 'none yet';
  document.getElementById('missions').innerHTML = Object.entries(s.missions||{})
    .map(([id,m]) => `<div>mission ${id}: <b>${m.mode}</b> ${m.host} — ${m.status}` +
      (m.status==='running' ?
       ` <a href="#" onclick="stopMission(${id});return false"
          style="color:#ff5a5a">■ stop</a>` : '') + `</div>`)
    .join('') || 'no missions yet';
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
            "SELECT ts, agent, command, exit_code, status FROM actions"
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
                    q = parse_qs(urlparse(self.path).query)
                    loot_id = int(q.get("id", ["0"])[0])
                    reveal = q.get("reveal", ["0"])[0] == "1"
                    body = json.dumps(
                        self_server._loot_item(loot_id, reveal)).encode()
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
