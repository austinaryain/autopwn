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
<div class="card" style="margin-top:1.2rem"><h2>Recent activity</h2>
<div id="actions"></div></div>
<script>
async function refresh(){
  const s = await (await fetch('/api/state')).json();
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
    `<div>(${l.kind}) ${l.title} <span class="mono">${l.value}</span></div>`
    ).join('') || 'none yet';
  document.getElementById('actions').innerHTML = s.actions.map(a =>
    `<div class="mono">[${a.ts}] <b>${a.agent}</b> ${a.command}
     — <span class="${a.exit_code==0?'ok':'fail'}">${a.status}</span></div>`
    ).join('') || 'none yet';
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
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

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
        return {"targets": targets, "actions": actions, "findings": findings,
                "loot": loot, "attack": attack}

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
                else:
                    body = page.replace(
                        "/api/state", f"/api/state?token={self_server.token}"
                    ).encode()
                    ctype = "text/html"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
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
