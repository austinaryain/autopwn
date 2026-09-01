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

from .dashboard_page import PAGE



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
        self.run_handler = None      # callable(host, command_str) — set by shell
        self.allowed_tools: list[str] = []  # for hint command extraction
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
        from .playbook import extract_commands, hints_for
        host = t["host"]
        hints = [h.replace("TARGET", host)
                 for h in hints_for(intel, loot=loot, target=host,
                                    workspace=self.workspace)]
        hint_commands = [extract_commands(h, self.allowed_tools)
                         for h in hints]
        return {"target": dict(t), "intel": intel, "findings": findings,
                "loot": loot, "attempts": attempts, "actions": actions,
                "hints": hints, "hint_commands": hint_commands}

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
                elif path == "/api/run":
                    if self_server.run_handler is None:
                        code, body = 400, json.dumps(
                            {"error": "no run handler wired"}).encode()
                    else:
                        try:
                            self_server.run_handler(str(data.get("host", "")),
                                                    str(data.get("command", "")))
                            code, body = 200, json.dumps(
                                {"started": True}).encode()
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
