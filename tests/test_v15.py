"""v1.5 — injection vuln classes: SQLi (error/boolean/time), command
injection, SSTI, reflected XSS — all signature-proven, all autonomous
engine capabilities."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from aegis.audit import AuditLog
from aegis.capabilities import CapabilityEngine
from aegis.db import EngagementDB
from aegis.guard import CommandGuard
from aegis.runner import Runner
from aegis.scope import ScopeGate
from aegis.webattack import WebAttacker

LINKS = ('<a href="app.php?id=1">a</a><a href="app.php?cmd=x">b</a>'
         '<a href="app.php?name=x">c</a><a href="app.php?search=x">d</a>')


class _MultiVuln(BaseHTTPRequestHandler):
    """One app, four vulns: id=SQLi(error), cmd=CMDi, name=SSTI, search=XSS."""

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        out = ""
        idv = qs.get("id", [""])[0]
        if idv and any(p in idv for p in ("'", '"', "CONVERT")):
            out += ("<br>Warning: mysql_fetch_assoc(): You have an error in "
                    "your SQL syntax near ''1'' at line 1")
        cmd = qs.get("cmd", [""])[0]
        if "id" in cmd and any(c in cmd for c in (";", "|", "`", "$", "&")):
            out += "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        name = qs.get("name", [""])[0]
        if "{{7331*7}}" in name:
            out += "Hello 51317!"
        elif "{{7*'7'}}" in name:
            out += "Hello 7777777!"
        search = qs.get("search", [""])[0]
        if search:
            out += f"You searched for: {search}"  # reflected, unescaped
        body = f"<html><body>{LINKS}{out}</body></html>"
        self._send(body)

    def _send(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class _BoolSQLi(_MultiVuln):
    """q: no errors leaked, but true/false conditions change the result set."""

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        q = qs.get("q", [""])[0]
        if any(f in q for f in ("'1'='2", '"1"="2', "1=2")):
            out = "no results"
        else:
            out = "results: dog pics"
        self._send(f'<html><body><a href="s.php?q=1">q</a>{out}</body></html>')


class _TimeSQLi(_MultiVuln):
    """t: blind — only an injected delay reveals it."""

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        t = qs.get("t", [""])[0]
        if "SLEEP" in t or "WAITFOR" in t:
            time.sleep(3.2)
        self._send('<html><body><a href="b.php?t=1">t</a>ok</body></html>')


class _Clean(_MultiVuln):
    def do_GET(self):
        self._send(f"<html><body>{LINKS}<h1>all good</h1></body></html>")


def _server(cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _db(workspace):
    return EngagementDB(str(workspace / "eng.db"))


def _probe(workspace, cls, method):
    srv = _server(cls)
    try:
        db = _db(workspace)
        tid = db.add_target("testlab.local")
        audit = AuditLog(str(workspace / "logs"))
        att = WebAttacker(db, audit=audit, max_probes=500)
        url = f"http://127.0.0.1:{srv.server_port}/app.php"
        res = getattr(att, method)(url, tid, host="testlab.local")
        return srv, db, tid, res
    except Exception:
        srv.shutdown()
        raise


def _assert_hit(db, tid, res, needle, severity):
    assert res["vulnerable"] is True, res
    f = next(f for f in db.findings_for(tid) if needle in f["title"])
    assert f["severity"] == severity
    assert f["verified"] == 1 and f["provenance"] == "tool-proven"
    assert any(a["success"] for a in db.attempts_for(tid))


def test_sqli_error_based(workspace):
    srv, db, tid, res = _probe(workspace, _MultiVuln, "probe_sqli")
    try:
        _assert_hit(db, tid, res, "SQL Injection (error-based)", "high")
        assert res["param"] == "id"
    finally:
        srv.shutdown()


def test_sqli_boolean_blind(workspace):
    srv, db, tid, res = _probe(workspace, _BoolSQLi, "probe_sqli")
    try:
        _assert_hit(db, tid, res, "SQL Injection (boolean-blind)", "high")
        assert res["param"] == "q"
    finally:
        srv.shutdown()


def test_sqli_time_based(workspace):
    srv, db, tid, res = _probe(workspace, _TimeSQLi, "probe_sqli")
    try:
        _assert_hit(db, tid, res, "SQL Injection (time-based blind)", "high")
        assert "delay" in res["evidence"]
    finally:
        srv.shutdown()


def test_command_injection(workspace):
    srv, db, tid, res = _probe(workspace, _MultiVuln, "probe_cmdi")
    try:
        _assert_hit(db, tid, res, "OS Command Injection", "critical")
        assert res["param"] == "cmd"
        assert "uid=33" in res["evidence"]
    finally:
        srv.shutdown()


def test_ssti(workspace):
    srv, db, tid, res = _probe(workspace, _MultiVuln, "probe_ssti")
    try:
        _assert_hit(db, tid, res, "Server-Side Template Injection", "high")
        assert res["param"] == "name"
    finally:
        srv.shutdown()


def test_reflected_xss(workspace):
    srv, db, tid, res = _probe(workspace, _MultiVuln, "probe_xss")
    try:
        _assert_hit(db, tid, res, "Reflected XSS", "medium")
        assert res["param"] == "search"
    finally:
        srv.shutdown()


def test_clean_app_no_findings(workspace):
    srv, db, tid, res = _probe(workspace, _Clean, "probe_sqli")
    try:
        assert res["vulnerable"] is False
        assert db.findings_for(tid) == []
    finally:
        srv.shutdown()


def test_engine_runs_all_injection_classes(workspace):
    """End to end: engine pointed at a multi-vuln app finds all four."""
    srv = _server(_MultiVuln)
    try:
        auth = json.loads((workspace / "authorization.json").read_text())
        auth["scope"].append("127.0.0.1/32")
        (workspace / "authorization.json").write_text(json.dumps(auth))
        scope = ScopeGate("authorization.json")
        cfg = json.loads(Path(__file__).resolve().parent.parent
                         .joinpath("config.example.json").read_text())
        cfg["paths"] = {"output_dir": str(workspace / "out")}
        db = EngagementDB(str(workspace / "eng.db"))
        audit = AuditLog(str(workspace / "logs"))
        runner = Runner(cfg, db, audit, scope)
        runner.guard = CommandGuard(scope, str(workspace))
        engine = CapabilityEngine(runner, db, audit, scope)
        tid = db.add_target("127.0.0.1")
        db.record_intel(tid, "service", f"{srv.server_port}/tcp",
                        "http Apache", source="test")
        engine.run("attack", "127.0.0.1")
        titles = [f["title"] for f in db.findings_for(tid)]
        for needle in ("SQL Injection", "OS Command Injection",
                       "Server-Side Template Injection", "Reflected XSS"):
            assert any(needle in t for t in titles), \
                f"missing {needle}; got {titles}"
        # all ATT&CK tagged: sqli/ssti/xss → T1190, cmdi → T1059
        tags = {a["attack_id"] for a in db.attempts_for(tid)}
        assert "T1190" in tags and "T1059" in tags
    finally:
        srv.shutdown()
