"""v1.4 — capability engine: the agent plans over declared capabilities,
not shell commands. The headline test: point the attack engine at a
simulated vulnerable PHP app and it finds (and follows up on) the LFI
entirely on its own — no human hint, no LLM."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from aegis.audit import AuditLog
from aegis.capabilities import CapabilityEngine, TargetState, default_registry
from aegis.db import EngagementDB
from aegis.guard import CommandGuard
from aegis.runner import Runner
from aegis.scope import ScopeError, ScopeGate

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
APP_SOURCE = ("<?php\n// dogcat-style app\n$db_pass = 's3cret-bounty-cred';\n"
              "$page = $_GET['page'];\ninclude($page . '.php');\n"
              "// padding padding padding padding padding padding\n?>")
DOG_HTML = ('<html><body><h1>Dogs and cats!</h1>'
            '<a href="index.php?view=dogs">dogs</a></body></html>')


class _VulnPHP(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        page = qs.get("page", [""])[0]
        if "php://filter" in page:
            body = "<html>" + base64.b64encode(
                APP_SOURCE.encode()).decode() + "</html>"
        elif "../" in page or page.startswith("/etc"):
            body = PASSWD
        else:
            body = DOG_HTML
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def _server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnPHP)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _scoped(workspace):
    """Scope fixture + localhost (the test server lives on 127.0.0.1)."""
    auth = json.loads((workspace / "authorization.json").read_text())
    auth["scope"].append("127.0.0.1/32")
    (workspace / "authorization.json").write_text(json.dumps(auth))
    return ScopeGate("authorization.json")


def _engine(workspace):
    cfg = json.loads(Path(__file__).resolve().parent.parent
                     .joinpath("config.example.json").read_text())
    cfg["paths"] = {"output_dir": str(workspace / "out")}
    scope = _scoped(workspace)
    db = EngagementDB(str(workspace / "eng.db"))
    audit = AuditLog(str(workspace / "logs"))
    runner = Runner(cfg, db, audit, scope)
    runner.guard = CommandGuard(scope, str(workspace))
    return CapabilityEngine(runner, db, audit, scope), db


def test_engine_autonomously_finds_and_escalates_lfi(workspace):
    srv = _server()
    try:
        engine, db = _engine(workspace)
        tid = db.add_target("127.0.0.1")
        # seed the recon picture a scan would have produced
        db.record_intel(tid, "service", f"{srv.server_port}/tcp",
                        "http Apache httpd 2.4.49", source="test")
        db.record_intel(tid, "tech", "php", "PHP 8.1", source="test")

        events = []
        result = engine.run("attack", "127.0.0.1", on_step=events.append)

        # 1. it tried the LFI probe — nobody told it to
        attempts = [dict(a) for a in db.attempts_for(tid)]
        lfi = [a for a in attempts if a["technique"] == "attack.lfi-probe"]
        assert lfi and lfi[0]["success"], f"attempts: {[a['technique'] for a in attempts]}"

        # 2. verified, tool-proven finding recorded
        findings = db.findings_for(tid)
        assert any(f["verified"] == 1 and "Local File Inclusion" in f["title"]
                   for f in findings)

        # 3. it CHAINED: confirmed LFI unlocked the source-read capability,
        #    and the app source (with its credential) landed in loot
        assert any(a["technique"] == "attack.lfi-source-read" and a["success"]
                   for a in attempts)
        loot = db.loot_for(tid)
        assert any("source code" in l["title"] for l in loot)
        assert any("s3cret-bounty-cred" in (l["value"] or "") for l in loot)

        # 4. ATT&CK tagging: LFI → T1190 Exploit Public-Facing Application
        assert any(a["attack_id"] == "T1190" for a in attempts)

        # 5. every step was observed and reported
        assert any(e.get("phase") == "observed" for e in events)
        assert result["transcript"]
    finally:
        srv.shutdown()


def test_engine_never_retries_tried_capabilities(workspace):
    srv = _server()
    try:
        engine, db = _engine(workspace)
        tid = db.add_target("127.0.0.1")
        db.record_intel(tid, "service", f"{srv.server_port}/tcp",
                        "http Apache", source="test")
        engine.run("attack", "127.0.0.1")
        n1 = len(db.attempts_for(tid))
        assert n1 > 0
        engine.run("attack", "127.0.0.1")  # second run: nothing new to try
        assert len(db.attempts_for(tid)) == n1
    finally:
        srv.shutdown()


def test_engine_skips_lfi_when_no_web_surface(workspace):
    engine, db = _engine(workspace)
    tid = db.add_target("127.0.0.1")
    db.record_intel(tid, "service", "22/tcp", "ssh OpenSSH 8.9p1",
                    source="test")
    result = engine.run("attack", "127.0.0.1")
    attempted = {a["technique"] for a in db.attempts_for(tid)}
    assert "attack.lfi-probe" not in attempted
    assert "attack.lfi-source-read" not in attempted
    assert result["transcript"]


def test_engine_refuses_out_of_scope(workspace):
    engine, _db = _engine(workspace)
    with pytest.raises(ScopeError):
        engine.run("attack", "192.0.2.99")


def test_registry_is_sane():
    reg = default_registry()
    names = [c.name for c in reg]
    assert len(names) == len(set(names)), "duplicate capability names"
    assert all(c.phase in ("recon", "attack") for c in reg)
    assert all(callable(c.when) and callable(c.execute) for c in reg)
    # the web vuln-class capabilities exist
    assert "attack.lfi-probe" in names
    assert "attack.lfi-source-read" in names


def test_target_state_queries(workspace):
    db = EngagementDB(str(workspace / "state.db"))
    tid = db.add_target("testlab.local")
    db.record_intel(tid, "service", "80/tcp", "http Apache/2.4", source="t")
    db.record_intel(tid, "service", "22/tcp", "ssh OpenSSH 8.9", source="t")
    db.record_intel(tid, "tech", "php", "PHP 8.1", source="t")
    db.record_loot(tid, "credential", "ssh", value="admin:hunter2")
    s = TargetState(db, tid, "testlab.local")
    assert s.web_ports() == [80]
    assert s.has_php()
    assert s.login_services() == ["ssh"]
    assert s.creds()[0]["value"] == "admin:hunter2"
    assert s.base_url() == "http://testlab.local"
    assert not s.tried("attack.lfi-probe")
