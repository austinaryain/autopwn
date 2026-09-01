"""v1.3 — deterministic web attack layer: /lfi prober + PHP playbook hint."""

import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from aegis.audit import AuditLog
from aegis.db import EngagementDB
from aegis.playbook import hints_for
from aegis.webattack import WebAttacker

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
PHP_SOURCE = "<?php // dogcat app\n$cat = $_GET['cat'];\ninclude($cat);\n?>"
DOG_HTML = ('<html><body><h1>Dogs!</h1>'
            '<a href="index.php?view=dogs">dogs</a>'
            '<form><input type="text" name="cat"></form></body></html>')


class _VulnHandler(BaseHTTPRequestHandler):
    """Vulnerable PHP-app simulator: ?page=../etc/passwd leaks passwd,
    ?page=php://filter... returns base64 source."""

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        page = qs.get("page", [""])[0]
        if "php://filter" in page:
            body = "<html>" + base64.b64encode(
                PHP_SOURCE.encode()).decode() + "</html>"
        elif "../" in page or "etc/passwd" in page or page.startswith("/etc"):
            body = PASSWD
        else:
            body = DOG_HTML
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


class _CleanHandler(_VulnHandler):
    def do_GET(self):
        self._send(DOG_HTML)


def _server(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _db(workspace):
    return EngagementDB(str(workspace / "eng.db"))


def test_probe_lfi_finds_traversal(workspace):
    srv = _server(_VulnHandler)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/index.php?page=home"
        db = _db(workspace)
        audit = AuditLog(str(workspace / "logs"))
        tid = db.add_target("testlab.local")
        res = WebAttacker(db, audit=audit).probe_lfi(url, tid,
                                                     host="testlab.local")
        assert res["vulnerable"] is True
        assert res["param"] == "page"
        assert "passwd" in res["evidence"]
        # verified, tool-proven finding recorded
        findings = db.findings_for(tid)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "high"
        assert f["verified"] == 1
        assert f["provenance"] == "tool-proven"
        assert "Local File Inclusion" in f["title"]
        # successful attempt recorded
        attempts = db.attempts_for(tid)
        assert any(a["technique"] == "lfi" and a["success"] for a in attempts)
        # audit event written
        lines = audit.path.read_text(encoding="utf-8")
        assert "lfi_found" in lines
    finally:
        srv.shutdown()


def test_probe_lfi_filter_discloses_source(workspace):
    """php://filter source disclosure → loot + next_steps guidance."""

    class FilterOnly(_VulnHandler):
        def do_GET(self):
            qs = parse_qs(urlparse(self.path).query)
            page = qs.get("page", [""])[0]
            if "php://filter" in page:
                long_source = (PHP_SOURCE + "\n// padding for blob size\n"
                               ) * 5  # detector needs a ≥200-char b64 blob
                self._send(base64.b64encode(long_source.encode()).decode()
                           + "<!-- filtered -->")
            else:
                self._send(DOG_HTML)

    srv = _server(FilterOnly)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/index.php?page=home"
        db = _db(workspace)
        tid = db.add_target("testlab.local")
        res = WebAttacker(db).probe_lfi(url, tid)
        assert res["vulnerable"] is True
        assert "filter" in res["evidence"]
        assert "docker" in res["next_steps"].lower()
        loot = db.loot_for(tid)
        assert any("source code" in l["title"] for l in loot)
    finally:
        srv.shutdown()


def test_discover_params_from_page_and_common(workspace):
    srv = _server(_CleanHandler)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/index.php"
        att = WebAttacker(_db(workspace))
        params = att.discover_params(url)
        names = {p for _page, p in params}
        assert "view" in names   # from the ?view=dogs link
        assert "cat" in names    # from the form input
        assert "page" in names   # common param
        assert len(params) == len(set(params))  # deduped
    finally:
        srv.shutdown()


def test_probe_lfi_clean_server_no_finding(workspace):
    srv = _server(_CleanHandler)
    try:
        url = f"http://127.0.0.1:{srv.server_port}/index.php"
        db = _db(workspace)
        tid = db.add_target("testlab.local")
        res = WebAttacker(db).probe_lfi(url, tid)
        assert res["vulnerable"] is False
        assert res["probes"] > 0
        assert db.findings_for(tid) == []
    finally:
        srv.shutdown()


def test_playbook_php_hint_recommends_lfi(workspace):
    intel = [{"kind": "service", "key": "80/tcp", "value": "http Apache/2.4"},
             {"kind": "tech", "key": "php", "value": "PHP/7.4.21"}]
    hints = hints_for(intel, target="10.10.10.5", workspace=workspace)
    assert any("/lfi" in h for h in hints)
    assert any("docker.sock" in h or "/.dockerenv" in h for h in hints)


def test_playbook_no_lfi_hint_without_php(workspace):
    intel = [{"kind": "service", "key": "80/tcp", "value": "http nginx/1.25"}]
    hints = hints_for(intel, target="10.10.10.5", workspace=workspace)
    assert not any("/lfi" in h for h in hints)
