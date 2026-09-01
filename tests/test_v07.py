"""v0.7 tests: intel extraction, flag hunting, playbook hints,
guard grounding, command-center endpoints, refusal adaptability."""

import json
import os
import sys
from pathlib import Path

import pytest
import requests

from aegis.db import EngagementDB
from aegis.dashboard import DashboardServer
from aegis.guard import CommandGuard, GuardError
from aegis.intel import extract_intel, hunt_flags
from aegis.playbook import hints_for
from aegis.runner import Runner
from aegis.audit import AuditLog

NMAP_SV = """\
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.49 ((Unix))
3306/tcp open  mysql   MySQL 5.7.38
OS details: Linux 4.15 - 5.6
"""

CURL_HEADERS = """\
HTTP/1.1 200 OK
Server: Apache/2.4.49 (Unix)
X-Powered-By: PHP/7.4.21
Content-Type: text/html
"""

WHATWEB = ('http://10.10.10.5 [200 OK] Apache[2.4.49], PHP[7.4.21], '
           'WordPress[5.8], Country[RESERVED][ZZ]')


# ---- intel extraction --------------------------------------------------------

def test_extract_services_and_os():
    items = extract_intel("nmap", "nmap -sV", NMAP_SV)
    svc = {(i["key"], i["value"]) for i in items if i["kind"] == "service"}
    assert ("22/tcp", "ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)") in svc
    assert ("80/tcp", "http Apache httpd 2.4.49 ((Unix))") in svc
    os_items = [i for i in items if i["kind"] == "os"]
    assert os_items and "Linux" in os_items[0]["value"]


def test_extract_web_headers():
    items = extract_intel("curl", "curl -sI", CURL_HEADERS)
    web = {(i["key"], i["value"]) for i in items if i["kind"] == "web"}
    assert ("server", "Apache/2.4.49 (Unix)") in web
    assert ("x-powered-by", "PHP/7.4.21") in web


def test_extract_whatweb_tech():
    items = extract_intel("whatweb", "whatweb http://x", WHATWEB)
    tech = [i["value"] for i in items if i["kind"] == "tech"]
    assert "Apache 2.4.49" in tech
    assert "PHP 7.4.21" in tech
    assert "WordPress 5.8" in tech


# ---- flag hunting -------------------------------------------------------------

def test_hunt_thm_and_htb_flags():
    out = "congrats! user flag: THM{c4ptur3_th3_fl4g} and HTB{an0th3r_0ne}"
    found = hunt_flags(out)
    values = [f["value"] for f in found]
    assert "THM{c4ptur3_th3_fl4g}" in values
    assert "HTB{an0th3r_0ne}" in values
    assert all(f["kind"] == "flag" for f in found)


def test_hunt_hex32_only_in_flag_context():
    plain = hunt_flags("md5sum: 5d41402abc4b2a76b9719d911017c592 file.txt")
    assert not plain  # no flag context -> no false positive
    ctx = hunt_flags("root.txt contains 5d41402abc4b2a76b9719d911017c592")
    assert ctx and ctx[0]["value"] == "5d41402abc4b2a76b9719d911017c592"


def test_hunt_private_key():
    out = ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n"
           "-----END RSA PRIVATE KEY-----")
    found = hunt_flags(out)
    assert found and found[0]["kind"] == "credential"
    assert "BEGIN RSA PRIVATE KEY" in found[0]["value"]


# ---- intel storage -------------------------------------------------------------

def test_intel_dedupe(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    db.record_intel(tid, "service", "80/tcp", "http Apache 2.4.49")
    db.record_intel(tid, "service", "80/tcp", "http Apache 2.4.49")
    rows = db.intel_for(tid)
    assert len(rows) == 1


def test_memory_summary_has_profile(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    db.record_intel(tid, "web", "x-powered-by", "PHP/7.4.21")
    mem = db.memory_summary(tid)
    assert "Target profile" in mem and "PHP/7.4.21" in mem


# ---- playbook hints -------------------------------------------------------------

def test_hints_apache_2449():
    intel = [{"kind": "service", "key": "80/tcp",
              "value": "http Apache httpd 2.4.49 ((Unix))"}]
    hints = hints_for(intel)
    assert any("CVE-2021-41773" in h for h in hints)
    assert any("web enum chain" in h for h in hints)


def test_hints_vsftpd():
    intel = [{"kind": "service", "key": "21/tcp", "value": "ftp vsftpd 2.3.4"}]
    hints = hints_for(intel)
    assert any("backdoor" in h.lower() for h in hints)
    assert any("anonymous" in h.lower() for h in hints)


# ---- guard grounding -------------------------------------------------------------

def test_nmap_script_validation(workspace, scope, monkeypatch, tmp_path):
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    (script_dir / "http-title.nse").write_text("-- fake")
    (script_dir / "http-enum.nse").write_text("-- fake")
    monkeypatch.setattr("aegis.guard.NMAP_SCRIPT_DIRS", (str(script_dir),))
    g = CommandGuard(scope, str(workspace))
    # valid scripts pass
    g.check_grounding("nmap", ["-sV", "--script=http-title,http-enum",
                               "10.10.10.5"])
    # categories pass
    g.check_grounding("nmap", ["--script=vuln", "10.10.10.5"])
    # hallucinated script refused with suggestion
    with pytest.raises(GuardError) as exc:
        g.check_grounding("nmap", ["--script=http-titel", "10.10.10.5"])
    assert "http-titel" in str(exc.value)
    assert "did you mean" in str(exc.value)


def test_bogus_path_refused(workspace, scope):
    g = CommandGuard(scope, str(workspace))
    with pytest.raises(GuardError) as exc:
        g.check_grounding("dirb", ["http://10.10.10.5/",
                                   "/path/to/custom/wordlist"])
    assert "does not exist" in str(exc.value)


def test_real_path_and_output_flag_ok(workspace, scope, tmp_path):
    g = CommandGuard(scope, str(workspace))
    real = tmp_path / "words.txt"
    real.write_text("admin\n")
    g.check_grounding("gobuster", ["dir", "-u", "http://10.10.10.5/",
                                   "-w", str(real)])
    # output-flag destinations need not exist
    g.check_grounding("nmap", ["-sV", "-oN", "reports/scan.txt", "10.10.10.5"])


# ---- runner integration: auto-capture -------------------------------------------

def _runner(workspace, scope, extra_tools=()):
    cfg = json.loads(Path(__file__).resolve().parent.parent
                     .joinpath("config.example.json").read_text())
    cfg["paths"] = {"output_dir": str(workspace / "out")}
    cfg["runner"]["allowed_tools"] = list(
        cfg["runner"]["allowed_tools"]) + list(extra_tools)
    r = Runner(cfg, EngagementDB(str(workspace / "eng.db")),
               AuditLog(str(workspace / "logs")), scope)
    r.guard = CommandGuard(scope, str(workspace))
    return r


def _install_tool(workspace, name, win_body, nix_body):
    bindir = workspace / "bin"
    bindir.mkdir(exist_ok=True)
    if sys.platform.startswith("win"):
        (bindir / f"{name}.bat").write_text(win_body)
    else:
        p = bindir / name
        p.write_text(nix_body)
        p.chmod(0o755)
    return bindir


def test_runner_autocaptures_flag_and_intel(workspace, scope):
    bindir = _install_tool(
        workspace, "nmap",
        "@echo off\r\necho 22/tcp   open  ssh     OpenSSH 7.6p1\r\n"
        "echo 80/tcp   open  http    Apache httpd 2.4.49\r\n"
        "echo user flag: THM{runner_c4ught_m3}\r\n",
        "#!/bin/sh\nprintf '22/tcp open ssh OpenSSH 7.6p1\\n"
        "80/tcp open http Apache httpd 2.4.49\\n"
        "user flag: THM{runner_c4ught_m3}\\n'\n")
    old_path = os.environ["PATH"]
    os.environ["PATH"] = str(bindir) + os.pathsep + old_path
    try:
        r = _runner(workspace, scope)
        res = r.run("nmap", ["-sV", "10.10.10.5"], target_host="10.10.10.5",
                    target_id=r.db.add_target("10.10.10.5"))
        assert res.status == "ok"
        loot = r.db.loot_for()
        assert any(l["kind"] == "flag" and "THM{runner_c4ught_m3}" in l["value"]
                   for l in loot)
        intel = r.db.intel_for(r.db.get_target("10.10.10.5")["id"])
        assert any(i["kind"] == "service" and "Apache" in i["value"]
                   for i in intel)
    finally:
        os.environ["PATH"] = old_path


def test_guard_refusal_recorded_with_reason(workspace, scope):
    r = _runner(workspace, scope)
    res = r.run("dirb", ["http://10.10.10.5/", "/path/to/custom/wordlist"],
                target_host="10.10.10.5",
                target_id=r.db.add_target("10.10.10.5"))
    assert res.status == "refused" and res.refusal == "guard"
    row = r.db.conn.execute("SELECT * FROM actions WHERE id = ?",
                            (res.action_id,)).fetchone()
    assert row["status"] == "refused"
    assert "does not exist" in row["error"]


# ---- command-center endpoints -----------------------------------------------------

def test_target_detail_and_action_log(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5", "THM easy box")
    db.record_intel(tid, "web", "server", "Apache/2.4.49 (Unix)")
    db.record_finding(tid, "Directory listing", severity="low")
    aid = db.record_action(tid, "scan-agent", "curl", "curl -sI x", 0, 0.2,
                           None, "ok")
    outdir = workspace / "out"
    outdir.mkdir()
    logf = outdir / f"action-{aid}.log"
    logf.write_text("$ curl -sI x\n\nServer: Apache/2.4.49\n")
    db._execute("UPDATE actions SET output_file = ? WHERE id = ?",
                (str(logf), aid))

    server = DashboardServer(db, port=8889)
    server.start()
    try:
        d = requests.get(
            f"http://127.0.0.1:8889/api/target?id={tid}&token={server.token}",
            timeout=5).json()
        assert d["target"]["host"] == "10.10.10.5"
        assert d["intel"][0]["value"] == "Apache/2.4.49 (Unix)"
        assert d["findings"][0]["title"] == "Directory listing"
        assert d["actions"][0]["id"] == aid
        # log viewer
        log = requests.get(
            f"http://127.0.0.1:8889/api/action/log?id={aid}"
            f"&token={server.token}", timeout=5).text
        assert "Apache/2.4.49" in log
        # bad ids -> JSON error, not a dropped connection
        bad = requests.get(
            f"http://127.0.0.1:8889/api/target?id=abc&token={server.token}",
            timeout=5).json()
        assert "error" in bad
        # no token -> 403
        r = requests.get(f"http://127.0.0.1:8889/api/target?id={tid}",
                         timeout=5)
        assert r.status_code == 403
    finally:
        server.stop()


# ---- agent adapts to guard refusals instead of dying ------------------------------

def test_agent_continues_after_guard_refusal(workspace, scope):
    """A planner that proposes a hallucinated path gets refused, sees the
    reason in memory, and must get another turn — not a dead loop."""
    from aegis.agent import Agent
    from aegis.llm import LLMClient

    class RefuseThenDone(LLMClient):
        def __init__(self):
            self.calls = 0

        def chat(self, messages, *, json_mode=False):
            self.calls += 1
            if self.calls == 1:
                return json.dumps({
                    "thought": "fuzz dirs", "done": False,
                    "command": {"tool": "dirb",
                                "args": ["http://10.10.10.5/",
                                         "/path/to/custom/wordlist"]},
                    "technique": "dir-fuzz", "vector": "http/80"})
            # second planning call: memory must show the refusal reason
            user = messages[-1]["content"]
            assert "refused" in user and "does not exist" in user
            return json.dumps({"thought": "no valid wordlist", "done": True,
                               "summary": "stopped after refusal feedback"})

        def available(self):
            return True

    db = EngagementDB("eng.db")
    r = _runner(workspace, scope)
    agent = Agent(RefuseThenDone(), r, db, max_steps=5)
    res = agent.run("attack", "10.10.10.5")
    phases = [e.get("phase") for e in res["transcript"]]
    assert "refused" in phases
    assert res["transcript"][-1].get("done") is True
