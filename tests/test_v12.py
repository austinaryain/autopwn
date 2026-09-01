"""v1.2 tests: one-click playbook recommendations."""

import json
import time

import requests

from aegis.dashboard import DashboardServer
from aegis.db import EngagementDB
from aegis.playbook import extract_commands, hints_for

ALLOWED = {"nmap", "curl", "nikto", "gobuster", "hydra", "nc", "whatweb",
           "nuclei", "searchsploit", "smbclient", "enum4linux-ng", "wpscan",
           "medusa", "sqlmap", "ffuf", "amass", "sublist3r", "ldapsearch"}


def svc(port, value):
    return {"kind": "service", "key": port, "value": value}


# ---- command extraction ---------------------------------------------------------

def test_extract_web_chain_commands():
    intel = [svc("80/tcp", "http nginx 1.24.0")]
    hints = hints_for(intel, target="10.10.10.5")
    chain = [h for h in hints if "enum chain" in h][0].replace(
        "TARGET", "10.10.10.5")
    cmds = extract_commands(chain, ALLOWED)
    assert any(c.startswith("whatweb http://10.10.10.5") for c in cmds)
    assert any(c.startswith("curl -sI http://10.10.10.5") for c in cmds)
    assert any(c.startswith("nikto -h http://10.10.10.5") for c in cmds)
    assert any(c.startswith("nuclei -u http://10.10.10.5") for c in cmds)
    # "check /robots.txt ..." is prose, not a command
    assert not any(c.startswith("check") for c in cmds)


def test_extract_quoted_curl_intact():
    hint = ("Apache 2.4.49 → CVE-2021-41773 path traversal/RCE: "
            "curl --path-as-is "
            "'http://10.10.10.5/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'")
    cmds = extract_commands(hint, ALLOWED)
    assert cmds == ["curl --path-as-is "
                    "'http://10.10.10.5/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'"]


def test_placeholder_commands_skipped():
    hint = ("SSH → password attack only with a real user list: "
            "hydra -L users.txt -P WORDLIST ssh://10.10.10.5")
    assert extract_commands(hint, ALLOWED) == []


def test_extract_multiple_same_tool():
    hint = ('Version research: searchsploit "OpenSSH 7.6" / searchsploit '
            '"httpd 2.4.38" (or run /privesc 10.10.10.5 which does this)')
    cmds = extract_commands(hint, ALLOWED)
    assert cmds == ['searchsploit "OpenSSH 7.6"', 'searchsploit "httpd 2.4.38"']


def test_extract_embedded_nc():
    hint = ("IRC → connect with nc 10.10.10.5 6667; check version "
            "(UnrealIRCd backdoor)")
    assert extract_commands(hint, ALLOWED) == ["nc 10.10.10.5 6667"]


def test_extract_empty_tools():
    assert extract_commands("curl http://x", []) == []


# ---- endpoint: hint_commands + /api/run ------------------------------------------

def test_target_detail_hint_commands(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    db.record_intel(tid, "service", "80/tcp", "http Apache httpd 2.4.49")
    server = DashboardServer(db, port=8885)
    server.workspace = str(workspace)
    server.allowed_tools = sorted(ALLOWED)
    server.start()
    try:
        d = requests.get(
            f"http://127.0.0.1:8885/api/target?id={tid}&token={server.token}",
            timeout=5).json()
        assert len(d["hints"]) == len(d["hint_commands"])
        flat = [c for cmds in d["hint_commands"] for c in cmds]
        assert any(c.startswith("curl --path-as-is") for c in flat)
        # every extracted command starts with an allowlisted tool
        assert all(c.split()[0] in ALLOWED for c in flat)
        # target-host commands carry the resolved host
        targeted = [c for c in flat if c.split()[0] != "searchsploit"]
        assert targeted and all("10.10.10.5" in c for c in targeted)
    finally:
        server.stop()


def test_run_endpoint(workspace):
    db = EngagementDB("eng.db")
    server = DashboardServer(db, port=8884)
    fired = []
    server.run_handler = lambda host, command: fired.append((host, command))
    server.start()
    try:
        r = requests.post(
            f"http://127.0.0.1:8884/api/run?token={server.token}",
            json={"host": "10.10.10.5",
                  "command": "curl -sI http://10.10.10.5"}, timeout=5)
        assert r.json()["started"] is True
        assert fired == [("10.10.10.5", "curl -sI http://10.10.10.5")]
        # no token -> 403
        r = requests.post("http://127.0.0.1:8884/api/run",
                          json={"host": "x", "command": "y"}, timeout=5)
        assert r.status_code == 403
    finally:
        server.stop()


def test_run_endpoint_without_handler(workspace):
    db = EngagementDB("eng.db")
    server = DashboardServer(db, port=8883)
    server.start()
    try:
        r = requests.post(
            f"http://127.0.0.1:8883/api/run?token={server.token}",
            json={"host": "10.10.10.5", "command": "curl x"}, timeout=5)
        assert r.status_code == 400
    finally:
        server.stop()
