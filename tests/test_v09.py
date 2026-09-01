"""v0.9 tests: data-driven playbook KB (JSON overlay, hot reload, War Room)."""

import json
import time

import pytest
import requests

from aegis.dashboard import DashboardServer
from aegis.db import EngagementDB
from aegis.playbook import (add_custom_rule, available_wordlists, hints_for,
                            list_custom_rules, load_kb)
from aegis.audit import AuditLog


def svc(port, value):
    return {"kind": "service", "key": port, "value": value}


# ---- loading & defaults --------------------------------------------------------

def test_load_kb_defaults(workspace):
    kb = load_kb(workspace)  # no custom file yet
    assert len(kb["version_hints"]) == 20
    assert len(kb["service_hints"]) == 21
    assert len(kb["port_hints"]) == 13
    assert set(kb["wordlists"]) == {"web-dirs", "passwords", "usernames",
                                    "subdomains"}


def test_defaults_preserve_behavior(workspace):
    """The JSON migration must reproduce the v0.8 hardcoded behavior."""
    hints = hints_for([svc("80/tcp", "http Apache httpd 2.4.49 ((Unix))")],
                      workspace=workspace)
    assert any("CVE-2021-41773" in h for h in hints)
    assert any("enum chain" in h for h in hints)


# ---- custom rules ---------------------------------------------------------------

def test_custom_rule_fires_first(workspace):
    add_custom_rule(workspace, "version_hints", r"acme-app 1\.",
                    "AcmeApp 1.x → our client's app has unauth /debug endpoint "
                    "on TARGET — curl http://TARGET/debug")
    hints = hints_for([svc("80/tcp", "http Acme-App 1.2")], workspace=workspace)
    assert hints[0].startswith("AcmeApp 1.x")


def test_custom_port_hint(workspace):
    add_custom_rule(workspace, "port_hints", "9999",
                    "Custom service (9999) → check TARGET with nc")
    hints = hints_for([svc("9999/tcp", "unknown")], workspace=workspace)
    assert any("Custom service (9999)" in h for h in hints)


def test_custom_wordlist_override(workspace, tmp_path):
    wl = tmp_path / "my-words.txt"
    wl.write_text("admin\n")
    add_wordlist = {"wordlists": {"web-dirs": [str(wl)]}}
    (workspace / "playbook.custom.json").write_text(json.dumps(add_wordlist))
    assert available_wordlists(workspace)["web-dirs"] == str(wl)


def test_add_rule_validation(workspace):
    with pytest.raises(ValueError):
        add_custom_rule(workspace, "bogus_group", "x", "y")
    with pytest.raises(ValueError):
        add_custom_rule(workspace, "version_hints", "(unclosed", "hint")
    with pytest.raises(ValueError):
        add_custom_rule(workspace, "port_hints", "not-a-port", "hint")
    with pytest.raises(ValueError):
        add_custom_rule(workspace, "service_hints", "", "hint")
    with pytest.raises(ValueError):
        add_custom_rule(workspace, "service_hints", "x", "")


def test_duplicate_rule_noop(workspace):
    add_custom_rule(workspace, "service_hints", "zimbra", "Zimbra hint TARGET")
    add_custom_rule(workspace, "service_hints", "zimbra", "Zimbra hint TARGET")
    rules = list_custom_rules(workspace)["service_hints"]
    assert len(rules) == 1


def test_hot_reload(workspace):
    intel = [svc("11211/tcp", "unknown")]
    assert not any("HOTRELOAD" in h for h in hints_for(intel,
                                                       workspace=workspace))
    add_custom_rule(workspace, "port_hints", "11211",
                    "HOTRELOAD marker hint for TARGET")
    assert any("HOTRELOAD" in h for h in hints_for(intel, workspace=workspace))


def test_corrupt_custom_file_ignored(workspace):
    (workspace / "playbook.custom.json").write_text("{not json!!")
    kb = load_kb(workspace)  # must not raise
    assert len(kb["version_hints"]) == 20


# ---- War Room endpoints -----------------------------------------------------------

def test_playbook_endpoints(workspace):
    db = EngagementDB("eng.db")
    audit = AuditLog(str(workspace / "logs"))
    server = DashboardServer(db, port=8888)
    server.workspace = str(workspace)
    server.audit = audit
    server.start()
    try:
        st = requests.get(
            f"http://127.0.0.1:8888/api/playbook?token={server.token}",
            timeout=5).json()
        assert st["bundled"]["version_hints"] == 20
        # add a valid rule
        r = requests.post(
            f"http://127.0.0.1:8888/api/playbook/add?token={server.token}",
            json={"group": "service_hints", "pattern": "zimbra",
                  "hint": "Zimbra → check /service/soap on TARGET"},
            timeout=5)
        assert r.json()["added"] is True
        rules = list_custom_rules(workspace)["service_hints"]
        assert rules and rules[0][0] == "zimbra"
        # invalid regex -> 400 with message
        r = requests.post(
            f"http://127.0.0.1:8888/api/playbook/add?token={server.token}",
            json={"group": "version_hints", "pattern": "(bad",
                  "hint": "x TARGET"}, timeout=5)
        assert r.status_code == 400 and "regex" in r.json()["error"]
        # audited
        entries = [json.loads(ln)
                   for f in (workspace / "logs").glob("audit-*.jsonl")
                   for ln in f.read_text().splitlines() if ln.strip()]
        assert any(e["category"] == "playbook" and e["action"] == "add_rule"
                   and e["actor"] == "war-room" for e in entries)
    finally:
        server.stop()


def test_target_detail_includes_hints(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    db.record_intel(tid, "service", "80/tcp", "http Apache httpd 2.4.49")
    server = DashboardServer(db, port=8887)
    server.workspace = str(workspace)
    server.start()
    try:
        d = requests.get(
            f"http://127.0.0.1:8887/api/target?id={tid}&token={server.token}",
            timeout=5).json()
        assert any("CVE-2021-41773" in h for h in d["hints"])
        # TARGET placeholder resolved to the real host
        assert all("TARGET" not in h for h in d["hints"])
        assert any("10.10.10.5" in h for h in d["hints"])
    finally:
        server.stop()
