"""v1.0 tests: the learning loop — successful attacks draft KB rules."""

import json
import os
import sys
from pathlib import Path

import pytest
import requests

from aegis.audit import AuditLog
from aegis.dashboard import DashboardServer
from aegis.db import EngagementDB
from aegis.guard import CommandGuard
from aegis.playbook import (dismiss_draft, hints_for, learn_from_success,
                            list_custom_rules, promote_draft)
from aegis.runner import Runner


def svc(port, value):
    return {"kind": "service", "key": port, "value": value}


def _seed_db(workspace, services=()):
    db = EngagementDB(str(workspace / "eng.db"))
    tid = db.add_target("10.10.10.5")
    for s in services:
        db.record_intel(tid, "service", s["key"], s["value"])
    return db, tid


# ---- draft generation ---------------------------------------------------------

def test_learn_drafts_version_rule(workspace):
    db, tid = _seed_db(workspace, [svc("10000/tcp", "http MiniServ 1.990")])
    draft = learn_from_success(db, tid, "rce", "tcp/10000 http", "curl",
                               "curl http://10.10.10.5:10000/pwchange",
                               "10.10.10.5", workspace=workspace)
    assert draft is not None
    assert draft["group"] == "version_hints"
    assert draft["pattern"] == r"miniserv.*1\.990"
    assert "TARGET" in draft["hint"] and "10.10.10.5" not in draft["hint"]
    # persisted as a draft, NOT live
    data = list_custom_rules(workspace)
    assert len(data["drafts"]) == 1
    assert not data["version_hints"]
    assert not any("MiniServ" in h
                   for h in hints_for([], workspace=workspace))


def test_no_draft_when_version_rule_already_covers(workspace):
    db, tid = _seed_db(workspace, [svc("80/tcp", "http Apache httpd 2.4.49")])
    draft = learn_from_success(db, tid, "path-traversal", "tcp/80 http",
                               "curl", "curl --path-as-is http://10.10.10.5/...",
                               "10.10.10.5", workspace=workspace)
    assert draft is None  # CVE-2021-41773 already in the bundled KB


def test_no_draft_without_service_context(workspace):
    db, tid = _seed_db(workspace)  # no intel at all
    assert learn_from_success(db, tid, "x", "tcp/80", "curl",
                              "curl http://10.10.10.5/", "10.10.10.5",
                              workspace=workspace) is None


def test_draft_dedupe(workspace):
    db, tid = _seed_db(workspace, [svc("10000/tcp", "http MiniServ 1.990")])
    for _ in range(3):
        learn_from_success(db, tid, "rce", "tcp/10000", "curl",
                           "curl http://10.10.10.5:10000/x", "10.10.10.5",
                           workspace=workspace)
    assert len(list_custom_rules(workspace)["drafts"]) == 1


def test_service_level_draft_when_no_version(workspace):
    db, tid = _seed_db(workspace, [svc("873/tcp", "rsync (protocol 31)")])
    draft = learn_from_success(db, tid, "anon-rsync", "tcp/873", "nc",
                               "nc 10.10.10.5 873", "10.10.10.5",
                               workspace=workspace)
    assert draft is not None and draft["group"] == "service_hints"
    assert draft["pattern"] == "^rsync"


# ---- promote / dismiss ----------------------------------------------------------

def _make_draft(workspace):
    db, tid = _seed_db(workspace, [svc("10000/tcp", "http MiniServ 1.990")])
    learn_from_success(db, tid, "rce", "tcp/10000", "curl",
                       "curl http://10.10.10.5:10000/x", "10.10.10.5",
                       workspace=workspace)


def test_promote_makes_live(workspace):
    _make_draft(workspace)
    d = promote_draft(workspace, 0)
    assert d["group"] == "version_hints"
    data = list_custom_rules(workspace)
    assert data["drafts"] == []
    assert data["version_hints"] and data["version_hints"][0][0] == d["pattern"]
    # and now it actually fires
    hints = hints_for([svc("10000/tcp", "http MiniServ 1.990")],
                      workspace=workspace)
    assert any("learned from a successful engagement" in h for h in hints)


def test_dismiss_removes(workspace):
    _make_draft(workspace)
    dismiss_draft(workspace, 0)
    assert list_custom_rules(workspace)["drafts"] == []
    hints = hints_for([svc("10000/tcp", "http MiniServ 1.990")],
                      workspace=workspace)
    assert not any("learned from a successful" in h for h in hints)


def test_promote_bad_index(workspace):
    with pytest.raises(ValueError):
        promote_draft(workspace, 7)


# ---- full agent loop integration --------------------------------------------------

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


HYDRA_WIN = ("@echo off\r\necho [22][ssh] host: 10.10.10.5   login: admin   "
             "password: s3cret123\r\n")
HYDRA_NIX = ("#!/bin/sh\necho '[22][ssh] host: 10.10.10.5   login: admin   "
             "password: s3cret123'\n")


class _HydraThenDone:
    """Scripted LLM: one hydra attack, then stop."""

    def __init__(self):
        self.plans = 0

    def chat(self, messages, *, json_mode=False):
        self.plans += 1
        if self.plans == 1:
            return json.dumps({
                "thought": "password spray ssh", "done": False,
                "command": {"tool": "hydra",
                            "args": ["-l", "admin", "-P", "pw.txt",
                                     "ssh://10.10.10.5"]},
                "technique": "password-spray", "vector": "tcp/22 ssh"})
        return json.dumps({"thought": "creds found", "done": True,
                           "summary": "ssh password sprayed"})

    def available(self):
        return True


def test_agent_learns_from_attack_success(workspace, scope):
    from aegis.agent import Agent
    bindir = _install_tool(workspace, "hydra", HYDRA_WIN, HYDRA_NIX)
    old_path = os.environ["PATH"]
    os.environ["PATH"] = str(bindir) + os.pathsep + old_path
    try:
        r = _runner(workspace, scope, extra_tools=["hydra"])
        tid = r.db.add_target("10.10.10.5")
        r.db.record_intel(tid, "service", "22/tcp", "ssh OpenSSH 8.9p1 Ubuntu")
        agent = Agent(_HydraThenDone(), r, r.db, max_steps=4)
        res = agent.run("attack", "10.10.10.5")
        # attack succeeded (parser-proven)
        assert any(e.get("success") for e in res["transcript"])
        # a draft rule was learned and audited
        drafts = list_custom_rules(workspace)["drafts"]
        assert len(drafts) == 1
        assert drafts[0]["pattern"] == r"openssh.*8\.9"
        assert drafts[0]["group"] == "version_hints"
        entries = [json.loads(ln)
                   for f in (workspace / "logs").glob("audit-*.jsonl")
                   for ln in f.read_text().splitlines() if ln.strip()]
        assert any(e["category"] == "playbook"
                   and e["action"] == "draft_rule" for e in entries)
    finally:
        os.environ["PATH"] = old_path


def test_scan_success_does_not_draft(workspace, scope):
    """Successful scans teach nothing — only attacks draft rules."""
    from aegis.agent import Agent
    bindir = _install_tool(workspace, "hydra", HYDRA_WIN, HYDRA_NIX)
    old_path = os.environ["PATH"]
    os.environ["PATH"] = str(bindir) + os.pathsep + old_path
    try:
        r = _runner(workspace, scope, extra_tools=["hydra"])
        tid = r.db.add_target("10.10.10.5")
        r.db.record_intel(tid, "service", "22/tcp", "ssh OpenSSH 8.9p1 Ubuntu")
        agent = Agent(_HydraThenDone(), r, r.db, max_steps=4)
        agent.run("scan", "10.10.10.5")  # same success, wrong mode
        assert list_custom_rules(workspace)["drafts"] == []
    finally:
        os.environ["PATH"] = old_path


# ---- War Room review endpoints -----------------------------------------------------

def test_promote_dismiss_endpoints(workspace):
    _make_draft(workspace)
    db = EngagementDB(str(workspace / "dash.db"))
    audit = AuditLog(str(workspace / "logs"))
    server = DashboardServer(db, port=8886)
    server.workspace = str(workspace)
    server.audit = audit
    server.start()
    try:
        r = requests.post(
            f"http://127.0.0.1:8886/api/playbook/promote?token={server.token}",
            json={"index": 0}, timeout=5)
        assert r.json()["ok"] is True
        assert list_custom_rules(workspace)["version_hints"]
        # dismissing with nothing left -> 400
        r = requests.post(
            f"http://127.0.0.1:8886/api/playbook/dismiss?token={server.token}",
            json={"index": 0}, timeout=5)
        assert r.status_code == 400
        # state exposes drafts list
        st = requests.get(
            f"http://127.0.0.1:8886/api/playbook?token={server.token}",
            timeout=5).json()
        assert "drafts" in st["custom"]
        # audited
        entries = [json.loads(ln)
                   for f in (workspace / "logs").glob("audit-*.jsonl")
                   for ln in f.read_text().splitlines() if ln.strip()]
        assert any(e["action"] == "promote_rule" for e in entries)
    finally:
        server.stop()
