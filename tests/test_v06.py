"""v0.6 tests: error visibility in Recent Activity, persistent loot reveal."""

import json
import os
import sys
import time
from pathlib import Path

import pytest
import requests

from aegis.db import EngagementDB
from aegis.dashboard import DashboardServer
from aegis.runner import Runner
from aegis.audit import AuditLog
from aegis.guard import CommandGuard


def _runner(workspace, scope, extra_tools=()):
    cfg = json.loads(Path(__file__).resolve().parent.parent
                     .joinpath("config.example.json").read_text())
    cfg["paths"] = {"output_dir": str(workspace / "out")}
    cfg["runner"]["default_timeout"] = 60
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


# ---- error summaries on failed actions -------------------------------------

def test_error_summary_from_stderr(workspace, scope):
    bindir = _install_tool(
        workspace, "failtool",
        "@echo off\r\necho NSE: failed to match script 'http-vuln-cve-nist' 1>&2\r\nexit /b 1\r\n",
        "#!/bin/sh\necho \"NSE: failed to match script 'http-vuln-cve-nist'\" >&2\nexit 1\n")
    old_path = os.environ["PATH"]
    os.environ["PATH"] = str(bindir) + os.pathsep + old_path
    try:
        r = _runner(workspace, scope, extra_tools=["failtool"])
        res = r.run("failtool", ["10.10.10.5"], target_host="10.10.10.5")
        assert res.status == "error"
        row = r.db.conn.execute("SELECT * FROM actions WHERE id = ?",
                                (res.action_id,)).fetchone()
        assert "http-vuln-cve-nist" in row["error"]
    finally:
        os.environ["PATH"] = old_path


def test_error_summary_no_output(workspace, scope):
    bindir = _install_tool(workspace, "dietool",
                           "@echo off\r\nexit /b 3\r\n",
                           "#!/bin/sh\nexit 3\n")
    old_path = os.environ["PATH"]
    os.environ["PATH"] = str(bindir) + os.pathsep + old_path
    try:
        r = _runner(workspace, scope, extra_tools=["dietool"])
        res = r.run("dietool", ["10.10.10.5"], target_host="10.10.10.5")
        row = r.db.conn.execute("SELECT * FROM actions WHERE id = ?",
                                (res.action_id,)).fetchone()
        assert row["error"] == "exit code 3 with no output"
    finally:
        os.environ["PATH"] = old_path


def test_cancelled_action_records_reason(workspace, scope):
    import threading
    bindir = _install_tool(workspace, "ping",
                           "@echo off\r\nping -n 30 127.0.0.1 >nul\r\n",
                           "#!/bin/sh\nsleep 30\n")
    old_path = os.environ["PATH"]
    os.environ["PATH"] = str(bindir) + os.pathsep + old_path
    try:
        r = _runner(workspace, scope)
        cancel = threading.Event()
        box = {}

        def go():
            box["res"] = r.run("ping", ["10.10.10.5"], target_host="10.10.10.5",
                               cancel_event=cancel)
        t = threading.Thread(target=go)
        t.start()
        time.sleep(1.5)
        cancel.set()
        t.join(timeout=10)
        assert not t.is_alive()
        row = r.db.conn.execute("SELECT * FROM actions WHERE id = ?",
                                (box["res"].action_id,)).fetchone()
        assert row["status"] == "cancelled"
        assert "cancelled" in row["error"]
    finally:
        os.environ["PATH"] = old_path


def test_ok_action_has_no_error(workspace, scope):
    bindir = _install_tool(workspace, "ping",
                           "@echo off\r\necho pong\r\n",
                           "#!/bin/sh\necho pong\n")
    old_path = os.environ["PATH"]
    os.environ["PATH"] = str(bindir) + os.pathsep + old_path
    try:
        r = _runner(workspace, scope)
        res = r.run("ping", ["10.10.10.5"], target_host="10.10.10.5")
        row = r.db.conn.execute("SELECT * FROM actions WHERE id = ?",
                                (res.action_id,)).fetchone()
        assert row["status"] == "ok"
        assert row["error"] == ""
    finally:
        os.environ["PATH"] = old_path


# ---- agent memory learns the reason ----------------------------------------

def test_memory_summary_shows_error_reason(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    db.record_action(tid, "scan-agent", "nmap", "nmap --script=bogus", 1, 1.0,
                     None, "error", error="NSE: bogus script not found")
    db.record_action(tid, "scan-agent", "nmap", "nmap -Pn", 0, 1.0, None, "ok")
    mem = db.memory_summary(tid)
    assert "reason: NSE: bogus script not found" in mem
    # ok rows stay compact — no dangling reason
    ok_line = [ln for ln in mem.splitlines() if "nmap -Pn" in ln][0]
    assert "reason" not in ok_line


# ---- dashboard state + reveal hardening ------------------------------------

def test_state_actions_include_error(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    db.record_action(tid, "attack-agent", "dirb", "dirb -g x", 1, 0.5, None,
                     "error", error="dirb: invalid option -- g")
    server = DashboardServer(db, port=8893)
    server.start()
    try:
        st = requests.get(
            f"http://127.0.0.1:8893/api/state?token={server.token}",
            timeout=5).json()
        act = st["actions"][0]
        assert act["status"] == "error"
        assert "invalid option" in act["error"]
    finally:
        server.stop()


def test_loot_reveal_bad_id_returns_json_error(workspace):
    """Malformed ids must get a JSON error, not a dropped connection."""
    db = EngagementDB("eng.db")
    server = DashboardServer(db, port=8892)
    server.start()
    try:
        r = requests.get(
            f"http://127.0.0.1:8892/api/loot?id=undefined&reveal=1"
            f"&token={server.token}", timeout=5)
        assert r.status_code == 200
        assert "error" in r.json()
        # missing id entirely
        r = requests.get(
            f"http://127.0.0.1:8892/api/loot?token={server.token}", timeout=5)
        assert "error" in r.json()  # id 0 -> not found
    finally:
        server.stop()


def test_loot_reveal_note_kind(workspace):
    """Regression: notes (unencrypted) must reveal just like credentials."""
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    lid = db.record_loot(tid, "note", "user flag", value="THM{fl4g}")
    server = DashboardServer(db, port=8891)
    server.start()
    try:
        j = requests.get(
            f"http://127.0.0.1:8891/api/loot?id={lid}&reveal=1"
            f"&token={server.token}", timeout=5).json()
        assert j["value"] == "THM{fl4g}"
    finally:
        server.stop()


def test_loot_reveal_audited(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    lid = db.record_loot(tid, "credential", "ssh", value="root:toor")
    audit = AuditLog(str(workspace / "logs"))
    server = DashboardServer(db, port=8890)
    server.audit = audit
    server.start()
    try:
        requests.get(
            f"http://127.0.0.1:8890/api/loot?id={lid}&reveal=1"
            f"&token={server.token}", timeout=5)
        entries = [json.loads(ln)
                   for f in (workspace / "logs").glob("audit-*.jsonl")
                   for ln in f.read_text().splitlines() if ln.strip()]
        views = [e for e in entries
                 if e.get("category") == "loot" and e.get("action") == "view"]
        assert views and views[0]["detail"]["id"] == lid
        assert views[0]["actor"] == "war-room"
    finally:
        server.stop()
