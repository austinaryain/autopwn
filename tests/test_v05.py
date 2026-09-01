"""v0.5 tests: dashboard scope-add, kill switch, loot viewing."""

import json
import threading
import time
from pathlib import Path

import pytest
import requests

from aegis.db import EngagementDB
from aegis.dashboard import DashboardServer
from aegis.runner import Runner
from aegis.audit import AuditLog
from aegis.guard import CommandGuard


# ---- #1 scope add -------------------------------------------------------------

def test_scope_add_to_file(scope, workspace):
    assert not scope.is_in_scope("10.99.99.5")
    scope.add_to_scope("10.99.99.5")
    assert scope.is_in_scope("10.99.99.5")
    # persisted to the authorization document
    data = json.loads((workspace / "authorization.json").read_text())
    assert "10.99.99.5" in data["scope"]


def test_scope_add_idempotent(scope, workspace):
    scope.add_to_scope("10.99.99.0/24")
    scope.add_to_scope("10.99.99.0/24")
    data = json.loads((workspace / "authorization.json").read_text())
    assert data["scope"].count("10.99.99.0/24") == 1


# ---- #2 kill switch -------------------------------------------------------------

def _runner(workspace, scope):
    cfg = json.loads(Path(__file__).resolve().parent.parent
                     .joinpath("config.example.json").read_text())
    cfg["paths"] = {"output_dir": str(workspace / "out")}
    cfg["runner"]["default_timeout"] = 60
    r = Runner(cfg, EngagementDB(str(workspace / "eng.db")),
               AuditLog(str(workspace / "logs")), scope)
    r.guard = CommandGuard(scope, str(workspace))
    return r


def test_cancel_running_process(workspace, scope):
    """A sleeping process must die promptly when the cancel event fires."""
    bindir = workspace / "bin"
    bindir.mkdir()
    import sys
    if sys.platform.startswith("win"):
        (bindir / "ping.bat").write_text(
            "@echo off\r\nping -n 30 127.0.0.1 >nul\r\n")
    else:
        p = bindir / "ping"
        p.write_text("#!/bin/sh\nsleep 30\n")
        p.chmod(0o755)
    import os
    old_path = os.environ["PATH"]
    os.environ["PATH"] = str(bindir) + os.pathsep + old_path
    try:
        r = _runner(workspace, scope)
        cancel = threading.Event()
        result_box = {}

        def go():
            result_box["res"] = r.run("ping", ["10.10.10.5"],
                                      target_host="10.10.10.5",
                                      cancel_event=cancel)
        t = threading.Thread(target=go)
        t.start()
        time.sleep(1.5)
        cancel.set()
        t.join(timeout=10)
        assert not t.is_alive(), "process was not killed"
        assert result_box["res"].status == "cancelled"
    finally:
        os.environ["PATH"] = old_path


def test_cancel_all(workspace, scope):
    r = _runner(workspace, scope)
    assert r.cancel_all() == 0  # nothing running


def test_agent_cancel_event(workspace, scope):
    """Agent stops cleanly when the cancel event is set before it starts."""
    from aegis.agent import Agent
    from aegis.llm import LLMClient
    db = EngagementDB("eng.db")
    r = _runner(workspace, scope)

    class NeverLLM(LLMClient):
        def __init__(self): pass
        def chat(self, m, *, json_mode=False): return "{}"
        def available(self): return True

    agent = Agent(NeverLLM(), r, db)
    cancel = threading.Event()
    cancel.set()  # operator hit stop before first step
    res = agent.run("scan", "10.10.10.5", cancel_event=cancel)
    assert any("cancelled" in (e.get("summary") or "")
               for e in res["transcript"])


# ---- #3 dashboard stop + loot reveal ---------------------------------------------

def test_mission_stop_endpoint(workspace):
    db = EngagementDB("eng.db")
    server = DashboardServer(db, port=8896)
    started = threading.Event()

    def handler(host, mode, cancel):
        started.set()
        cancel.wait(10)  # simulate long mission

    server.mission_handler = handler
    server.start()
    try:
        r = requests.post(
            f"http://127.0.0.1:8896/api/mission/start?token={server.token}",
            json={"host": "10.10.10.5", "mode": "scan"}, timeout=5)
        mid = r.json()["mission_id"]
        assert started.wait(5)
        r = requests.post(
            f"http://127.0.0.1:8896/api/mission/stop?token={server.token}",
            json={"id": mid}, timeout=5)
        assert r.json()["stopped"] is True
        time.sleep(0.5)
        state = requests.get(
            f"http://127.0.0.1:8896/api/state?token={server.token}",
            timeout=5).json()
        assert "stop" in state["missions"][str(mid)]["status"]
    finally:
        server.stop()


def test_loot_reveal_endpoint(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    lid = db.record_loot(tid, "credential", "ssh admin", "admin:S3cur3!")
    server = DashboardServer(db, port=8895)
    server.start()
    try:
        masked = requests.get(
            f"http://127.0.0.1:8895/api/loot?id={lid}&token={server.token}",
            timeout=5).json()
        assert "S3cur3" not in masked["value"]
        revealed = requests.get(
            f"http://127.0.0.1:8895/api/loot?id={lid}&reveal=1&token={server.token}",
            timeout=5).json()
        assert revealed["value"] == "admin:S3cur3!"
        # unauthenticated reveal must fail
        r = requests.get(f"http://127.0.0.1:8895/api/loot?id={lid}&reveal=1",
                         timeout=5)
        assert r.status_code == 403
    finally:
        server.stop()


def test_scope_add_endpoint(workspace):
    db = EngagementDB("eng.db")
    server = DashboardServer(db, port=8894)
    added = []
    server.scope_handler = lambda host, network: added.append((host, network))
    server.start()
    try:
        r = requests.post(
            f"http://127.0.0.1:8894/api/scope/add?token={server.token}",
            json={"host": "10.10.10.9", "network": "THM-room-42"}, timeout=5)
        assert r.json()["added"] is True
        assert added == [("10.10.10.9", "THM-room-42")]
    finally:
        server.stop()
