import json

import pytest

from aegis.audit import AuditLog
from aegis.db import EngagementDB
from aegis.guard import CommandGuard
from aegis.opsec import OpsecProfile
from aegis.runner import Runner, sanitize_output


def _runner(scope, workspace, opsec_level="normal"):
    cfg = json.loads(
        open(__file__.rsplit("tests", 1)[0] + "config.example.json",
             encoding="utf-8").read())
    cfg["paths"] = {"output_dir": str(workspace / "out")}
    db = EngagementDB(str(workspace / "eng.db"))
    audit = AuditLog(str(workspace / "logs"))
    r = Runner(cfg, db, audit, scope)
    r.guard = CommandGuard(scope, str(workspace))
    r.opsec = OpsecProfile(opsec_level)
    return r


def test_allowlist_enforced(scope, workspace):
    r = _runner(scope, workspace)
    with pytest.raises(Exception, match="allowed_tools"):
        r.run("rm", ["-rf", "/"], target_host="10.10.10.5")


def test_guard_refuses_out_of_scope_args(scope, workspace):
    r = _runner(scope, workspace)
    res = r.run("nmap", ["-sV", "10.10.10.5", "8.8.8.8"],
                target_host="10.10.10.5")
    assert res.status == "refused"


def test_opsec_stealth_requires_proxy(scope, workspace):
    r = _runner(scope, workspace, opsec_level="stealth")
    r.use_proxychains = False  # nothing to wrap with
    with pytest.raises(Exception, match="proxychains"):
        r.run("ping", ["-c1", "10.10.10.5"], target_host="10.10.10.5")


def test_ansi_sanitization():
    hostile = "\x1b[31mred\x1b[0m \x07bell \x1b]0;evil title\x07"
    clean = sanitize_output(hostile)
    assert "\x1b" not in clean and "\x07" not in clean
    assert "red" in clean
