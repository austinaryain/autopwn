"""Full-loop regression: simulation-mode lab validation must always pass."""

import pytest

from aegis.guard import CommandGuard, GuardError
from validation.run_lab_validation import run_simulation


def test_full_loop_simulation():
    cl = run_simulation(verbose=False)
    failed = [name for ok, name in cl.results if not ok]
    assert cl.ok, f"failed checks: {failed}"


def test_coordinator_mission(tmp_path, monkeypatch):
    """Full operator chain: recon → exploiter → analyst with narrative."""
    import json as _json
    import os
    from pathlib import Path as _Path
    monkeypatch.chdir(tmp_path)
    from validation.fake_tools import prepend_path, write_fake_tools
    from validation.scripted_llm import ScriptedLLM
    write_fake_tools(tmp_path / "bin", "10.10.10.5")
    with prepend_path(tmp_path / "bin"):
        (tmp_path / "authorization.json").write_text(_json.dumps({
            "engagement": "mission-test", "valid_from": "2020-01-01",
            "valid_until": "2099-01-01", "scope": ["10.10.10.0/24"],
            "exclusions": []}))
        cfg = _json.loads(_Path(__file__).resolve().parent.parent
                          .joinpath("config.example.json").read_text())
        cfg["paths"] = {"db": "eng.db", "logs_dir": "logs",
                        "output_dir": "logs/output",
                        "authorization": "authorization.json",
                        "reports_dir": "reports", "loot_dir": "loot"}
        from aegis.cli import Shell
        shell = Shell(cfg)
        scripted = ScriptedLLM("10.10.10.5")
        shell.agent.llm = scripted
        shell.llm = scripted
        shell.refuter.llm = scripted
        shell._target_or_print("10.10.10.5")
        result = shell.coordinator.run_mission("10.10.10.5")
        assert set(result["phases"]) == {"recon", "exploiter", "analyst"}
        narrative = result["phases"]["analyst"]["narrative"]
        assert "Attack narrative" in narrative
        # credential from the exploiter phase landed in the vault
        assert any("admin:S3cur3!" in (c["value"] or "")
                   for c in shell.db.credentials())
        # narrative recorded as loot note for the report
        notes = [l for l in shell.db.loot_for()
                 if l["title"] == "attack narrative"]
        assert notes


def test_hydra_login_flag_allowed(scope):
    """'-l' is hydra's login flag, not a target-file flag."""
    g = CommandGuard(scope, ".")
    g.check_flags("hydra", ["-l", "admin", "-P", "wl.txt", "ssh://10.10.10.5"])


def test_nuclei_list_flag_denied(scope):
    g = CommandGuard(scope, ".")
    with pytest.raises(GuardError):
        g.check_flags("nuclei", ["-l", "targets.txt"])


def test_nmap_il_flag_denied(scope):
    g = CommandGuard(scope, ".")
    with pytest.raises(GuardError):
        g.check_flags("nmap", ["-iL", "targets.txt"])
