"""Diagnostics tests: debug log wiring, tail filtering, doctor checks."""

import json
from pathlib import Path

from aegis.diag import doctor, get_logger, setup_logging, tail_debug_log


def test_debug_log_captures_module_logs(workspace):
    path = setup_logging(workspace / "logs")
    log = get_logger("testmod")
    log.debug("debug line")
    log.warning("warning line")
    log.error("error line")
    text = path.read_text(encoding="utf-8")
    assert "testmod" in text and "error line" in text and "warning line" in text


def test_tail_filters_by_level(workspace):
    setup_logging(workspace / "logs")
    log = get_logger("testtail")
    log.debug("quiet debug detail")
    log.error("loud error detail")
    lines = tail_debug_log(workspace / "logs", min_level="WARNING")
    joined = "\n".join(lines)
    assert "loud error detail" in joined
    assert "quiet debug detail" not in joined


def test_doctor_core_checks(workspace):
    cfg = json.loads(Path(__file__).resolve().parent.parent
                     .joinpath("config.example.json").read_text())
    results = doctor(cfg)  # no shell -> env-only checks
    names = {r["name"]: r for r in results}
    assert names["python >= 3.10"]["ok"]
    assert names["python dep: rich"]["ok"]
    assert "kali tools installed" in names  # detail reports missing tools


def test_doctor_with_shell(workspace):
    cfg = json.loads(Path(__file__).resolve().parent.parent
                     .joinpath("config.example.json").read_text())
    cfg["paths"] = {"db": "eng.db", "logs_dir": "logs",
                    "output_dir": "logs/output",
                    "authorization": "authorization.json",
                    "reports_dir": "reports", "loot_dir": "loot"}
    from aegis.cli import Shell
    shell = Shell(cfg)
    results = doctor(cfg, shell)
    names = {r["name"]: r for r in results}
    assert names["authorization loaded"]["ok"]
    assert names["loot encryption active"]["ok"]
    assert "LLM backend reachable" in names  # may fail offline — that's fine
