"""Diagnostics — module-level debug logging + environment health checks.

The audit chain answers "what did Aegis do?" (tamper-evident, for clients).
The debug log answers "why did it misbehave?" (verbose, for operators):

  logs/debug-YYYYMMDD.log   — every module logs here via get_logger(__name__)

`doctor()` runs a full environment health check and returns structured
results for the /doctor command.
"""

from __future__ import annotations

import logging
import shutil
import sys
import time
from pathlib import Path

_initialized_paths: set[str] = set()


def setup_logging(logs_dir: str | Path, level: int = logging.DEBUG) -> Path:
    """Configure the shared debug log. Idempotent per log directory."""
    logs = Path(logs_dir)
    logs.mkdir(parents=True, exist_ok=True)
    path = logs / f"debug-{time.strftime('%Y%m%d')}.log"
    key = str(logs.resolve())
    if key not in _initialized_paths:
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        root = logging.getLogger("aegis")
        root.setLevel(level)
        root.addHandler(handler)
        root.propagate = False
        _initialized_paths.add(key)
    return path


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"aegis.{name}")


def tail_debug_log(logs_dir: str | Path, lines: int = 40,
                   min_level: str = "WARNING") -> list[str]:
    """Last N lines at or above min_level from today's debug log."""
    path = Path(logs_dir) / f"debug-{time.strftime('%Y%m%d')}.log"
    if not path.exists():
        return ["(no debug log yet today)"]
    rank = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
    threshold = rank.get(min_level.upper(), 2)
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        lvl = next((r for name, r in rank.items() if f" {name:<7}" in line
                    or f" {name} " in line), None)
        if lvl is not None and lvl >= threshold:
            out.append(line)
    return out[-lines:] or ["(no warnings or errors today)"]


def doctor(config: dict, shell=None) -> list[dict]:
    """Environment health check. Returns [{name, ok, detail}]."""
    results: list[dict] = []

    def check(name, ok, detail=""):
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    # python
    check("python >= 3.10", sys.version_info >= (3, 10),
          ".".join(map(str, sys.version_info[:3])))

    # core deps
    for mod in ("rich", "requests", "cryptography", "msgpack"):
        try:
            __import__(mod)
            check(f"python dep: {mod}", True)
        except ImportError:
            check(f"python dep: {mod}", False, "pip install -r requirements.txt")

    # authorization / scope
    if shell is not None:
        check("authorization loaded", shell.scope is not None,
              f"engagement '{shell.scope.engagement}', "
              f"{len(shell.scope.scope)} scope entries")
        check("loot encryption active", shell.cipher.active,
              shell.cipher.error or "Fernet")
        check("LLM backend reachable", shell.llm.available(),
              f"{shell.llm.backend} @ {shell.llm.base_url} "
              f"model={shell.llm.model}")
        check("proxychains available", shell.runner.proxychains_available(),
              shell.runner.proxychains_bin)
        check("VPN interface up", shell.runner.vpn_up(),
              "checked " + ",".join(shell.runner.vpn_interfaces))

    # kali tools
    tools = config.get("runner", {}).get("allowed_tools", [])
    installed = [t for t in tools if shutil.which(t)]
    missing = [t for t in tools if not shutil.which(t)]
    check("kali tools installed", len(missing) <= len(tools) // 2,
          f"{len(installed)}/{len(tools)} present"
          + (f"; missing: {', '.join(missing[:8])}{'…' if len(missing) > 8 else ''}"
             if missing else ""))

    # OSV reachability (disclosure novelty checks)
    try:
        import requests
        ok = requests.get("https://api.osv.dev/v1/vulns/CVE-2021-41773",
                          timeout=8).ok
        check("OSV API reachable", ok)
    except Exception as exc:
        check("OSV API reachable", False, str(exc)[:80])

    return results
