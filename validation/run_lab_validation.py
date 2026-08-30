"""Full-loop lab validation: scan → attack → report, end to end.

Two modes:

  SIMULATION (default, runs anywhere):
    Fake lab tools + scripted LLM drive the entire real pipeline —
    planner, guard, runner, parsers, memory, encrypted loot, ATT&CK
    tagging, report, audit chain — with pass/fail checkpoints.

  REAL (--real, run on Kali):
    Same checklist against a live lab VM (Metasploitable, HTB, …) with
    real tools and a real LLM backend.

Usage:
    python -m validation.run_lab_validation                 # simulation
    python -m validation.run_lab_validation --real --target 10.10.10.5
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from validation.fake_tools import prepend_path, write_fake_tools
from validation.scripted_llm import ScriptedLLM

TARGET = "10.10.10.5"


class Checklist:
    def __init__(self, verbose: bool = True):
        self.results: list[tuple[bool, str]] = []
        self.verbose = verbose

    def check(self, name: str, condition: bool, detail: str = "") -> bool:
        self.results.append((bool(condition), name))
        if self.verbose:
            mark = "✅ PASS" if condition else "❌ FAIL"
            suffix = f" — {detail}" if detail and not condition else ""
            print(f"  {mark}  {name}{suffix}")
        return bool(condition)

    @property
    def ok(self) -> bool:
        return all(ok for ok, _ in self.results)


def _make_workspace(root: Path, real: bool) -> dict:
    (root / "authorization.json").write_text(json.dumps({
        "engagement": "lab-validation",
        "valid_from": "2020-01-01", "valid_until": "2099-01-01",
        "scope": ["10.10.10.0/24"],
        "exclusions": [],
        "prohibited_techniques": ["denial-of-service"],
        "max_requests_per_second": 0,
        "testing_hours": "",
    }), encoding="utf-8")
    cfg_path = Path(__file__).resolve().parent.parent / "config.example.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["paths"] = {
        "db": str(root / "engagement.db"),
        "logs_dir": str(root / "logs"),
        "output_dir": str(root / "logs" / "output"),
        "authorization": str(root / "authorization.json"),
        "reports_dir": str(root / "reports"),
        "loot_dir": str(root / "loot"),
    }
    return cfg


def run_validation(root: Path, target: str = TARGET, *, real: bool = False,
                   verbose: bool = True) -> Checklist:
    import os
    os.chdir(root)
    cl = Checklist(verbose)
    cfg = _make_workspace(root, real)

    from aegis.cli import Shell
    shell = Shell(cfg)

    if not real:
        scripted = ScriptedLLM(target)
        shell.agent.llm = scripted
        shell.llm = scripted

    print(f"\n[1/7] Scope gate")
    row = shell._target_or_print(target)
    cl.check("in-scope target accepted", row is not None)
    res = shell.runner.run("nmap", ["-sV", target, "8.8.8.8"],
                           target_host=target)
    cl.check("out-of-scope embedded host refused", res.status == "refused")

    print(f"\n[2/7] OSINT")
    shell.cmd_osint([target])
    cl.check("OSINT items recorded",
             len(shell.db.osint_for(row["id"])) > 0)

    print(f"\n[3/7] Scan agent")
    scan = shell.agent.run("scan", target)
    cl.check("scan agent completed steps",
             any("command" in e for e in scan["transcript"]))
    attempts = shell.db.attempts_for(row["id"])
    cl.check("scan attempts recorded with ATT&CK tags",
             any(a["attack_id"] for a in attempts))
    memory = shell.db.memory_summary(row["id"])
    cl.check("parser ground truth in memory (open ports)",
             "22/tcp" in memory or "open ports" in memory)

    print(f"\n[4/7] Attack agent")
    attack = shell.agent.run("attack", target)
    creds = shell.db.credentials()
    cl.check("credential captured by deterministic parser",
             any("admin:S3cur3!" in (c["value"] or "") for c in creds))
    if not real:
        raw = shell.db.conn.execute(
            "SELECT value FROM loot WHERE kind='credential'").fetchall()
        cl.check("loot encrypted at rest",
                 all(r["value"].startswith("enc:v1:") for r in raw))
    cl.check("attack attempt tagged T1110",
             any(a["attack_id"] == "T1110"
                 for a in shell.db.attempts_for(row["id"])))

    print(f"\n[5/7] ATT&CK coverage")
    from aegis.attack_map import coverage
    cov = coverage(shell.db)
    cl.check("multiple tactics covered",
             sum(1 for c in cov.values() if c["tried"]) >= 2)

    print(f"\n[6/7] Report")
    shell.cmd_report(["lab-validation"])
    md = root / "reports" / "report-lab-validation.md"
    cl.check("report file generated", md.exists())
    if md.exists():
        text = md.read_text(encoding="utf-8")
        cl.check("report has ATT&CK coverage section",
                 "ATT&CK Coverage" in text)
        cl.check("report secrets redacted",
                 "S3cur3!" not in text)
        cl.check("report records the successful brute-force",
                 "brute-force" in text)

    print(f"\n[7/7] Audit chain")
    from aegis.audit import AuditLog
    logs = sorted((root / "logs").glob("audit-*.jsonl"))
    cl.check("audit log exists", len(logs) > 0)
    for p in logs:
        ok, msg = AuditLog.verify(p)
        cl.check(f"audit chain intact ({p.name})", ok, msg)

    shell.db.close()
    return cl


def run_simulation(verbose: bool = True) -> Checklist:
    root = Path(tempfile.mkdtemp(prefix="aegis-lab-"))
    write_fake_tools(root / "bin", TARGET)
    with prepend_path(root / "bin"):
        return run_validation(root, TARGET, real=False, verbose=verbose)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", action="store_true",
                    help="run against a live lab target with real tools/LLM")
    ap.add_argument("--target", default=TARGET)
    args = ap.parse_args()

    print("=" * 60)
    print("AEGIS LAB VALIDATION — full scan → attack → report loop")
    print("mode:", "REAL (live target)" if args.real else "SIMULATION (fake tools)")
    print("=" * 60)

    if args.real:
        ans = input(f"Run against live target {args.target}? "
                    f"Confirm written authorization [yes/NO]: ")
        if ans.strip().lower() != "yes":
            print("Aborted.")
            return 2
        root = Path(tempfile.mkdtemp(prefix="aegis-lab-real-"))
        cl = run_validation(root, args.target, real=True)
    else:
        cl = run_simulation()

    print("\n" + "=" * 60)
    passed = sum(1 for ok, _ in cl.results if ok)
    print(f"RESULT: {passed}/{len(cl.results)} checks passed")
    print("LAB VALIDATION " + ("PASSED ✅" if cl.ok else "FAILED ❌"))
    print("=" * 60)
    return 0 if cl.ok else 1


if __name__ == "__main__":
    sys.exit(main())
