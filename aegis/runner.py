"""Scoped command runner — the only path by which tools execute.

Responsibilities:
- tool allowlist (from config)
- optional proxychains4 wrapping of every invocation
- optional VPN interface requirement (tun0/wg0) before running
- timeout enforcement
- full stdout/stderr capture to logs/output/<id>.log
- recording every run in the audit log and engagement DB
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from .audit import AuditLog
from .db import EngagementDB
from .diag import get_logger
from .scope import ScopeError, ScopeGate

log = get_logger("runner")


class RunnerError(Exception):
    pass


_ANSI_RE = __import__("re").compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07")
_CTRL_RE = __import__("re").compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_output(text: str) -> str:
    """Strip ANSI escapes and control chars from untrusted tool output —
    targets can send hostile terminal sequences."""
    return _CTRL_RE.sub("", _ANSI_RE.sub("", text))


class RunResult:
    def __init__(self, action_id, command, exit_code, duration, output_file,
                 stdout_tail, status):
        self.action_id = action_id
        self.command = command
        self.exit_code = exit_code
        self.duration = duration
        self.output_file = output_file
        self.stdout_tail = stdout_tail
        self.status = status  # "ok" | "error" | "timeout" | "refused"
        self.refusal = None   # "guard" | "scope" when status == "refused"

    def __repr__(self):
        return (f"<RunResult {self.status} exit={self.exit_code} "
                f"{self.duration:.1f}s -> {self.output_file}>")


class Runner:
    def __init__(self, config: dict, db: EngagementDB, audit: AuditLog,
                 scope: ScopeGate):
        rc = config.get("runner", {})
        paths = config.get("paths", {})
        self.allowed_tools = set(rc.get("allowed_tools", []))
        self.use_proxychains = bool(rc.get("use_proxychains", False))
        self.proxychains_bin = rc.get("proxychains_bin", "proxychains4")
        self.require_vpn = bool(rc.get("require_vpn", False))
        self.vpn_interfaces = rc.get("vpn_interfaces", ["tun0", "wg0"])
        self.default_timeout = int(rc.get("default_timeout", 600))
        self.output_dir = Path(paths.get("output_dir", "logs/output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.db = db
        self.audit = audit
        self.scope = scope
        self.opsec = None  # optional OpsecProfile, set by the shell
        self.guard = None  # optional CommandGuard, set by the shell
        import threading
        self._active_lock = threading.Lock()
        self.active_procs: dict[int, subprocess.Popen] = {}

    def cancel_all(self) -> int:
        """Kill every running tool process. Returns count killed."""
        with self._active_lock:
            procs = list(self.active_procs.values())
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass
        if procs:
            log.warning("cancel_all killed %d process(es)", len(procs))
        return len(procs)

    # ---- transport checks ----------------------------------------------
    def vpn_up(self) -> bool:
        for iface in self.vpn_interfaces:
            if Path(f"/sys/class/net/{iface}").exists():
                return True
        return False

    def proxychains_available(self) -> bool:
        return shutil.which(self.proxychains_bin) is not None

    # ---- execution ------------------------------------------------------
    def run(self, tool: str, args: list[str], *, target_host: str | None = None,
            target_id: int | None = None, agent: str = "user",
            timeout: int | None = None, cancel_event=None) -> RunResult:
        # 1. allowlist
        if tool not in self.allowed_tools:
            self.audit.log(agent, "runner", "tool_refused",
                           {"tool": tool, "reason": "not in allowlist"})
            raise RunnerError(f"Tool '{tool}' is not in the allowed_tools list.")

        # 2. command guard: embedded-host scope, flag policy, RoE, rate limit.
        #    Runs BEFORE the installed check so refusals are always enforced
        #    and audited, even on machines without the tool.
        if self.guard is not None:
            from .guard import GuardError
            try:
                self.guard.validate(tool, [str(a) for a in args])
            except GuardError as exc:
                log.warning("guard refused %s %s: %s", tool, args, exc)
                self.audit.log(agent, "guard", "command_refused",
                               {"tool": tool, "args": args, "reason": str(exc)})
                cmd_str = f"{tool} {' '.join(str(a) for a in args)}"
                action_id = self.db.record_action(
                    target_id, agent, tool, cmd_str, -1, 0.0, None, "refused",
                    error=f"guard refused: {exc}")
                res = RunResult(action_id, cmd_str, -1, 0.0, None, "", "refused")
                res.refusal = "guard"
                return res

        # 3. scope gate
        if target_host:
            try:
                self.scope.check(target_host)
            except ScopeError as exc:
                log.warning("scope refused %s: %s", target_host, exc)
                self.audit.log(agent, "scope", "out_of_scope_refused",
                               {"host": target_host, "tool": tool, "error": str(exc)})
                cmd_str = f"{tool} {' '.join(str(a) for a in args)}"
                action_id = self.db.record_action(
                    target_id, agent, tool, cmd_str, -1, 0.0, None, "refused",
                    error=f"out of scope: {exc}")
                res = RunResult(action_id, cmd_str, -1, 0.0, None, "", "refused")
                res.refusal = "scope"
                return res

        # 4. tool must exist before we go further
        resolved = shutil.which(tool)
        if resolved is None:
            raise RunnerError(f"Tool '{tool}' is not installed on this system.")

        # 5. VPN requirement
        if self.require_vpn and not self.vpn_up():
            raise RunnerError(
                f"require_vpn is on but none of {self.vpn_interfaces} is up.")

        # 6. build command (proxychains wrap) — absolute path: no PATH race
        cmd = [resolved, *args]
        wrapped = False
        if self.use_proxychains and self.proxychains_available():
            cmd = [self.proxychains_bin, "-q", *cmd]
            wrapped = True

        # 4b. OPSEC gate (may jitter-sleep or refuse unwrapped execution)
        opsec_notes = {}
        if self.opsec is not None:
            from .opsec import OpsecError
            try:
                opsec_notes = self.opsec.pre_exec(tool, proxy_wrapped=wrapped)
            except OpsecError as exc:
                self.audit.log(agent, "opsec", "exec_refused",
                               {"tool": tool, "reason": str(exc)})
                raise RunnerError(str(exc)) from exc

        cmd_str = " ".join(cmd)

        self.audit.log(agent, "runner", "exec_start",
                       {"command": cmd_str, "target": target_host,
                        "proxychains": wrapped, "vpn_up": self.vpn_up(),
                        "opsec": opsec_notes})

        # 5. execute (Popen so the operator can kill a running process)
        timeout = timeout or self.default_timeout
        t0 = time.time()
        status, out = "ok", ""
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        with self._active_lock:
            self.active_procs[proc.pid] = proc
        try:
            while True:
                try:
                    stdout, stderr = proc.communicate(timeout=1.0)
                    exit_code = proc.returncode
                    out = (stdout or "") + (("\n[stderr]\n" + stderr) if stderr else "")
                    break
                except subprocess.TimeoutExpired:
                    if cancel_event is not None and cancel_event.is_set():
                        proc.kill()
                        proc.communicate()
                        exit_code = -15
                        status = "cancelled"
                        out = "[CANCELLED by operator]"
                        log.warning("process killed by operator: %s (pid %s)",
                                    tool, proc.pid)
                        break
                    if time.time() - t0 > timeout:
                        proc.kill()
                        stdout, stderr = proc.communicate()
                        log.warning("timeout after %ss: %s", timeout, tool)
                        exit_code = -9
                        status = "timeout"
                        out = (stdout or "") + f"\n[TIMEOUT after {timeout}s]"
                        break
        finally:
            with self._active_lock:
                self.active_procs.pop(proc.pid, None)
        duration = time.time() - t0
        if status == "ok" and exit_code != 0:
            status = "error"
        out = sanitize_output(out)
        log.debug("exec %s exit=%s %.1fs status=%s", tool, exit_code,
                  duration, status)

        # compact failure reason — surfaced in dashboard, CLI and agent memory
        error_summary = ""
        if status != "ok":
            if status == "cancelled":
                error_summary = "cancelled by operator"
            else:
                src = out.split("\n[stderr]\n", 1)[-1] if "\n[stderr]\n" in out else out
                tail = [ln for ln in src.strip().splitlines() if ln.strip()]
                error_summary = "\n".join(tail[-8:])[:400]
                if not error_summary:
                    error_summary = f"exit code {exit_code} with no output"

        # 6. persist output + records
        action_id = self.db.record_action(
            target_id, agent, tool, cmd_str, exit_code, duration, None, status,
            error=error_summary)
        output_file = self.output_dir / f"action-{action_id}.log"
        output_file.write_text(f"$ {cmd_str}\n(exit {exit_code}, {duration:.1f}s)\n\n{out}",
                               encoding="utf-8", errors="replace")
        self.db._execute("UPDATE actions SET output_file = ? WHERE id = ?",
                         (str(output_file), action_id))

        self.audit.log(agent, "runner", "exec_end",
                       {"action_id": action_id, "command": cmd_str,
                        "exit_code": exit_code, "duration_sec": round(duration, 2),
                        "status": status, "output_file": str(output_file)})

        # 7. deterministic post-processing: mine every byte we captured.
        #    Flags/secrets become loot; services/versions/web stack become
        #    structured intel that feeds the dashboard, planner and playbook.
        if target_id is not None and out and status != "refused":
            from .intel import extract_intel, hunt_flags
            for f in hunt_flags(out):
                self.db.record_loot(target_id, f["kind"], f["title"],
                                    value=f["value"], source=cmd_str[:200])
                self.audit.log(agent, "loot", "auto_capture",
                               {"kind": f["kind"], "title": f["title"],
                                "action_id": action_id})
                log.warning("AUTO-CAPTURED %s via %s: %s",
                            f["kind"], tool, f["value"][:80])
            for item in extract_intel(tool, cmd_str, out):
                self.db.record_intel(target_id, item["kind"], item["key"],
                                     item["value"], source=cmd_str)

        tail = "\n".join(out.strip().splitlines()[-40:])
        return RunResult(action_id, cmd_str, exit_code, duration,
                         str(output_file), tail, status)
