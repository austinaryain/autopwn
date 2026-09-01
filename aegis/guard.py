"""Command guard — closes the critical hole between the scope gate and the
actual command line.

Before ANY tool executes, the guard:

1. Extracts every host, IP and URL embedded in the *arguments* (not just the
   declared target) and scope-checks each one. A hallucinated
   `nmap -sV 10.10.10.5 8.8.8.8` is refused.
2. Enforces an argument-safety policy: no arbitrary code-exec flags, no
   target-list files (scope bypass), no output paths outside the workspace.
3. Enforces the engagement rules of engagement from authorization.json:
   prohibited techniques, testing hours, and a global rate limit.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from .scope import ScopeError, ScopeGate


class GuardError(Exception):
    pass


IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
CIDR_HOST_RE = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3})/\d{1,2}$")

# Flags that execute arbitrary code or scripts — never allowed from a planner.
DENY_FLAGS = {
    "--script", "--script-args", "--script-args-file",  # nmap NSE = code exec
    "-e", "-c",                                          # nc/ncat command exec
    "--eval",
    "-r",                                                # msfconsole resource script
    "-x",                                                # msfconsole execute command
}

# Flags that read a list of targets from a file — bypasses per-host scope
# checks, so they are denied outright (scope each host individually instead).
# NOTE: tool-specific — e.g. '-l' is a target list for nuclei but a login
# name for hydra.
TARGET_FILE_FLAGS_GLOBAL = {"--targets-file"}
TARGET_FILE_FLAGS_BY_TOOL: dict[str, set[str]] = {
    "nmap": {"-iL"},
    "masscan": {"-iL"},
    "rustscan": {"-iL"},
    "nuclei": {"-l", "--list"},
    "amass": {"-df"},
    # NOTE: sublist3r/theHarvester '-d' is the domain itself (scope-checked
    # like any other arg) — do NOT list it here or those tools break.
}

# Flags whose value is an output path; the value must stay inside the workspace.
OUTPUT_PATH_FLAGS = {
    "-o", "-oA", "-oX", "-oN", "-oG", "-oS", "--output", "--output-file",
    "--log", "--log-file",
}

# File extensions that indicate wordlists/payloads rather than hostnames.
FILE_EXT_RE = re.compile(r"\.(txt|lst|json|xml|csv|log|rc|sh|py|gz|tar|zip|"
                         r"png|jpg|html?|md|db|yaml|yml|conf|cfg)$", re.I)

# NSE script categories that are valid selectors without a .nse file.
NMAP_CATEGORIES = {"auth", "broadcast", "brute", "default", "discovery",
                   "dos", "exploit", "external", "fuzzer", "intrusive",
                   "malware", "safe", "version", "vuln"}
NMAP_SCRIPT_DIRS = ("/usr/share/nmap/scripts",
                    "/usr/local/share/nmap/scripts")


def extract_hosts(args: list[str]) -> list[str]:
    """Pull every host-like token out of a command argument list."""
    hosts: list[str] = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg in OUTPUT_PATH_FLAGS or arg in TARGET_FILE_FLAGS_GLOBAL or \
                any(arg in s for s in TARGET_FILE_FLAGS_BY_TOOL.values()):
            skip_next = True
            continue
        a = arg.strip()
        if not a or a.startswith("-") and not URL_RE.match(a):
            # plain flag like -sV (but URLs can follow schemes with '-')
            if a.startswith("-"):
                continue
        # key=value forms (e.g. msf RHOSTS=10.0.0.1)
        if "=" in a and not URL_RE.match(a):
            a = a.split("=", 1)[1]
        # URLs
        if URL_RE.match(a):
            host = urlparse(a).hostname
            if host:
                hosts.append(host)
            continue
        # scheme-less host:port
        a_noport = a.rsplit(":", 1)[0] if re.match(r"^\S+:\d+$", a) else a
        if CIDR_HOST_RE.match(a_noport):
            a_noport = CIDR_HOST_RE.match(a_noport).group(1)  # type: ignore[union-attr]
        if IP_RE.match(a_noport):
            hosts.append(a_noport)
            continue
        if DOMAIN_RE.match(a_noport) and not FILE_EXT_RE.search(a_noport):
            hosts.append(a_noport.lower())
    # dedupe, preserve order
    seen, out = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


class CommandGuard:
    def __init__(self, scope: ScopeGate, workspace: str | Path = "."):
        self.scope = scope
        self.workspace = Path(workspace).resolve()
        self._last_exec = 0.0

    # ---- argument safety -------------------------------------------------
    def check_flags(self, tool: str, args: list[str]) -> None:
        file_flags = TARGET_FILE_FLAGS_GLOBAL | TARGET_FILE_FLAGS_BY_TOOL.get(
            tool, set())
        for i, arg in enumerate(args):
            if arg in DENY_FLAGS:
                raise GuardError(
                    f"Flag '{arg}' is denied: it executes arbitrary code/scripts.")
            if arg in file_flags:
                raise GuardError(
                    f"Flag '{arg}' reads targets from a file — this bypasses "
                    f"per-host scope checks. Scope and run each host individually.")
            if arg in OUTPUT_PATH_FLAGS and i + 1 < len(args):
                dest = Path(args[i + 1])
                if not dest.is_absolute():
                    dest = (Path.cwd() / dest)
                try:
                    dest.resolve().relative_to(self.workspace)
                except ValueError:
                    raise GuardError(
                        f"Output path '{args[i + 1]}' escapes the workspace — refused.")

    # ---- grounding: arguments must match local reality -------------------
    @staticmethod
    def _nmap_script_dir() -> Path | None:
        for d in NMAP_SCRIPT_DIRS:
            if Path(d).is_dir():
                return Path(d)
        return None

    def check_grounding(self, tool: str, args: list[str]) -> None:
        """Refuse commands that reference things which do not exist locally:
        hallucinated NSE script names and made-up file/wordlist paths.
        Runs only when the reference data is available (no-op off-Kali)."""
        # 1. nmap --script= names must be real categories or installed .nse
        if tool == "nmap":
            script_dir = self._nmap_script_dir()
            if script_dir is not None:
                requested: list[str] = []
                for a in args:
                    if a.startswith("--script="):
                        requested.extend(
                            s.strip() for s in a.split("=", 1)[1].split(",")
                            if s.strip())
                if requested:
                    import difflib
                    import glob as _glob
                    installed = {p.stem for p in script_dir.glob("*.nse")}
                    bad: list[str] = []
                    for name in requested:
                        if name in NMAP_CATEGORIES or name in installed:
                            continue
                        if any(c in name for c in "*?["):
                            if _glob.glob(str(script_dir / f"{name}.nse")):
                                continue
                        bad.append(name)
                    if bad:
                        detail = []
                        for b in bad:
                            close = difflib.get_close_matches(
                                b, sorted(installed), n=3, cutoff=0.55)
                            detail.append(
                                f"'{b}'" + (f" (did you mean: {', '.join(close)}?)"
                                            if close else " (nothing similar)"))
                        raise GuardError(
                            "Unknown NSE script(s): " + "; ".join(detail) +
                            f". Only use scripts installed in {script_dir}.")

        # 2. filesystem paths in arguments must exist (wordlists etc.)
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg in OUTPUT_PATH_FLAGS:
                skip_next = True   # output destinations are created, not read
                continue
            if URL_RE.match(arg):
                continue
            if not arg.startswith(("/", "~/", "./", "../")):
                continue
            p = Path(os.path.expanduser(arg))
            if not p.is_absolute():
                p = self.workspace / p
            if not p.exists():
                from .playbook import available_wordlists
                wls = available_wordlists()
                hint = (" Wordlists that DO exist: " + "; ".join(
                    f"{k}={v}" for k, v in wls.items())) if wls else ""
                raise GuardError(
                    f"Path '{arg}' does not exist on this machine — refusing "
                    f"to run a command built on a made-up file path.{hint}")

    # ---- embedded host scope ---------------------------------------------
    def check_embedded_hosts(self, args: list[str]) -> list[str]:
        hosts = extract_hosts(args)
        for h in hosts:
            try:
                self.scope.check(h)
            except ScopeError as exc:
                raise GuardError(
                    f"Argument references out-of-scope host '{h}': {exc}") from exc
        return hosts

    # ---- rules of engagement ---------------------------------------------
    def check_roe(self, tool: str, args: list[str], technique: str = "") -> None:
        roe = self.scope.roe
        hay = " ".join([tool, technique, *args]).lower()
        for banned in roe.get("prohibited_techniques", []):
            b = str(banned).lower()
            if b in hay:
                raise GuardError(
                    f"'{banned}' is prohibited by the engagement rules of "
                    f"engagement (authorization.json).")
        hours = roe.get("testing_hours", "")
        if hours:
            self._check_hours(hours)

    @staticmethod
    def _check_hours(hours: str) -> None:
        m = re.match(r"^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$", hours)
        if not m:
            return
        h1, m1, h2, m2 = (int(x) for x in m.groups())
        now = time.localtime()
        cur = now.tm_hour * 60 + now.tm_min
        start, end = h1 * 60 + m1, h2 * 60 + m2
        ok = start <= cur <= end if start <= end else (cur >= start or cur <= end)
        if not ok:
            raise GuardError(
                f"Outside authorized testing hours ({hours}). Refusing to run.")

    def rate_limit(self) -> float:
        """Enforce the engagement max_requests_per_second. Returns wait seconds."""
        rps = float(self.scope.roe.get("max_requests_per_second", 0) or 0)
        if rps <= 0:
            return 0.0
        interval = 1.0 / rps
        now = time.time()
        wait = self._last_exec + interval - now
        if wait > 0:
            time.sleep(wait)
        self._last_exec = time.time()
        return max(wait, 0.0)

    # ---- full gate ---------------------------------------------------------
    def validate(self, tool: str, args: list[str], technique: str = "") -> list[str]:
        """Run all checks; returns the list of embedded hosts that passed."""
        self.check_flags(tool, args)
        self.check_grounding(tool, args)
        hosts = self.check_embedded_hosts(args)
        self.check_roe(tool, args, technique)
        self.rate_limit()
        return hosts
