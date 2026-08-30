"""Fake lab tools — cross-platform shims that emit realistic tool output.

Lets the FULL pipeline (planner → guard → runner → parsers → memory →
loot → report) execute for real on any machine, no Kali required. On Linux
these are shell scripts; on Windows they are .bat files (the runner resolves
absolute paths, so .bat works via CreateProcess).
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")

# tool -> stdout lines (TARGET is substituted with the lab target)
FAKE_OUTPUTS: dict[str, list[str]] = {
    "nmap": [
        "Starting Nmap 7.94 ( https://nmap.org )",
        "Nmap scan report for {T}",
        "Host is up (0.0010s latency).",
        "PORT   STATE SERVICE VERSION",
        "22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3",
        "80/tcp open  http    Apache httpd 2.4.49 ((Unix))",
        "Service detection performed.",
        "Nmap done: 1 IP address (1 host up) scanned in 6.12 seconds",
    ],
    "whatweb": [
        "http://{T} [200 OK] Apache[2.4.49], Country[RESERVED][ZZ], "
        "HTTPServer[Apache/2.4.49 (Unix)], Title[Acme Corp Intranet]",
    ],
    "hydra": [
        "Hydra v9.5 (c) 2023 by van Hauser/THC",
        "[DATA] attacking ssh://{T}:22/",
        "[22][ssh] host: {T}   login: admin   password: S3cur3!",
        "1 of 1 target successfully completed, 1 valid password found",
    ],
    "dig": [
        "{T}",
    ],
    "whois": [
        "Domain Name: LAB-TARGET.LOCAL",
        "Registrar: Lab Registrar Inc.",
        "Registrant Organization: Acme Corp",
        "Name Server: NS1.LAB-TARGET.LOCAL",
    ],
    "curl": [
        "200",
    ],
    "searchsploit": [
        "----------------------------------- ---------------------------------",
        " Exploit Title                     |  Path",
        "----------------------------------- ---------------------------------",
        "Apache 2.4.49 - Path Traversal    | linux/remote/50383.sh",
        "OpenSSH 8.9 - Information Leak    | linux/remote/50999.py",
        "----------------------------------- ---------------------------------",
    ],
    "ping": [
        "PING {T} ({T}) 56(84) bytes of data.",
        "64 bytes from {T}: icmp_seq=1 ttl=64 time=0.04 ms",
    ],
}


def _bat_escape(line: str) -> str:
    return (line.replace("%", "%%")
                .replace("|", "^|")
                .replace("&", "^&")
                .replace("<", "^<")
                .replace(">", "^>"))


def write_fake_tools(directory: str | Path, target: str) -> Path:
    """Write fake tool executables for the current platform. Returns the dir."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    for tool, lines in FAKE_OUTPUTS.items():
        body = [ln.replace("{T}", target) for ln in lines]
        if IS_WINDOWS:
            content = "@echo off\r\n" + "\r\n".join(
                f"echo {_bat_escape(ln)}" for ln in body) + "\r\n"
            (d / f"{tool}.bat").write_text(content, encoding="utf-8")
        else:
            content = "#!/bin/sh\n" + "\n".join(
                "echo '" + ln.replace("'", "'\\''") + "'" for ln in body) + "\n"
            p = d / tool
            p.write_text(content, encoding="utf-8")
            p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return d


class prepend_path:
    """Context manager: put the fake-tools dir first on PATH."""

    def __init__(self, directory: str | Path):
        self.directory = str(Path(directory).resolve())
        self._old = None

    def __enter__(self):
        self._old = os.environ.get("PATH", "")
        os.environ["PATH"] = self.directory + os.pathsep + self._old
        return self

    def __exit__(self, *exc):
        os.environ["PATH"] = self._old
