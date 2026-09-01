"""MITRE ATT&CK technique mapping and coverage analysis.

Every attempt gets tagged with an ATT&CK technique ID. Coverage analysis then
shows the planner (and the report) which tactics have been exercised, which
succeeded, and where the gaps are.
"""

from __future__ import annotations

from .db import EngagementDB

# tactic -> [(attack_id, technique name, keywords that imply it)]
ATTACK_MAP: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {
    "Reconnaissance": [
        ("T1595", "Active Scanning", ("nmap", "masscan", "rustscan", "port-scan", "scan")),
        ("T1595.002", "Vulnerability Scanning", ("nikto", "nuclei", "wpscan", "vuln")),
        ("T1590", "Gather Victim Network Information", ("dns", "dig", "whois", "subdomain", "osint", "amass", "sublist3r", "theharvester")),
    ],
    "Resource Development": [
        ("T1587.001", "Develop Capabilities: Exploits", ("searchsploit",)),
    ],
    "Initial Access": [
        ("T1190", "Exploit Public-Facing Application", ("sqlmap", "web-exploit", "exploit-public", "rce", "lfi", "rfi", "upload", "sqli", "ssti", "xss", "xxe", "ssrf")),
        ("T1078", "Valid Accounts", ("valid-account", "default-creds", "stolen-cred")),
    ],
    "Execution": [
        ("T1059", "Command and Scripting Interpreter", ("command-injection", "webshell", "revshell", "msfconsole", "cmdi")),
    ],
    "Persistence": [
        ("T1136", "Create Account", ("create-user", "add-user", "persistence")),
    ],
    "Privilege Escalation": [
        ("T1068", "Exploitation for Privilege Escalation", ("privesc", "linpeas", "winpeas", "kernel-exploit")),
        ("T1078", "Valid Accounts", ("sudo", "su-", "runas")),
    ],
    "Credential Access": [
        ("T1110", "Brute Force", ("hydra", "medusa", "ncrack", "brute")),
        ("T1110.002", "Password Cracking", ("john", "hashcat", "crack")),
        ("T1110.003", "Password Spraying", ("spray",)),
        ("T1003", "OS Credential Dumping", ("hashdump", "secretsdump", "mimikatz", "credential-dump")),
        ("T1552", "Unsecured Credentials", ("grep-pass", "config-cred", "loot-cred")),
    ],
    "Discovery": [
        ("T1046", "Network Service Discovery", ("service-enum", "banner")),
        ("T1087", "Account Discovery", ("enum4linux", "rpcclient", "ldapsearch", "user-enum")),
        ("T1135", "Network Share Discovery", ("smbclient", "smb-share", "crackmapexec", "netexec")),
        ("T1083", "File and Directory Discovery", ("gobuster", "feroxbuster", "dirb", "ffuf", "wfuzz", "dir-")),
    ],
    "Lateral Movement": [
        ("T1021", "Remote Services", ("psexec", "wmiexec", "ssh-login", "lateral")),
        ("T1021.002", "SMB/Windows Admin Shares", ("smb-exec", "admin$",)),
    ],
    "Exfiltration": [
        ("T1041", "Exfiltration Over C2 Channel", ("exfil",)),
    ],
}

KEYWORD_INDEX: list[tuple[str, str, str]] = [
    (kw, tid, tactic)
    for tactic, entries in ATTACK_MAP.items()
    for tid, _name, kws in entries
    for kw in kws
]

TACTIC_ORDER = list(ATTACK_MAP.keys())


def tag_attempt(technique: str, vector: str, tool: str) -> tuple[str, str]:
    """Return (attack_id, tactic) best matching an attempt.

    Keywords match on word boundaries only, so e.g. 'rce' does not fire on
    the 'rce' inside 'brute-force'.
    """
    import re
    hay = f"{technique} {vector} {tool}".lower()
    for kw, tid, tactic in KEYWORD_INDEX:
        if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", hay):
            return tid, tactic
    return "", "Unmapped"


def coverage(db: EngagementDB, target_id: int | None = None) -> dict:
    """Per-tactic coverage: techniques tried vs succeeded."""
    if target_id is None:
        rows = db.conn.execute(
            "SELECT technique, vector, payload, success, attack_id FROM attempts"
        ).fetchall()
    else:
        rows = db.conn.execute(
            "SELECT technique, vector, payload, success, attack_id FROM attempts"
            " WHERE target_id = ?", (target_id,)).fetchall()
    cov: dict[str, dict] = {t: {"tried": set(), "succeeded": set()}
                            for t in TACTIC_ORDER}
    for r in rows:
        tid = r["attack_id"] or ""
        tactic = next((t for t, entries in ATTACK_MAP.items()
                       if any(e[0] == tid for e in entries)), None)
        if not tactic:
            tid2, tactic2 = tag_attempt(r["technique"] or "", r["vector"] or "",
                                        r["payload"] or "")
            tid, tactic = tid2, tactic2
        if tactic in cov:
            key = tid or (r["technique"] or "?")
            cov[tactic]["tried"].add(key)
            if r["success"]:
                cov[tactic]["succeeded"].add(key)
    return cov


def render_coverage(cov: dict) -> str:
    """ASCII heatmap of ATT&CK tactic coverage."""
    lines = [f"{'Tactic':<24} {'Tried':>6} {'Succeeded':>10}  Bar"]
    lines.append("-" * 62)
    for tactic in TACTIC_ORDER:
        c = cov.get(tactic, {"tried": set(), "succeeded": set()})
        tried, succ = len(c["tried"]), len(c["succeeded"])
        bar = "█" * succ + "░" * (tried - succ) or "·"
        lines.append(f"{tactic:<24} {tried:>6} {succ:>10}  {bar}")
    return "\n".join(lines)


def planner_gap_hint(cov: dict) -> str:
    """Short text for the LLM planner: which tactics are untouched."""
    gaps = [t for t in TACTIC_ORDER if not cov.get(t, {}).get("tried")]
    if not gaps:
        return "All ATT&CK tactics have been exercised at least once."
    return "ATT&CK tactics not yet exercised: " + ", ".join(gaps)
