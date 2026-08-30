"""Deterministic output parsers — ground truth for agent evaluation.

The LLM evaluator can hallucinate; parsers cannot. For tools with a parser,
the parser's verdict on success / loot / findings is authoritative and the
LLM is only used for summarization when the parser is inconclusive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Verdict:
    success: bool
    summary: str
    findings: list[dict] = field(default_factory=list)
    loot: list[dict] = field(default_factory=list)


# ---- nmap ---------------------------------------------------------------
NMAP_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", re.M)


def parse_nmap(output: str) -> Verdict | None:
    ports = NMAP_PORT_RE.findall(output)
    if not ports:
        if "0 hosts up" in output or "Note: Host seems down" in output:
            return Verdict(False, "nmap: host down or no response")
        return None
    services = [f"{p}/{proto} {svc} {ver}".strip()
                for (p, proto, svc, ver) in ports]
    return Verdict(True, f"nmap: {len(ports)} open ports — "
                         + "; ".join(services[:10]))


# ---- hydra / medusa / ncrack ---------------------------------------------
HYDRA_CRED_RE = re.compile(
    r"(?:\[\d+\])?\[(?P<svc>[a-z0-9+.-]+)\]\s+host:\s*(?P<host>\S+).*?"
    r"login:\s*(?P<login>\S+)\s+password:\s*(?P<pass>\S+)", re.I)
NCRACK_CRED_RE = re.compile(
    r"(?P<host>\S+)\s+\d+/\w+\s+(?P<svc>\w+):\s*'(?P<login>[^']+)'\s*'"
    r"(?P<pass>[^']*)'", re.I)


def parse_bruteforce(output: str) -> Verdict | None:
    creds = [{"kind": "credential", "title": f"{m['svc']} on {m['host']}",
              "value": f"{m['login']}:{m['pass']}"}
             for m in HYDRA_CRED_RE.finditer(output)]
    creds += [{"kind": "credential", "title": f"{m['svc']} on {m['host']}",
               "value": f"{m['login']}:{m['pass']}"}
              for m in NCRACK_CRED_RE.finditer(output)]
    if creds:
        return Verdict(True, f"brute-force: {len(creds)} valid credential(s) found",
                       loot=creds)
    if "0 valid passwords found" in output or "[ERROR]" in output:
        return Verdict(False, "brute-force: no valid credentials")
    return None


# ---- nikto ---------------------------------------------------------------
NIKTO_ITEM_RE = re.compile(r"^\+\s+(.*)$", re.M)


def parse_nikto(output: str) -> Verdict | None:
    items = [i for i in NIKTO_ITEM_RE.findall(output)
             if not i.startswith(("Target", "Start", "End", "-"))]
    if not items and "+ " not in output:
        return None
    findings = [{"title": i[:120], "severity": "low", "description": i}
                for i in items if re.search(r"OSVDB|CVE|vulnerab|outdated|"
                                            r"default file|exposed", i, re.I)]
    return Verdict(bool(items), f"nikto: {len(items)} observations, "
                                f"{len(findings)} notable",
                   findings=findings)


# ---- whatweb --------------------------------------------------------------
def parse_whatweb(output: str) -> Verdict | None:
    if "[" not in output:
        return None
    techs = re.findall(r"\[([^\[\]]+)\]", output)
    interesting = [t for t in techs if re.search(
        r"Apache|nginx|IIS|PHP|WordPress|Drupal|Joomla|Tomcat|jQuery", t)]
    return Verdict(bool(techs),
                   "whatweb: " + (", ".join(interesting[:8]) or "no tech identified"))


PARSERS = {
    "nmap": parse_nmap,
    "masscan": parse_nmap,
    "rustscan": parse_nmap,
    "hydra": parse_bruteforce,
    "medusa": parse_bruteforce,
    "ncrack": parse_bruteforce,
    "nikto": parse_nikto,
    "whatweb": parse_whatweb,
}


def evaluate(tool: str, output: str) -> Verdict | None:
    """Deterministic verdict for a tool run, or None if inconclusive."""
    parser = PARSERS.get(tool)
    if not parser:
        return None
    try:
        return parser(output)
    except Exception:
        return None
