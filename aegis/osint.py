"""OSINT collector — passive recon pulled automatically for a target.

Collectors are network-light and passive-first: DNS records, certificate
transparency (crt.sh) subdomains, and whois. Everything is stored in the
engagement DB and rendered as a digestible summary.
"""

from __future__ import annotations

import socket

import requests

from .db import EngagementDB
from .runner import Runner, RunnerError


class OSINTCollector:
    def __init__(self, runner: Runner, db: EngagementDB):
        self.runner = runner
        self.db = db

    def collect(self, host: str, target_id: int) -> dict:
        results = {"host": host, "dns": {}, "subdomains": [], "whois_tail": ""}
        results["dns"] = self._dns(host, target_id)
        if not self._is_ip(host):
            results["subdomains"] = self._crtsh(host, target_id)
            results["whois_tail"] = self._whois(host, target_id)
        return results

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            socket.inet_aton(value)
            return True
        except OSError:
            return False

    def _dns(self, host: str, target_id: int) -> dict:
        records: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                res = self.runner.run("dig", ["+short", rtype, host],
                                      target_host=host, target_id=target_id,
                                      agent="osint", timeout=60)
                lines = [ln.strip() for ln in res.stdout_tail.splitlines() if ln.strip()]
                if lines:
                    records[rtype] = lines
                    self.db.record_osint(target_id, "dig", f"dns-{rtype}", lines)
            except RunnerError:
                records[rtype] = []
        return records

    def _crtsh(self, domain: str, target_id: int) -> list[str]:
        try:
            r = requests.get("https://crt.sh/", params={"q": f"%.{domain}",
                                                        "output": "json"},
                             timeout=30)
            r.raise_for_status()
            names = set()
            for entry in r.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lower()
                    if name and "*" not in name:
                        names.add(name)
            subs = sorted(names)
            if subs:
                self.db.record_osint(target_id, "crt.sh", "subdomains", subs)
            return subs
        except (requests.RequestException, ValueError):
            return []

    def _whois(self, domain: str, target_id: int) -> str:
        try:
            res = self.runner.run("whois", [domain], target_host=domain,
                                  target_id=target_id, agent="osint", timeout=60)
            tail = "\n".join(res.stdout_tail.splitlines()[:25])
            if tail:
                self.db.record_osint(target_id, "whois", "registration", tail)
            return tail
        except RunnerError:
            return ""


def render_osint_summary(data: dict) -> str:
    """Human-digestible rendering of a collect() result."""
    lines = [f"OSINT summary for {data['host']}", "=" * 40, "", "DNS:"]
    dns = data.get("dns") or {}
    if any(dns.values()):
        for rtype, values in dns.items():
            for v in values:
                lines.append(f"  {rtype:5} {v}")
    else:
        lines.append("  (no records collected)")
    subs = data.get("subdomains") or []
    lines.append(f"\nSubdomains from certificate transparency ({len(subs)}):")
    for s in subs[:30]:
        lines.append(f"  - {s}")
    if len(subs) > 30:
        lines.append(f"  … and {len(subs) - 30} more (see engagement DB)")
    whois = (data.get("whois_tail") or "").strip()
    if whois:
        lines.append("\nWHOIS (head):")
        lines.extend(f"  {ln}" for ln in whois.splitlines()[:15])
    return "\n".join(lines)
