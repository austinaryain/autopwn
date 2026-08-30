"""Post-exploitation: privilege-escalation checks and lateral movement.

- privesc: runs searchsploit against service versions found in memory and
  suggests kernel/local exploits; records them as attempts.
- lateral: mines loot (credentials) and OSINT (subdomains) for new candidate
  hosts, scope-checks each one, and queues in-scope discoveries as targets.
"""

from __future__ import annotations

import re

from .db import EngagementDB
from .runner import Runner, RunnerError
from .scope import ScopeGate

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_-]{2,20})[/ ](\d+(?:\.\d+){1,3})")


class PostEx:
    def __init__(self, runner: Runner, db: EngagementDB, scope: ScopeGate):
        self.runner = runner
        self.db = db
        self.scope = scope

    # ---- privilege escalation ------------------------------------------
    def privesc_check(self, target_id: int, host: str) -> list[dict]:
        """searchsploit against every service/version string in memory."""
        memory = self.db.memory_summary(target_id)
        candidates = set()
        for name, ver in VERSION_RE.findall(memory):
            if name.lower() in {"cve", "http", "tcp", "udp", "the", "and"}:
                continue
            candidates.add(f"{name} {ver}")
        results = []
        for query in sorted(candidates)[:12]:
            try:
                res = self.runner.run("searchsploit", [query],
                                      target_host=host, target_id=target_id,
                                      agent="postex", timeout=60)
            except RunnerError:
                continue
            hits = [ln for ln in res.stdout_tail.splitlines()
                    if "|" in ln and "Shellcode" not in ln][:5]
            if hits:
                self.db.record_attempt(
                    target_id, "privesc-research", "local", f"searchsploit {query}",
                    f"{len(hits)} candidate exploits", bool(hits),
                    evidence=res.output_file or "", attack_id="T1068")
                results.append({"query": query, "hits": hits})
        return results

    # ---- lateral movement ----------------------------------------------
    def lateral_candidates(self, target_id: int) -> dict:
        """Mine memory for new hosts; scope-check and queue the in-scope ones."""
        memory = self.db.memory_summary(target_id)
        seen = {t["host"] for t in self.db.list_targets()}
        found: dict[str, list[str]] = {"queued": [], "out_of_scope": [],
                                       "already_known": []}
        hosts = set(IP_RE.findall(memory)) | set(HOST_RE.findall(memory))
        for h in sorted(hosts):
            if h in seen:
                found["already_known"].append(h)
                continue
            if self.scope.is_in_scope(h):
                self.db.add_target(h, "discovered via lateral movement analysis")
                found["queued"].append(h)
            else:
                found["out_of_scope"].append(h)
        return found

    def credentials_for_lateral(self) -> list[dict]:
        """Summarize looted credentials usable for lateral movement attempts."""
        return [{"title": r["title"], "value": r["value"][:60],
                 "source": r["source"]} for r in self.db.credentials()]
