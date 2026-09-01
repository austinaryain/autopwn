"""Operator roles + Coordinator — the multi-operator kill chain (P1).

Roles share the same agentic engine and engagement memory, but carry
distinct briefs and tool subsets, sequenced by the Coordinator:

  Recon     → map the attack surface (no exploitation)
  Exploiter → validate weaknesses, capture loot (confirmation-gated)
  Analyst   → post-engagement: refute model-asserted findings, write the
              attack narrative for the report

`/mission <host>` runs the full chain.
"""

from __future__ import annotations

from .agent import Agent
from .db import EngagementDB
from .provenance import Refuter

ROLE_BRIEFS = {
    "recon": (
        "You are the RECON operator. Goal: map the attack surface of {target}. "
        "Enumerate ports, services, versions, DNS, and web technologies. "
        "Do NOT attempt exploitation or brute force. Finish when the surface "
        "is mapped."
    ),
    "exploiter": (
        "You are the EXPLOITER operator. Goal: identify and validate "
        "exploitable weaknesses on {target} using everything in memory "
        "(recon results, OSINT, prior attempts). Adapt after every failure. "
        "Capture credentials as loot. Validate before claiming success. "
        "Stay strictly on this target."
    ),
    "analyst": (
        "You are the ANALYST operator. You run no tools. Review the "
        "engagement memory for {target} and produce the attack narrative."
    ),
}

# tool subsets per role (None = full allowlist)
ROLE_TOOLS = {
    "recon": {"nmap", "masscan", "rustscan", "dig", "host", "whois",
              "whatweb", "curl", "theHarvester", "sublist3r", "amass",
              "ping", "enum4linux", "enum4linux-ng", "smbclient",
              "rpcclient", "ldapsearch"},
    "exploiter": None,  # full allowlist minus recon-only handled by brief
    "analyst": set(),
}

NARRATIVE_PROMPT = """Write the attack narrative section of a penetration test
report for this engagement. Walk the kill chain chronologically: what was
discovered, what was attempted, what succeeded, what failed, and the
business impact of what was proven. Ground every claim in the memory below —
never invent steps that are not recorded. Use clear sections and past tense.

Memory:
{memory}
"""


class Coordinator:
    """Sequences operators over one target, sharing engagement memory."""

    def __init__(self, agent: Agent, db: EngagementDB, refuter: Refuter):
        self.agent = agent
        self.db = db
        self.refuter = refuter

    def run_mission(self, target: str, *, skip_exploit: bool = False,
                    on_step=None, cancel_event=None) -> dict:
        result: dict = {"target": target, "phases": {}}

        def phase_cb(phase):
            def cb(event):
                if on_step:
                    on_step({"operator": phase, **event})
            return cb

        # Phase 1 — recon
        result["phases"]["recon"] = self.agent.run(
            "scan", target, on_step=phase_cb("recon"), cancel_event=cancel_event)
        if cancel_event is not None and cancel_event.is_set():
            self.db.set_target_status(self.db.get_target(target)["id"],
                                      "cancelled")
            result["phases"]["cancelled"] = True
            return result
        self.agent.llm  # planner briefs are per-mode; recon uses scan brief

        # Phase 2 — exploitation (optional, confirmation handled by caller)
        if not skip_exploit:
            result["phases"]["exploiter"] = self.agent.run(
                "attack", target, on_step=phase_cb("exploiter"),
                cancel_event=cancel_event)

        # Phase 3 — analyst: refute + narrative
        row = self.db.get_target(target)
        refutations = self.refuter.review_target(row["id"])
        narrative = ""
        try:
            memory = self.db.memory_summary(row["id"])
            narrative = self.agent.llm.chat(
                [{"role": "user",
                  "content": NARRATIVE_PROMPT.format(memory=memory)}])
        except Exception as exc:
            narrative = f"(narrative unavailable: {exc})"
        if narrative:
            self.db.record_loot(row["id"], "note", "attack narrative",
                                value=narrative[:4000], source="analyst")
        result["phases"]["analyst"] = {"refutations": refutations,
                                       "narrative": narrative}
        self.db.set_target_status(row["id"], "mission-complete")
        return result
