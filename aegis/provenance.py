"""Finding provenance & refuter — the anti-hallucination layer (P0).

Every finding carries a provenance label:
  - tool-proven     — produced by a deterministic parser from real tool output
  - model-asserted  — claimed by the LLM evaluator

Model-asserted findings at medium severity or above must survive a refuter
pass: an adversarial prompt that tries to DISPROVE the finding from the
captured evidence. Outcomes:
  confirmed  → verified=1, ships in the report's main findings
  uncertain  → status='needs-verification', appendix only
  rejected   → status='rejected', excluded from the report body
"""

from __future__ import annotations

import json
from pathlib import Path

from .db import EngagementDB
from .llm import LLMClient, LLMError

REFUTE_SYSTEM = """You are a hostile reviewer of penetration-test findings. Your job
is to DISPROVE the finding below using only the provided evidence. Look for:
misread tool output, version banners that do not imply the claimed vuln,
generic scanner noise, missing proof of exploitability, and overclaimed
severity. Reply ONLY with JSON:
{"verdict": "confirmed" | "uncertain" | "rejected",
 "reason": "one or two sentences citing the evidence"}
Bias toward rejection: a finding that survives you is allowed into a client
report, and a false positive there is a reputational disaster.
"""

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Refuter:
    def __init__(self, llm: LLMClient, db: EngagementDB):
        self.llm = llm
        self.db = db

    def _load_evidence(self, evidence_path: str, cap: int = 20_000) -> str:
        if not evidence_path:
            return ""
        try:
            return Path(evidence_path).read_text(
                encoding="utf-8", errors="replace")[-cap:]
        except OSError:
            return ""

    def refute_finding(self, finding_id: int) -> dict:
        f = self.db.get_finding(finding_id)
        if not f:
            return {"verdict": "rejected", "reason": "finding not found"}
        if f["provenance"] == "tool-proven":
            return {"verdict": "confirmed", "reason": "tool-proven, exempt"}
        evidence = self._load_evidence(f["evidence"])
        messages = [
            {"role": "system", "content": REFUTE_SYSTEM},
            {"role": "user", "content":
                f"Finding: {f['title']}\nSeverity: {f['severity']}\n"
                f"Description: {f['description']}\n\n"
                f"Evidence:\n{evidence or '(no evidence captured)'}"},
        ]
        try:
            raw = self.llm.chat(messages, json_mode=True)
            text = raw.strip()
            if text.startswith("```"):
                text = text.strip("`").removeprefix("json").strip()
            verdict = json.loads(text)
        except (LLMError, json.JSONDecodeError) as exc:
            verdict = {"verdict": "uncertain",
                       "reason": f"refuter unavailable: {exc}"}
        v = verdict.get("verdict", "uncertain")
        if v not in ("confirmed", "uncertain", "rejected"):
            v = "uncertain"
        status = {"confirmed": None, "uncertain": "needs-verification",
                  "rejected": "rejected"}[v]
        self.db.set_finding_verdict(finding_id, v == "confirmed",
                                    verdict.get("reason", ""), status)
        return {"verdict": v, "reason": verdict.get("reason", "")}

    def review_target(self, target_id: int) -> list[dict]:
        """Refute every model-asserted medium+ finding for a target."""
        results = []
        for f in self.db.findings_for(target_id):
            rank = SEVERITY_RANK.get(f["severity"].lower(), 0)
            if f["provenance"] == "model-asserted" and rank >= 2 \
                    and f["status"] not in ("rejected",):
                r = self.refute_finding(f["id"])
                results.append({"finding_id": f["id"], "title": f["title"],
                                **r})
        return results
