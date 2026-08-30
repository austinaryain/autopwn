"""Scripted LLM — a deterministic stand-in for the planner/evaluator.

Drives a fixed, realistic plan so the full agent loop executes end-to-end
without an LLM backend. Mirrors what a competent planner would do against
the lab target: enumerate, fingerprint, then brute-force SSH.
"""

from __future__ import annotations

import json


class ScriptedLLM:
    def __init__(self, target: str):
        self.target = target
        self._scan = [
            {"thought": "start with service enumeration",
             "done": False,
             "command": {"tool": "nmap", "args": ["-sV", "-sC", target]},
             "technique": "service-enum", "vector": "tcp"},
            {"thought": "fingerprint the web service found on 80",
             "done": False,
             "command": {"tool": "whatweb", "args": [f"http://{target}"]},
             "technique": "web-fingerprint", "vector": "tcp/80 http"},
            {"thought": "attack surface mapped: ssh + http",
             "done": True, "summary": "scan complete"},
        ]
        self._attack = [
            {"thought": "ssh is open; try credential brute force",
             "done": False,
             "command": {"tool": "hydra",
                         "args": ["-l", "admin", "-P", "wordlist.txt",
                                  f"ssh://{target}"]},
             "technique": "brute-force", "vector": "ssh"},
            {"thought": "valid credentials captured — objective reached",
             "done": True, "summary": "initial access via ssh creds"},
        ]

    def available(self) -> bool:
        return True

    def chat(self, messages: list[dict], *, json_mode: bool = False) -> str:
        system = messages[0]["content"] if messages else ""
        user = messages[-1]["content"] if messages else ""
        if "evaluate the output" in system:
            return json.dumps({"success": True, "summary": "llm-eval",
                               "interesting": [], "findings": [], "loot": []})
        if "attack narrative" in user:
            return ("## Attack narrative\nRecon mapped SSH and HTTP on the "
                    "target; the exploiter validated SSH credentials via "
                    "brute force, proving initial access.")
        if "hostile reviewer" in system or "DISPROVE" in system:
            return json.dumps({"verdict": "confirmed",
                               "reason": "evidence supports the claim"})
        if "advisory chat mode" in user:
            return ("Recommended path: enumerate services, fingerprint the "
                    "web app, then brute-force SSH with hydra.")
        queue = self._attack if "exploitable weaknesses" in user else self._scan
        item = queue.pop(0) if queue else {"done": True,
                                           "summary": "script exhausted"}
        return json.dumps(item)
