"""Agentic scan & attack loops.

Each agent runs a plan → act → observe → adapt loop:
  1. The LLM planner sees the full engagement memory for the target.
  2. It proposes the *next single command* as structured JSON.
  3. The runner executes it (scope-gated, allowlisted, audited).
  4. The LLM evaluates the output: success? findings? what did we learn?
  5. That verdict is written to memory and feeds the next planning step —
     so failed approaches are not blindly repeated.
"""

from __future__ import annotations

import json

from .db import EngagementDB
from .diag import get_logger
from .llm import LLMClient, LLMError
from .runner import Runner, RunnerError

log = get_logger("agent")

SYSTEM = """You are Aegis, an autonomous penetration-testing agent operating under a
signed, written authorization limited to the declared engagement scope.
You plan and execute CLI security tools on Kali Linux against ONE in-scope target.

Rules you must follow:
- Propose exactly ONE command per step.
- Use only tools from this allowlist: {tools}
- Never propose a command against any host other than the given target.
- Prefer low-noise actions first; escalate deliberately.
- Study the memory carefully: do not repeat a technique that already failed
  unless you have a concrete reason to believe a modification makes it viable.
- When you have enough results, or nothing promising remains, stop.

Reply ONLY with JSON:
{{
  "thought": "brief reasoning, referencing memory",
  "done": false,
  "command": {{"tool": "nmap", "args": ["-sV", "-sC", "<target>"]}},
  "technique": "short label e.g. service-enum",
  "vector": "port/protocol/entry point e.g. tcp/80 http"
}}
or, when finished:
{{"thought": "why we stop", "done": true, "summary": "what was accomplished"}}
"""

EVAL_SYSTEM = """You evaluate the output of a security tool run during an authorized
penetration test. Reply ONLY with JSON:
{{
  "success": true/false,           // did the action achieve its goal?
  "summary": "one sentence",
  "interesting": ["notable line", ...],   // up to 5
  "findings": [{{"title": "...", "severity": "info|low|medium|high|critical",
                 "description": "...", "cvss": "CVSS:3.1/... or empty",
                 "remediation": "how to fix, or empty"}}],   // may be empty
  "loot": [{{"kind": "credential|hash|note", "title": "...",
             "value": "user:pass / hash / note text"}}]      // may be empty
}}
"""

SCAN_BRIEF = """Goal: reconnaissance and enumeration of {target}.
Enumerate ports, services, versions, and obvious low-hanging fruit. Build a
picture of the attack surface. Do NOT attempt exploitation."""

ATTACK_BRIEF = """Goal: identify and validate exploitable weaknesses on {target},
based on everything in memory (scans, OSINT, prior attempts).
Adapt after every failure. Validate exploits carefully and record evidence.
Stay strictly on this target."""


class Agent:
    def __init__(self, llm: LLMClient, runner: Runner, db: EngagementDB,
                 max_steps: int = 25, time_budget_min: int = 45):
        self.llm = llm
        self.runner = runner
        self.db = db
        self.max_steps = max_steps
        self.time_budget_min = time_budget_min

    def _plan(self, brief: str, target: str, target_id: int) -> dict:
        from .attack_map import coverage, planner_gap_hint
        memory = self.db.memory_summary(target_id)
        gap_hint = planner_gap_hint(coverage(self.db, target_id))
        tools = ", ".join(sorted(self.runner.allowed_tools))
        messages = [
            {"role": "system", "content": SYSTEM.format(tools=tools)},
            {"role": "user", "content":
                f"{brief}\n\nTarget: {target}\n\n{gap_hint}\n\n"
                f"Memory so far:\n{memory}"},
        ]
        raw = self.llm.chat(messages, json_mode=True)
        return self._parse_json(raw)

    def _assess(self, tool: str, command: str, output: str) -> dict:
        """Deterministic parser verdict first (ground truth); LLM only when
        the parser is inconclusive. Parser wins on success/loot/findings."""
        from .parsers import evaluate
        verdict = evaluate(tool, output)
        if verdict is not None:
            return {"success": verdict.success, "summary": verdict.summary,
                    "interesting": [], "findings": verdict.findings,
                    "loot": verdict.loot, "source": "parser"}
        evaluation = self._evaluate(command, output)
        evaluation["source"] = "llm"
        return evaluation

    def _evaluate(self, command: str, output: str) -> dict:
        messages = [
            {"role": "system", "content": EVAL_SYSTEM},
            {"role": "user", "content": f"Command: {command}\nOutput (tail):\n{output}"},
        ]
        try:
            raw = self.llm.chat(messages, json_mode=True)
            return self._parse_json(raw)
        except LLMError:
            return {"success": False, "summary": "evaluation unavailable",
                    "interesting": [], "findings": []}

    @staticmethod
    def _parse_json(raw: str) -> dict:
        text = raw.strip()
        if text.startswith("```"):
            text = text.strip("`").removeprefix("json").strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    pass
        return {"thought": "planner returned unparseable output", "done": True,
                "summary": text[:300]}

    @staticmethod
    def _full_output(result) -> str:
        """Prefer the complete captured output file over the 40-line tail."""
        if result.output_file:
            try:
                from pathlib import Path
                text = Path(result.output_file).read_text(
                    encoding="utf-8", errors="replace")
                return text[-200_000:]
            except OSError:
                pass
        return result.stdout_tail

    def run(self, mode: str, target: str, *, on_step=None) -> dict:
        """Run an agent loop. mode: 'scan' | 'attack'. on_step(dict) callback."""
        target_row = self.db.get_target(target) or self.db.add_target(target) \
            and self.db.get_target(target)
        target_id = target_row["id"]
        brief = SCAN_BRIEF if mode == "scan" else ATTACK_BRIEF
        brief = brief.format(target=target_row["host"])
        self.db.set_target_status(target_id, f"{mode}ing")

        import time as _time
        started = _time.time()
        seen_commands: set[str] = set()
        repeats = 0
        steps, transcript = [], []
        for step in range(1, self.max_steps + 1):
            # time budget circuit breaker
            if (_time.time() - started) / 60 > self.time_budget_min:
                transcript.append({"step": step, "done": True,
                                   "summary": f"time budget of "
                                              f"{self.time_budget_min} min reached"})
                break
            try:
                plan = self._plan(brief, target_row["host"], target_id)
            except LLMError as exc:
                log.error("planner failed at step %s: %s", step, exc)
                transcript.append({"step": step, "error": str(exc)})
                break

            if plan.get("done"):
                transcript.append({"step": step, "done": True,
                                   "summary": plan.get("summary", "")})
                break

            cmd = plan.get("command") or {}
            tool, args = cmd.get("tool", ""), [str(a) for a in cmd.get("args", [])]
            technique = plan.get("technique", mode)
            vector = plan.get("vector", "")

            # duplicate-command circuit breaker (normalized)
            norm = f"{tool} {' '.join(sorted(args))}"
            if norm in seen_commands:
                repeats += 1
                log.warning("planner repeated command (x%s): %s", repeats, norm)
                event = {"step": step, "phase": "skipped",
                         "command": norm,
                         "error": f"duplicate command (repeat #{repeats}) — "
                                  f"planner must choose a different action"}
                transcript.append(event)
                if on_step:
                    on_step({**event, "phase": "error"})
                if repeats >= 3:
                    transcript.append({"step": step, "done": True,
                                       "summary": "stopped: planner stuck "
                                                  "repeating commands"})
                    break
                continue
            seen_commands.add(norm)

            event = {"step": step, "thought": plan.get("thought", ""),
                     "command": f"{tool} {' '.join(args)}"}
            if on_step:
                on_step({**event, "phase": "planned"})

            if not tool:
                event["error"] = "planner gave empty command"
                transcript.append(event)
                continue

            try:
                result = self.runner.run(tool, args, target_host=target_row["host"],
                                         target_id=target_id, agent=f"{mode}-agent")
            except RunnerError as exc:
                event["error"] = str(exc)
                transcript.append(event)
                if on_step:
                    on_step({**event, "phase": "error"})
                continue

            evaluation = self._assess(tool, result.command,
                                      self._full_output(result))
            log.debug("step %s %s: status=%s source=%s success=%s",
                      step, tool, result.status,
                      evaluation.get("source"), evaluation.get("success"))
            success = bool(evaluation.get("success"))
            from .attack_map import tag_attempt
            attack_id, _tactic = tag_attempt(technique, vector, tool)
            self.db.record_attempt(target_id, technique, vector, result.command,
                                   evaluation.get("summary", ""), success,
                                   evidence=result.output_file or "",
                                   attack_id=attack_id)
            provenance = "tool-proven" if evaluation.get("source") == "parser" \
                else "model-asserted"
            for f in evaluation.get("findings", []):
                self.db.record_finding(target_id, f.get("title", "untitled"),
                                       f.get("severity", "info"),
                                       f.get("description", ""),
                                       evidence=result.output_file or "",
                                       cvss=f.get("cvss", ""),
                                       remediation=f.get("remediation", ""),
                                       attack_id=attack_id,
                                       provenance=provenance,
                                       verified=provenance == "tool-proven")
            for l in evaluation.get("loot", []):
                kind = l.get("kind", "note")
                if kind not in ("credential", "hash", "note"):
                    kind = "note"
                self.db.record_loot(target_id, kind, l.get("title", "loot"),
                                    value=l.get("value", ""),
                                    source=result.command[:200])

            event.update({"phase": "observed", "status": result.status,
                          "success": success,
                          "evaluation": evaluation.get("summary", "")})
            transcript.append(event)
            if on_step:
                on_step(event)

            if result.status == "refused":
                break  # scope refusal — stop, do not fight the gate

        self.db.set_target_status(target_id, f"{mode}-done")
        return {"target": target_row["host"], "mode": mode, "transcript": transcript}

    def advise(self, target: str, question: str) -> str:
        """Chat about a target: answer using full engagement memory."""
        row = self.db.get_target(target)
        memory = self.db.memory_summary(row["id"]) if row else "(target not in DB yet)"
        tools = ", ".join(sorted(self.runner.allowed_tools))
        messages = [
            {"role": "system", "content": SYSTEM.format(tools=tools)},
            {"role": "user", "content":
                "You are in advisory chat mode — answer the operator's question "
                "about attack strategy for this target using the memory below. "
                "Be concrete: name tools, commands, and why.\n\n"
                f"Target: {target}\n\nMemory:\n{memory}\n\n"
                f"Operator: {question}"},
        ]
        return self.llm.chat(messages)
