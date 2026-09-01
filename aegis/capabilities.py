"""Capability engine — the agentic core.

Every thing Aegis can *do* to a target is a declared Capability with:
  - preconditions (`when`): a predicate over the live engagement state
    (intel, attempt memory, findings, loot)
  - an `execute` function that runs the action and records its own evidence
  - a priority: lower runs earlier

The engine loop is deterministic:
  observe state → pick the highest-priority untried capability whose
  preconditions are met → execute → results land in the DB → rebuild state
  (a confirmed LFI unlocks source-reading; discovered creds unlock
  credential-stuffing) → repeat until nothing applicable remains.

No LLM is required to act: hypothesis generation is the precondition graph,
grounded in what was actually observed. The LLM remains for chat/advisory
and report narrative. Attempt memory is the anti-repeat mechanism: a
capability that has been tried (success OR failure) is not retried, and
follow-up capabilities only appear when prior success changes the state.

Adding a new vuln class = registering one more Capability. No new manual
command, no per-machine patching.
"""

from __future__ import annotations

import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .db import EngagementDB
from .diag import get_logger
from .parsers import evaluate
from .playbook import WEB_PORTS, available_wordlists
from .runner import Runner, RunnerError

log = get_logger("capabilities")


# ---- engagement state --------------------------------------------------------

class TargetState:
    """Snapshot of everything known about one target. Rebuilt each step."""

    def __init__(self, db: EngagementDB, target_id: int, host: str):
        self.db = db
        self.target_id = target_id
        self.host = host
        self.intel = [dict(r) for r in db.intel_for(target_id)]
        self.attempts = [dict(r) for r in db.attempts_for(target_id)]
        self.findings = [dict(r) for r in db.findings_for(target_id)]
        self.loot = [dict(r) for r in db.loot_for(target_id)]

    # -- capabilities tried (attempt memory is the anti-repeat mechanism)
    def tried(self, cap_name: str) -> bool:
        return any(a["technique"] == cap_name for a in self.attempts)

    def succeeded(self, cap_name: str) -> bool:
        return any(a["technique"] == cap_name and a["success"]
                   for a in self.attempts)

    # -- intel queries
    def web_ports(self) -> list[int]:
        ports = set()
        for i in self.intel:
            if i["kind"] != "service":
                continue
            port = i["key"].split("/")[0]
            if not port.isdigit():
                continue
            if re.search(r"http|ssl|www", i["value"].lower()) \
                    or port in WEB_PORTS:
                ports.add(int(port))
        return sorted(ports)

    def has_php(self) -> bool:
        return any("php" in i["value"].lower()
                   for i in self.intel if i["kind"] in ("tech", "web"))

    def login_services(self) -> list[str]:
        out = set()
        for i in self.intel:
            if i["kind"] == "service" and re.search(
                    r"ssh|ftp|mysql|mssql|postgres|smb|rdp|telnet|vnc|pop3|imap",
                    i["value"].lower()):
                out.add(i["value"].split()[0])
        return sorted(out)

    def version_products(self) -> list[str]:
        from .playbook import VERSION_PROD_RE
        out = []
        for i in self.intel:
            if i["kind"] == "service":
                m = VERSION_PROD_RE.search(i["value"])
                if m:
                    out.append(f"{m.group(1)} {m.group(2)}")
        return out

    def verified_finding(self, needle: str) -> dict | None:
        for f in self.findings:
            if f.get("verified") and needle.lower() in (f["title"] or "").lower():
                return f
        return None

    def creds(self) -> list[dict]:
        return [l for l in self.loot if l.get("kind") == "credential"
                and ":" in (l.get("value") or "")]

    def base_url(self, port: int | None = None) -> str:
        port = port or (self.web_ports() or [80])[0]
        scheme = "https" if port in (443, 8443) else "http"
        default = 443 if scheme == "https" else 80
        suffix = "" if port == default else f":{port}"
        return f"{scheme}://{self.host}{suffix}"


# ---- capability declaration --------------------------------------------------

@dataclass
class CapResult:
    success: bool
    summary: str


@dataclass
class Capability:
    name: str                 # unique; recorded as attempt technique
    phase: str                # "recon" (runs in scan+attack) or "attack"
    priority: int             # lower = earlier
    description: str
    when: Callable[[TargetState], bool]
    execute: Callable[["EngineContext", TargetState], CapResult]
    tool: str = ""            # underlying tool — drives ATT&CK tagging


@dataclass
class EngineContext:
    runner: Runner
    db: EngagementDB
    audit: object
    cancel_event: object = None
    agent_name: str = "capability-engine"


def tool_available(tool: str) -> bool:
    return shutil.which(tool) is not None


# ---- shared execution helpers ------------------------------------------------

def _full_output(result) -> str:
    if result.output_file:
        try:
            return Path(result.output_file).read_text(
                encoding="utf-8", errors="replace")[-200_000:]
        except OSError:
            pass
    return result.stdout_tail


def run_tool(ctx: EngineContext, state: TargetState, tool: str,
             args: list[str]) -> CapResult:
    """Execute an allowlisted shell tool through the full safety path and
    fold parser-verified findings/loot into memory."""
    args = [a.replace("{host}", state.host) for a in args]
    try:
        result = ctx.runner.run(tool, args, target_host=state.host,
                                target_id=state.target_id,
                                agent=ctx.agent_name,
                                cancel_event=ctx.cancel_event)
    except RunnerError as exc:
        return CapResult(False, str(exc))
    if result.status == "refused":
        return CapResult(False, f"refused ({result.refusal})")
    verdict = evaluate(tool, _full_output(result))
    if verdict is None:
        ok = result.status == "ok"
        return CapResult(ok, f"{tool} finished (status={result.status})")
    for f in verdict.findings:
        ctx.db.record_finding(state.target_id, f.get("title", "untitled"),
                              f.get("severity", "info"),
                              f.get("description", ""),
                              evidence=result.output_file or "",
                              provenance="tool-proven", verified=1)
    for l in verdict.loot:
        kind = l.get("kind", "note")
        if kind not in ("credential", "hash", "note", "flag"):
            kind = "note"
        ctx.db.record_loot(state.target_id, kind, l.get("title", "loot"),
                           value=l.get("value", ""),
                           source=result.command[:200])
    return CapResult(verdict.success, verdict.summary)


# ---- the default registry ----------------------------------------------------

def default_registry() -> list[Capability]:
    caps: list[Capability] = []

    def cap(name, phase, priority, description, when, tool=""):
        def deco(fn):
            caps.append(Capability(name, phase, priority, description,
                                   when, fn, tool))
            return fn
        return deco

    has_web = lambda s: bool(s.web_ports())

    # ---- recon (runs in scan AND attack mode — attack bootstraps recon) ----

    @cap("recon.tcp-scan", "recon", 10,
         "TCP service scan (nmap -sV -sC)",
         lambda s: tool_available("nmap"), tool="nmap")
    def _tcp(ctx, s):
        return run_tool(ctx, s, "nmap", ["-sV", "-sC", "-Pn", "{host}"])

    @cap("recon.http-headers", "recon", 15,
         "HTTP headers (server / powered-by intel)",
         lambda s: has_web(s) and tool_available("curl"), tool="curl")
    def _hdrs(ctx, s):
        return run_tool(ctx, s, "curl", ["-sI", s.base_url() + "/"])

    @cap("recon.whatweb", "recon", 16,
         "Technology fingerprinting (whatweb)",
         lambda s: has_web(s) and tool_available("whatweb"), tool="whatweb")
    def _whatweb(ctx, s):
        return run_tool(ctx, s, "whatweb", [s.base_url() + "/"])

    @cap("recon.udp-scan", "recon", 40,
         "UDP top-100 service scan",
         lambda s: tool_available("nmap"), tool="nmap")
    def _udp(ctx, s):
        return run_tool(ctx, s, "nmap",
                        ["-sU", "-sV", "-Pn", "--top-ports", "100", "{host}"])

    # ---- attack ----

    @cap("attack.nuclei", "attack", 20,
         "Known-CVE template scan (nuclei)",
         lambda s: has_web(s) and tool_available("nuclei"), tool="nuclei")
    def _nuclei(ctx, s):
        return run_tool(ctx, s, "nuclei", ["-u", s.base_url() + "/"])

    @cap("attack.lfi-probe", "attack", 25,
         "LFI/RFI probe: parameter discovery + traversal + php://filter",
         lambda s: has_web(s), tool="webattack")
    def _lfi(ctx, s):
        from .webattack import WebAttacker
        att = WebAttacker(ctx.db, audit=ctx.audit)
        res = att.probe_lfi(s.base_url() + "/", s.target_id, host=s.host)
        if res.get("error"):
            return CapResult(False, res["error"])
        if not res["vulnerable"]:
            return CapResult(False, f"no LFI ({res['probes']} probes)")
        return CapResult(True, f"LFI CONFIRMED via '{res['param']}' — "
                               f"{res['evidence']}")

    @cap("attack.lfi-source-read", "attack", 26,
         "Post-LFI: read application source via php://filter → loot",
         lambda s: s.verified_finding("Local File Inclusion") is not None)
    def _lfi_src(ctx, s):
        from .webattack import WebAttacker
        finding = s.verified_finding("Local File Inclusion")
        m = re.search(r"[?&]([^=&]+)=", finding.get("evidence") or "")
        if not m:
            return CapResult(False, "could not recover vulnerable parameter "
                                    "from finding evidence")
        page = (finding["evidence"] or "").split("?")[0]
        att = WebAttacker(ctx.db, audit=ctx.audit)
        res = att.read_sources(page, m.group(1), s.target_id)
        return CapResult(bool(res["files"]),
                         res["summary"])

    def _probe(ctx, s, method: str, label: str, max_probes: int = 400):
        """Shared adapter: run a webattack probe, translate to CapResult."""
        from .webattack import WebAttacker
        att = WebAttacker(ctx.db, audit=ctx.audit, max_probes=max_probes)
        res = getattr(att, method)(s.base_url() + "/", s.target_id,
                                   host=s.host)
        if res.get("error"):
            return CapResult(False, res["error"])
        if not res["vulnerable"]:
            return CapResult(False, f"no {label} ({res['probes']} probes)")
        return CapResult(True, f"{label} CONFIRMED via '{res['param']}' — "
                               f"{res['evidence']}")

    @cap("attack.sqli-probe", "attack", 22,
         "SQL injection probe: error-based, boolean-blind, time-based",
         lambda s: has_web(s), tool="webattack")
    def _sqli(ctx, s):
        return _probe(ctx, s, "probe_sqli", "SQLi")

    @cap("attack.cmdi-probe", "attack", 27,
         "OS command injection probe (id/whoami execution signatures)",
         lambda s: has_web(s), tool="webattack")
    def _cmdi(ctx, s):
        return _probe(ctx, s, "probe_cmdi", "command injection")

    @cap("attack.ssti-probe", "attack", 28,
         "SSTI probe (template-engine arithmetic canaries)",
         lambda s: has_web(s), tool="webattack")
    def _ssti(ctx, s):
        return _probe(ctx, s, "probe_ssti", "SSTI")

    @cap("attack.xss-probe", "attack", 30,
         "Reflected XSS probe (unescaped-metacharacter canary)",
         lambda s: has_web(s), tool="webattack")
    def _xss(ctx, s):
        return _probe(ctx, s, "probe_xss", "XSS")

    @cap("attack.dir-bruteforce", "attack", 35,
         "Directory brute-force (gobuster/dirb + on-disk wordlist)",
         lambda s: has_web(s) and (
             tool_available("gobuster") or tool_available("dirb"))
         and bool(available_wordlists().get("web-dirs")), tool="gobuster")
    def _dirs(ctx, s):
        wl = available_wordlists()["web-dirs"]
        if tool_available("gobuster"):
            return run_tool(ctx, s, "gobuster",
                            ["dir", "-u", s.base_url() + "/", "-w", wl, "-q"])
        return run_tool(ctx, s, "dirb", [s.base_url() + "/", wl])

    @cap("attack.version-research", "attack", 50,
         "searchsploit exploit research against detected versions",
         lambda s: bool(s.version_products()) and tool_available("searchsploit"),
         tool="searchsploit")
    def _versions(ctx, s):
        hits = []
        for product in s.version_products()[:5]:
            r = run_tool(ctx, s, "searchsploit", [product])
            if r.success and "No Results" not in r.summary:
                hits.append(product)
        return CapResult(bool(hits),
                         f"exploit-db hits for: {', '.join(hits)}"
                         if hits else "no public exploits for detected versions")

    DEFAULT_USERS = ["admin", "root", "administrator", "user", "test"]
    DEFAULT_PASSWORDS = ["admin", "password", "123456", "root", "test",
                         "changeme", "letmein", "admin123"]

    @cap("attack.default-creds", "attack", 55,
         "default/common credential check on login services (hydra)",
         lambda s: bool(s.login_services()) and tool_available("hydra"),
         tool="hydra")
    def _default_creds(ctx, s):
        outdir = Path(ctx.runner.output_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        users = outdir / "default-users.txt"
        pwds = outdir / "default-passwords.txt"
        users.write_text("\n".join(DEFAULT_USERS) + "\n")
        pwds.write_text("\n".join(DEFAULT_PASSWORDS) + "\n")
        svc = s.login_services()[0]
        return run_tool(ctx, s, "hydra",
                        ["-L", str(users), "-P", str(pwds), "{host}", svc])

    @cap("attack.cred-stuffing", "attack", 60,
         "Replay looted credentials against discovered login services (hydra)",
         lambda s: bool(s.creds()) and bool(s.login_services())
         and tool_available("hydra"), tool="hydra")
    def _stuff(ctx, s):
        # secrets go in a combo FILE, never on the command line — argv lands
        # in the action log, output capture, and reports.
        outdir = Path(ctx.runner.output_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        combo = outdir / "loot-combo.txt"
        combo.write_text("\n".join(c["value"] for c in s.creds()[:5]) + "\n")
        svc = s.login_services()[0]
        return run_tool(ctx, s, "hydra", ["-C", str(combo), "{host}", svc])

    return caps


# ---- the engine ---------------------------------------------------------------

class CapabilityEngine:
    """Observe → hypothesize (precondition graph) → act → learn. Deterministic."""

    def __init__(self, runner: Runner, db: EngagementDB, audit, scope,
                 max_steps: int = 30, time_budget_min: int = 45,
                 registry: list[Capability] | None = None):
        self.runner = runner
        self.db = db
        self.audit = audit
        self.scope = scope
        self.max_steps = max_steps
        self.time_budget_min = time_budget_min
        self.registry = registry if registry is not None else default_registry()

    def _candidates(self, state: TargetState, mode: str) -> list[Capability]:
        out = []
        for c in self.registry:
            if c.phase == "attack" and mode != "attack":
                continue
            if state.tried(c.name):
                continue
            try:
                if c.when(state):
                    out.append(c)
            except Exception as exc:  # a bad predicate must never kill the loop
                log.error("precondition failed for %s: %s", c.name, exc)
        out.sort(key=lambda c: c.priority)
        return out

    def run(self, mode: str, host: str, *, on_step=None,
            cancel_event=None) -> dict:
        """mode: 'scan' (recon capabilities) or 'attack' (recon + attack)."""
        self.scope.check(host)  # raises ScopeError — callers handle it
        row = self.db.get_target(host) or self.db.get_target(
            self.db.add_target(host))
        target_id = row["id"]
        self.db.set_target_status(target_id, f"{mode}ing")
        self.audit.log(f"{mode}-agent", "engine", "start",
                       {"host": host, "mode": mode})

        ctx = EngineContext(self.runner, self.db, self.audit,
                            cancel_event=cancel_event,
                            agent_name=f"{mode}-agent")
        started = time.time()
        transcript: list[dict] = []

        for step in range(1, self.max_steps + 1):
            if cancel_event is not None and cancel_event.is_set():
                transcript.append({"step": step, "done": True,
                                   "summary": "cancelled by operator"})
                self.db.set_target_status(target_id, "cancelled")
                break
            if (time.time() - started) / 60 > self.time_budget_min:
                transcript.append({"step": step, "done": True,
                                   "summary": "time budget reached"})
                break

            state = TargetState(self.db, target_id, row["host"])
            candidates = self._candidates(state, mode)
            if not candidates:
                transcript.append({"step": step, "done": True,
                                   "summary": "no applicable capabilities "
                                              "remain — engagement exhausted"})
                break
            capability = candidates[0]

            event = {"step": step, "capability": capability.name,
                     "command": f"[{capability.name}] {capability.description}",
                     "thought": "preconditions met, untried, highest priority"}
            if on_step:
                on_step({**event, "phase": "planned"})
            log.warning("step %s: %s — %s", step, capability.name,
                        capability.description)

            try:
                result = capability.execute(ctx, state)
            except Exception as exc:
                log.exception("capability %s raised", capability.name)
                result = CapResult(False, f"capability error: {exc}")

            # attempt memory — this is what makes the next iteration smarter
            from .attack_map import tag_attempt
            attack_id, _ = tag_attempt(capability.name, capability.phase,
                                       capability.tool)
            self.db.record_attempt(target_id, capability.name,
                                   capability.phase, capability.description,
                                   result.summary, result.success,
                                   attack_id=attack_id)
            # learning loop: proven attacks become draft KB rules for review
            if result.success and mode == "attack":
                try:
                    from .playbook import learn_from_success
                    draft = learn_from_success(
                        self.db, target_id, capability.name, capability.phase,
                        "engine", capability.description, row["host"])
                    if draft:
                        self.audit.log(f"{mode}-agent", "playbook",
                                       "draft_rule",
                                       {"pattern": draft["pattern"],
                                        "technique": capability.name})
                except Exception as exc:
                    log.error("learning hook failed: %s", exc)

            event.update({"phase": "observed", "success": result.success,
                          "evaluation": result.summary})
            transcript.append(event)
            if on_step:
                on_step(event)

        self.db.set_target_status(target_id, f"{mode}-done")
        self.audit.log(f"{mode}-agent", "engine", "finish",
                       {"host": host, "mode": mode, "steps": len(transcript)})
        return {"target": row["host"], "mode": mode, "transcript": transcript}
