"""Interactive Aegis shell — chat with the planner or drive agents directly."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from .agent import Agent
from .attack_map import coverage, render_coverage
from .audit import AuditLog
from .dashboard import DashboardServer
from .db import EngagementDB
from .diff import diff_engagements
from .llm import LLMClient, LLMError
from .loot import LootVault
from .msf import MetasploitRPC, MsfError
from .opsec import OpsecProfile
from .osint import OSINTCollector, render_osint_summary
from .parallel import ParallelRunner
from .postex import PostEx
from .report import ReportGenerator
from .runner import Runner, RunnerError
from .scope import ScopeError, ScopeGate
from .webattack import WebAttacker
from .webvuln import WebVulnPipeline

BANNER = r"""
   __                  _
  /  \  ___  ___ _ _  (_)___
 | ▓▓ |/ _ \/ _ `/ / / (_-<
 | __ |  __/ (_| | V V / __/
 |_||_|\___|\__, |\_/|_/___/
           |___/  Workbench v0.1 — authorized use only
"""

HELP = """
Commands:
  /target add <host> [desc]   add an in-scope target
  /target list                list targets
  /osint <host>               pull & display OSINT for a target
  /scan <host>                start autonomous scan agent
  /attack <host>              start autonomous attack agent (asks to confirm)
  /parallel <mode> <h1> <h2>… run one agent per host in parallel
  /mission <host> [--no-exploit]  full operator chain: recon → exploiter → analyst
  /refute <host>              adversarial re-verification of LLM-claimed findings
  /disclose <finding-id>      draft a HackerOne-style disclosure (you send it)
  /run <tool> [args...]       run one allowlisted tool against scope
  /findings [host]            show recorded findings
  /attempts <host>            show attack attempt memory
  /loot [host]                show the loot vault (creds, hashes, files)
  /loot show <id>             view full loot content (decrypted)
  /authorize <host> [label]   add host/CIDR to authorization.json scope
  /missions                   list running/finished missions
  /stop <id|all>              stop a running mission / kill all processes
  /hashes <outfile>           export captured hashes for john/hashcat
  /kb [add <group> <pat> <hint>]  list/add playbook knowledge-base rules
  /kb promote|dismiss <n>     review auto-learned rule drafts
  /map [host]                 MITRE ATT&CK coverage heatmap
  /webvuln <host>             web pipeline: discover HTTP + nuclei scan
  /lfi <url>                  LFI/RFI probe (param discovery + traversal)
  /privesc <host>             privesc research (searchsploit vs. memory)
  /lateral <host>             find & scope-check lateral movement candidates
  /msf <module> <host>        run a Metasploit exploit via msfrpcd
  /opsec <normal|stealth|paranoid>  set OPSEC profile
  /proxy on|off               toggle proxychains wrapping
  /vpn                        show VPN interface status
  /dashboard [port]           start live web dashboard (127.0.0.1)
  /diff <other.db>            diff another engagement DB against this one
  /doctor                     environment health check (tools, LLM, crypto…)
  /logs [n]                   show last n warnings/errors from the debug log
  /report <name>              generate pentest report (MD + HTML)
  /verify-audit               verify audit-chain integrity
  /help                       this help
  /quit                       exit
Anything else is sent to the planner as chat (ask about attack strategy).
"""


class Shell:
    def __init__(self, config: dict):
        self.console = Console()
        paths = config.get("paths", {})
        from .diag import get_logger, setup_logging
        self.debug_log = setup_logging(paths.get("logs_dir", "logs"))
        self.log = get_logger("cli")
        self.db = EngagementDB(paths.get("db", "engagement.db"))
        self.audit = AuditLog(paths.get("logs_dir", "logs"))
        self.scope = ScopeGate(paths.get("authorization", "authorization.json"))
        self.runner = Runner(config, self.db, self.audit, self.scope)
        self.llm = LLMClient(config)
        self.agent = Agent(self.llm, self.runner, self.db,
                           max_steps=config.get("agent", {}).get("max_steps", 25),
                           time_budget_min=config.get("agent", {})
                           .get("time_budget_minutes", 45))
        self.osint = OSINTCollector(self.runner, self.db)
        # v0.3 hardening: command guard + loot encryption
        from .crypto import LootCipher
        from .guard import CommandGuard
        self.cipher = LootCipher(".")
        self.db.cipher = self.cipher
        self.guard = CommandGuard(self.scope, ".")
        self.runner.guard = self.guard
        self.loot = LootVault(self.db, self.runner,
                              paths.get("loot_dir", "loot"))
        self.webvuln = WebVulnPipeline(self.runner, self.db)
        self.postex = PostEx(self.runner, self.db, self.scope)
        self.msf = MetasploitRPC(config)
        from .capabilities import CapabilityEngine
        from .disclosure import DisclosurePipeline
        from .operators import Coordinator
        from .provenance import Refuter
        self.refuter = Refuter(self.llm, self.db)
        self.engine = CapabilityEngine(
            self.runner, self.db, self.audit, self.scope,
            max_steps=config.get("agent", {}).get("max_steps", 30),
            time_budget_min=config.get("agent", {})
            .get("time_budget_minutes", 45))
        self.parallel = ParallelRunner(self.engine)
        self.coordinator = Coordinator(self.engine, self.db, self.refuter,
                                       llm=self.llm)
        self.disclosure = DisclosurePipeline(
            self.db, paths.get("disclosures_dir", "disclosures"))
        self.dashboard: DashboardServer | None = None
        self.opsec = OpsecProfile(config.get("opsec", {}).get("level", "normal"))
        self.runner.opsec = self.opsec
        self.config = config
        self.audit.log("operator", "session", "start",
                       {"engagement": self.scope.engagement})

    # ---- helpers --------------------------------------------------------
    def _target_or_print(self, host):
        row = self.db.get_target(host)
        if not row:
            self.console.print(f"[yellow]Unknown target '{host}' — adding it.[/]")
            tid = self.db.add_target(host)
            row = self.db.get_target(tid)
        return row

    def _on_step(self, event: dict) -> None:
        phase = event.get("phase")
        if phase == "planned":
            self.console.print(f"[cyan]step {event['step']}[/] {event['thought']}")
            self.console.print(f"  [bold]$ {event['command']}[/]")
        elif phase == "error":
            self.console.print(f"  [red]error: {event['error']}[/]")
        else:
            mark = "✅" if event.get("success") else "❌"
            self.console.print(f"  {mark} [{event['status']}] {event['evaluation']}")

    # ---- command handlers ------------------------------------------------
    def cmd_target(self, args):
        if len(args) >= 2 and args[0] == "add":
            host = args[1]
            try:
                self.scope.check(host)
            except ScopeError as exc:
                self.console.print(f"[red]{exc}[/]")
                return
            desc = " ".join(args[2:])
            self.db.add_target(host, desc)
            self.audit.log("operator", "target", "add", {"host": host, "desc": desc})
            self.console.print(f"[green]Target added:[/] {host}")
        else:
            table = Table(title="Targets")
            for col in ("id", "host", "status", "description"):
                table.add_column(col)
            for t in self.db.list_targets():
                table.add_row(str(t["id"]), t["host"], t["status"], t["description"])
            self.console.print(table)

    def cmd_osint(self, args):
        if not args:
            return self.console.print("[red]usage: /osint <host>[/]")
        host = args[0]
        try:
            self.scope.check(host)
        except ScopeError as exc:
            return self.console.print(f"[red]{exc}[/]")
        row = self._target_or_print(host)
        with self.console.status(f"Collecting OSINT for {host}…"):
            data = self.osint.collect(row["host"], row["id"])
        self.console.print(render_osint_summary(data))

    def cmd_agent(self, mode, args):
        if not args:
            return self.console.print(f"[red]usage: /{mode} <host>[/]")
        host = args[0]
        try:
            self.scope.check(host)
        except ScopeError as exc:
            return self.console.print(f"[red]{exc}[/]")
        if mode == "attack" and self.config.get("agent", {}).get(
                "auto_attack_requires_confirmation", True):
            ans = input(f"Launch autonomous ATTACK agent on {host}? "
                        "Confirm you are authorized [yes/NO]: ")
            if ans.strip().lower() != "yes":
                return self.console.print("[yellow]Aborted by operator.[/]")
        self.console.print(f"[bold magenta]Starting {mode} engine on {host}[/] "
                           "(capability-driven: observe → hypothesize → act)")
        result = self.engine.run(mode, host, on_step=self._on_step)
        n = len(result["transcript"])
        self.console.print(f"[green]{mode} engine finished after {n} steps.[/]")

    def cmd_run(self, args):
        if not args:
            return self.console.print("[red]usage: /run <tool> [args...][/]")
        tool, targs = args[0], args[1:]
        host = next((a for a in targs if not a.startswith("-")), None)
        try:
            result = self.runner.run(tool, targs, target_host=host, agent="operator")
            self.console.print(f"[bold]{result.status}[/] exit={result.exit_code} "
                               f"({result.duration:.1f}s) → {result.output_file}")
            if result.stdout_tail:
                from rich.markup import escape
                self.console.print(escape(result.stdout_tail))
        except RunnerError as exc:
            self.console.print(f"[red]{exc}[/]")

    def _quick_run_handler(self, host: str, command: str):
        """War Room one-click: run an extracted hint command through the full
        runner path (allowlist → guard → scope → audit) in the background."""
        import shlex
        import threading
        from .diag import get_logger
        log = get_logger("war-room")

        def work():
            try:
                parts = shlex.split(command)
                if not parts:
                    return
                tool, targs = parts[0], parts[1:]
                row = self.db.get_target(host)
                tid = row["id"] if row else self.db.add_target(host)
                result = self.runner.run(tool, targs, target_host=host,
                                         target_id=tid, agent="war-room")
                log.info("one-click %s: %s (exit %s)",
                         result.status, command, result.exit_code)
            except (RunnerError, ValueError) as exc:
                log.warning("one-click failed: %s — %s", command, exc)

        threading.Thread(target=work, daemon=True).start()

    def cmd_findings(self, args):
        row = self.db.get_target(args[0]) if args else None
        findings = self.db.findings_for(row["id"]) if row else self.db.findings_for()
        table = Table(title="Findings")
        for col in ("id", "severity", "title", "status"):
            table.add_column(col)
        for f in findings:
            table.add_row(str(f["id"]), f["severity"], f["title"], f["status"])
        self.console.print(table)

    def cmd_attempts(self, args):
        if not args:
            return self.console.print("[red]usage: /attempts <host>[/]")
        row = self.db.get_target(args[0])
        if not row:
            return self.console.print("[red]unknown target[/]")
        table = Table(title=f"Attempt memory — {row['host']}")
        for col in ("ok", "technique", "vector", "result"):
            table.add_column(col)
        for a in self.db.attempts_for(row["id"]):
            table.add_row("✅" if a["success"] else "❌", a["technique"],
                          a["vector"], (a["result"] or "")[:80])
        self.console.print(table)

    def cmd_report(self, args):
        name = args[0] if args else self.scope.engagement
        include_secrets = bool(self.config.get("report", {})
                               .get("include_secrets", False))
        gen = ReportGenerator(self.db, name, self.config.get("paths", {})
                              .get("reports_dir", "reports"),
                              include_secrets=include_secrets)
        md = gen.build_markdown()
        html = gen.build_html(md)
        self.audit.log("operator", "report", "generated",
                       {"md": str(md), "html": str(html),
                        "include_secrets": include_secrets})
        note = "" if include_secrets else " (secrets redacted)"
        self.console.print(f"[green]Report written{note}:[/]\n  {md}\n  {html}")

    def cmd_verify_audit(self):
        for p in sorted(Path(self.config.get("paths", {}).get("logs_dir", "logs"))
                        .glob("audit-*.jsonl")):
            ok, msg = AuditLog.verify(p)
            color = "green" if ok else "red"
            self.console.print(f"[{color}]{p.name}: {msg}[/]")

    # ---- v0.2 handlers ---------------------------------------------------
    def _scoped_target(self, host: str):
        """Scope-check + resolve target row, printing errors. None on failure."""
        try:
            self.scope.check(host)
        except ScopeError as exc:
            self.console.print(f"[red]{exc}[/]")
            return None
        return self._target_or_print(host)

    def cmd_loot(self, args):
        if args and args[0] == "show":
            if len(args) > 1 and args[1].isdigit():
                return self.cmd_loot_show(int(args[1]))
            return self.console.print("[red]usage: /loot show <id>[/]")
        row = self.db.get_target(args[0]) if args else None
        items = self.db.loot_for(row["id"]) if row else self.db.loot_for()
        table = Table(title="Loot vault")
        for col in ("id", "kind", "title", "value / file", "source"):
            table.add_column(col)
        for l in items:
            table.add_row(str(l["id"]), l["kind"], l["title"],
                          (l["value"] or l["file_path"])[:70], l["source"][:40])
        self.console.print(table)

    def cmd_hashes(self, args):
        if not args:
            return self.console.print("[red]usage: /hashes <outfile>[/]")
        out = self.loot.export_hashes(args[0])
        n = len(out.read_text(encoding="utf-8").split())
        self.console.print(f"[green]{n} hashes exported → {out}[/] "
                           f"(feed to john or hashcat)")

    def cmd_map(self, args):
        row = self.db.get_target(args[0]) if args else None
        cov = coverage(self.db, row["id"] if row else None)
        self.console.print("```\n" + render_coverage(cov) + "\n```")

    def cmd_webvuln(self, args):
        if not args:
            return self.console.print("[red]usage: /webvuln <host>[/]")
        row = self._scoped_target(args[0])
        if not row:
            return
        with self.console.status(f"Web pipeline on {row['host']}…"):
            result = self.webvuln.run(row["host"], row["id"])
        self.console.print(f"Web services: {result['web_services'] or 'none found'}")
        self.console.print(f"[green]{result['findings']} nuclei findings recorded.[/]")
        for e in result["errors"]:
            self.console.print(f"[yellow]{e}[/]")

    def cmd_privesc(self, args):
        if not args:
            return self.console.print("[red]usage: /privesc <host>[/]")
        row = self._scoped_target(args[0])
        if not row:
            return
        with self.console.status("Researching privesc paths…"):
            results = self.postex.privesc_check(row["id"], row["host"])
        if not results:
            return self.console.print("[yellow]No version candidates in memory — "
                                      "run /scan first.[/]")
        for r in results:
            self.console.print(f"[bold]{r['query']}[/]")
            for h in r["hits"]:
                self.console.print(f"  {h}")

    def cmd_lfi(self, args):
        if not args:
            return self.console.print("[red]usage: /lfi <url>[/]")
        url = args[0]
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        host = urlparse(url).hostname
        if not host:
            return self.console.print(f"[red]Cannot parse host from '{url}'[/]")
        row = self._scoped_target(host)
        if not row:
            return
        attacker = WebAttacker(self.db, audit=self.audit)
        with self.console.status(f"Probing {url} for LFI (discovering "
                                 "parameters, traversal payloads)…"):
            result = attacker.probe_lfi(url, row["id"], host=host)
        if result.get("error"):
            return self.console.print(f"[yellow]{result['error']}[/]")
        if not result["vulnerable"]:
            return self.console.print(
                f"[green]No LFI found[/] ({result['probes']} probes). "
                "If the app uses JS-rendered links, pass a URL with the "
                "parameter directly: /lfi 'http://host/index.php?page=1'")
        self.console.print(f"[bold red]LFI CONFIRMED[/] — "
                           f"param '{result['param']}'")
        self.console.print(f"  payload : {result['payload']}")
        self.console.print(f"  evidence: {result['evidence']}")
        self.console.print(f"  finding #{result['finding_id']} recorded "
                           "(verified, tool-proven)")
        self.console.print(f"\n[bold]Next steps:[/] {result['next_steps']}")

    def cmd_lateral(self, args):
        if not args:
            return self.console.print("[red]usage: /lateral <host>[/]")
        row = self._scoped_target(args[0])
        if not row:
            return
        found = self.postex.lateral_candidates(row["id"])
        self.console.print(f"[green]Queued (in scope):[/] {found['queued'] or 'none'}")
        self.console.print(f"[red]Out of scope (refused):[/] "
                           f"{found['out_of_scope'] or 'none'}")
        creds = self.postex.credentials_for_lateral()
        if creds:
            self.console.print("[bold]Looted credentials usable for lateral "
                               "movement:[/]")
            for c in creds:
                self.console.print(f"  🔑 {c['title']}: {c['value']}")

    def cmd_msf(self, args):
        if len(args) < 2:
            return self.console.print("[red]usage: /msf <exploit-module> <host> "
                                      "[payload][/]")
        module, host = args[0], args[1]
        payload = args[2] if len(args) > 2 else ""
        row = self._scoped_target(host)
        if not row:
            return
        if not self.msf.available():
            return self.console.print("[red]msfrpcd not reachable — start it with: "
                                      "msfrpcd -P <pass> -S -a 127.0.0.1[/]")
        ans = input(f"Execute {module} against {host}? Confirm authorization "
                    "[yes/NO]: ")
        if ans.strip().lower() != "yes":
            return self.console.print("[yellow]Aborted.[/]")
        try:
            resp = self.msf.run_exploit(module, host, payload)
            self.console.print(f"[green]msf job:[/] {resp}")
            self.db.record_attempt(row["id"], "msf-exploit", module, module,
                                   str(resp)[:300], "job_id" in resp,
                                   attack_id="T1059")
            self.audit.log("operator", "msf", "exploit",
                           {"module": module, "host": host, "resp": str(resp)[:500]})
        except MsfError as exc:
            self.console.print(f"[red]{exc}[/]")

    def cmd_opsec(self, args):
        if args:
            self.opsec = OpsecProfile(args[0])
            self.runner.opsec = self.opsec
            self.audit.log("operator", "opsec", "level", {"level": self.opsec.level})
        enforce = "proxychains enforced" if self.opsec.enforce_proxy else "proxy optional"
        self.console.print(f"OPSEC level: [bold]{self.opsec.level}[/] ({enforce})")

    def cmd_parallel(self, args):
        if len(args) < 2:
            return self.console.print("[red]usage: /parallel <scan|attack> "
                                      "<host1> <host2> …[/]")
        mode, hosts = args[0], args[1:]
        if mode not in ("scan", "attack"):
            return self.console.print("[red]mode must be scan or attack[/]")
        jobs = []
        for h in hosts:
            try:
                self.scope.check(h)
                jobs.append((mode, h))
            except ScopeError as exc:
                self.console.print(f"[red]{exc}[/]")
        if not jobs:
            return
        if mode == "attack":
            ans = input(f"Launch ATTACK agents on {len(jobs)} hosts? [yes/NO]: ")
            if ans.strip().lower() != "yes":
                return self.console.print("[yellow]Aborted.[/]")
        if not self.llm.available():
            return self.console.print("[red]LLM backend unavailable.[/]")

        def on_step(host, event):
            phase = event.get("phase")
            if phase == "planned":
                self.console.print(f"[cyan][{host}] step {event['step']}:[/] "
                                   f"$ {event['command']}")
            elif phase == "observed":
                mark = "✅" if event.get("success") else "❌"
                self.console.print(f"[{host}] {mark} {event['evaluation']}")
            elif phase == "error":
                self.console.print(f"[{host}] [red]{event['error']}[/]")

        self.console.print(f"[bold magenta]Launching {len(jobs)} {mode} agents…[/]")
        results = self.parallel.run(jobs, on_step=on_step)
        for host, res in results.items():
            if isinstance(res, dict):
                self.console.print(f"[green]{host}: {len(res['transcript'])} steps[/]")
            else:
                self.console.print(f"[red]{host}: {res}[/]")

    def cmd_dashboard(self, args):
        port = int(args[0]) if args else int(
            self.config.get("dashboard", {}).get("port", 8765))
        if self.dashboard:
            self.console.print(f"[yellow]Already running:[/] "
                               f"http://127.0.0.1:{self.dashboard.port}/")
            return
        self.dashboard = DashboardServer(self.db, port=port)
        self.dashboard.mission_handler = self._mission_handler
        self.dashboard.scope_handler = self._scope_handler
        self.dashboard.run_handler = self._quick_run_handler
        self.dashboard.allowed_tools = sorted(self.runner.allowed_tools)
        self.dashboard.audit = self.audit
        url = self.dashboard.start()
        self.audit.log("operator", "dashboard", "start", {"url": url})
        self.console.print(f"[green]War Room live at {url}[/] (auto-refreshes; "
                           f"mission control enabled)")

    def _scope_handler(self, host: str, network: str = "") -> None:
        """War Room 'Add to Scope' — edits authorization.json, audited."""
        host = host.strip()
        if not host:
            raise ValueError("empty host")
        self.scope.add_to_scope(host)
        desc = f"network: {network}" if network else "added via War Room"
        self.db.add_target(host, desc)
        self.audit.log("war-room", "scope", "add",
                       {"host": host, "network": network})

    def _mission_handler(self, host: str, mode: str, cancel_event=None) -> None:
        """War Room mission launch (HTTP API entry). Scope is enforced here."""
        self.scope.check(host)  # raises → mission status = error
        self.audit.log("war-room", "mission", "start", {"host": host, "mode": mode})
        if mode == "mission":
            self.coordinator.run_mission(host, cancel_event=cancel_event)
        else:
            self.engine.run(mode, host, cancel_event=cancel_event)

    def cmd_mission(self, args):
        if not args:
            return self.console.print("[red]usage: /mission <host> [--no-exploit][/]")
        host = args[0]
        skip_exploit = "--no-exploit" in args
        try:
            self.scope.check(host)
        except ScopeError as exc:
            return self.console.print(f"[red]{exc}[/]")
        self._target_or_print(host)
        if not skip_exploit:
            ans = input(f"Full mission on {host} includes the EXPLOITER phase. "
                        "Confirm written authorization [yes/NO]: ")
            if ans.strip().lower() != "yes":
                skip_exploit = True
                self.console.print("[yellow]Running recon+analyst only.[/]")
        self.console.print(f"[bold magenta]Mission launch:[/] {host} "
                           f"(recon → {'exploiter → ' if not skip_exploit else ''}analyst)")
        result = self.coordinator.run_mission(
            host, skip_exploit=skip_exploit,
            on_step=lambda e: self._on_step(e))
        refutations = result["phases"].get("analyst", {}).get("refutations", [])
        for r in refutations:
            icon = {"confirmed": "✅", "uncertain": "❓", "rejected": "🚫"}.get(
                r["verdict"], "❓")
            self.console.print(f"  {icon} refuter: {r['title']} — {r['verdict']} "
                               f"({r['reason'][:80]})")
        self.console.print("[green]Mission complete. /report to render.[/]")

    def cmd_refute(self, args):
        row = None
        if args:
            row = self.db.get_target(args[0])
        if not row:
            return self.console.print("[red]usage: /refute <host>[/]")
        if not self.llm.available():
            return self.console.print("[red]LLM backend unavailable.[/]")
        with self.console.status("Refuter reviewing model-asserted findings…"):
            results = self.refuter.review_target(row["id"])
        if not results:
            return self.console.print("[yellow]Nothing to review — no "
                                      "model-asserted medium+ findings.[/]")
        for r in results:
            icon = {"confirmed": "✅", "uncertain": "❓", "rejected": "🚫"}.get(
                r["verdict"], "❓")
            self.console.print(f"{icon} [{r['finding_id']}] {r['title']}: "
                               f"{r['verdict']} — {r['reason']}")

    def cmd_disclose(self, args):
        if not args or not args[0].isdigit():
            return self.console.print("[red]usage: /disclose <finding-id>[/]")
        fid = int(args[0])
        f = self.db.get_finding(fid)
        if not f:
            return self.console.print(f"[red]no finding #{fid}[/]")
        if not f["verified"]:
            ans = input(f"Finding #{fid} is UNVERIFIED ({f['provenance']}). "
                        "Draft anyway? [yes/NO]: ")
            if ans.strip().lower() != "yes":
                return
        out = self.disclosure.draft(fid)
        self.audit.log("operator", "disclosure", "draft",
                       {"finding_id": fid, "file": str(out)})
        self.console.print(f"[green]Disclosure draft:[/] {out}\n"
                           f"[yellow]Review, validate, and submit manually — "
                           f"Aegis never sends.[/]")

    def cmd_diff(self, args):
        if not args:
            return self.console.print("[red]usage: /diff <other-engagement.db>[/]")
        if not Path(args[0]).exists():
            return self.console.print(f"[red]no such file: {args[0]}[/]")
        report = diff_engagements(args[0], self.db)
        self.console.print(report)

    def cmd_doctor(self):
        from .diag import doctor
        with self.console.status("Running health checks…"):
            results = doctor(self.config, self)
        table = Table(title="Aegis doctor")
        for col in ("check", "status", "detail"):
            table.add_column(col)
        for r in results:
            table.add_row(r["name"],
                          "[green]OK[/]" if r["ok"] else "[red]FAIL[/]",
                          r["detail"])
        self.console.print(table)
        fails = sum(1 for r in results if not r["ok"])
        self.console.print(f"[{'green' if fails == 0 else 'yellow'}]"
                           f"{len(results) - fails}/{len(results)} checks healthy[/]")

    def cmd_logs(self, args):
        from .diag import tail_debug_log
        lines = int(args[0]) if args and args[0].isdigit() else 40
        for line in tail_debug_log(self.config.get("paths", {})
                                   .get("logs_dir", "logs"), lines):
            self.console.print(f"[dim]{line}[/]")

    # ---- v0.5 handlers: scope-add, kill switch, loot viewing ---------------
    def cmd_authorize(self, args):
        if not args:
            return self.console.print("[red]usage: /authorize <host|CIDR> "
                                      "[network-label][/]")
        host, network = args[0], " ".join(args[1:])
        try:
            self._scope_handler(host, network)
            self.console.print(f"[green]Authorized & registered:[/] {host}"
                               + (f" (network: {network})" if network else ""))
        except Exception as exc:
            self.console.print(f"[red]{exc}[/]")

    def cmd_kb(self, args):
        """/kb — list KB + drafts. /kb add <group> <pat> <hint>.
        /kb promote <n> | /kb dismiss <n> — review learned drafts."""
        from .playbook import (add_custom_rule, dismiss_draft,
                               list_custom_rules, load_kb, promote_draft)
        if args and args[0] == "add":
            if len(args) < 4:
                return self.console.print(
                    "[red]usage: /kb add <version_hints|service_hints|"
                    "port_hints> <pattern|port> <hint>[/]")
            group, pattern, hint = args[1], args[2], " ".join(args[3:])
            try:
                add_custom_rule(".", group, pattern, hint)
                self.audit.log("operator", "playbook", "add_rule",
                               {"group": group, "pattern": pattern})
                self.console.print("[green]Rule added[/] — live for the next "
                                   "planning step (hot-reloaded)")
            except ValueError as exc:
                self.console.print(f"[red]{exc}[/]")
            return
        if args and args[0] in ("promote", "dismiss"):
            if len(args) < 2 or not args[1].isdigit():
                return self.console.print(f"[red]usage: /kb {args[0]} <n>[/]")
            try:
                fn = promote_draft if args[0] == "promote" else dismiss_draft
                d = fn(".", int(args[1]))
                self.audit.log("operator", "playbook",
                               f"{args[0]}_rule", {"pattern": d["pattern"]})
                verb = "promoted to live rules" if args[0] == "promote" \
                    else "dismissed"
                self.console.print(f"[green]Draft {verb}:[/] {d['pattern']}")
            except ValueError as exc:
                self.console.print(f"[red]{exc}[/]")
            return
        kb = load_kb(".")
        custom = list_custom_rules(".")
        self.console.print(
            f"[bold]Bundled:[/] {len(kb['version_hints'])} version-exploit, "
            f"{len(kb['service_hints'])} service, "
            f"{len(kb['port_hints'])} port-fallback rules")
        drafts = custom.get("drafts", [])
        if drafts:
            table = Table(title="⏳ Learned drafts — /kb promote <n> or "
                                "/kb dismiss <n>")
            table.add_column("#")
            table.add_column("group")
            table.add_column("pattern")
            table.add_column("hint", overflow="fold")
            for i, d in enumerate(drafts):
                table.add_row(str(i), d["group"], d["pattern"], d["hint"])
            self.console.print(table)
        rows = ([(g, r[0], r[1]) for g in ("version_hints", "service_hints")
                 for r in custom.get(g, [])]
                + [("port_hints", k, v)
                   for k, v in custom.get("port_hints", {}).items()])
        if not rows and not drafts:
            self.console.print("[dim]No custom rules — add one with "
                               "/kb add or from the War Room.[/]")
            return
        if rows:
            table = Table(title="Custom playbook rules (fire first)")
            table.add_column("group")
            table.add_column("pattern")
            table.add_column("hint", overflow="fold")
            for g, p, htext in rows:
                table.add_row(g, p, htext)
            self.console.print(table)

    def cmd_loot_show(self, loot_id: int):
        row = self.db.conn.execute("SELECT * FROM loot WHERE id = ?",
                                   (loot_id,)).fetchone()
        if not row:
            return self.console.print(f"[red]no loot #{loot_id}[/]")
        item = self.db._decrypt_row(row)
        self.console.print(f"[bold]#{item['id']} ({item['kind']}) "
                           f"{item['title']}[/]")
        if item["value"]:
            self.console.print(item["value"])
        if item["file_path"]:
            self.console.print(f"file: {item['file_path']}")
        if item["source"]:
            self.console.print(f"[dim]source: {item['source']}[/]")
        self.audit.log("operator", "loot", "view", {"id": loot_id})

    def cmd_missions(self):
        if not self.dashboard or not self.dashboard.missions:
            return self.console.print("[yellow]No missions tracked — start the "
                                      "War Room with /dashboard or use /scan.[/]")
        table = Table(title="Missions")
        for col in ("id", "mode", "host", "status"):
            table.add_column(col)
        for mid, m in self.dashboard.missions.items():
            table.add_row(str(mid), m["mode"], m["host"], m["status"])
        self.console.print(table)

    def cmd_stop(self, args):
        if not args:
            return self.console.print("[red]usage: /stop <mission-id|all>[/]")
        if args[0] == "all":
            n = self.runner.cancel_all()
            if self.dashboard:
                for mid, m in self.dashboard.missions.items():
                    if m["status"] == "running":
                        self.dashboard.stop_mission(mid)
            self.audit.log("operator", "mission", "stop_all", {"killed": n})
            return self.console.print(f"[yellow]Stopped everything — "
                                      f"{n} process(es) killed.[/]")
        if not self.dashboard:
            return self.console.print("[red]no War Room running[/]")
        if self.dashboard.stop_mission(int(args[0])):
            self.audit.log("operator", "mission", "stop", {"id": args[0]})
            self.console.print(f"[yellow]Mission {args[0]} stopping…[/]")
        else:
            self.console.print(f"[red]mission {args[0]} not running[/]")

    # ---- main loop -------------------------------------------------------
    def run(self):
        self.console.print(BANNER, style="bold blue")
        self.console.print(f"Engagement: [bold]{self.scope.engagement}[/]  "
                           f"scope={len(self.scope.scope)} entries  "
                           f"proxychains={'on' if self.runner.use_proxychains else 'off'}")
        roe = self.scope.roe
        roe_bits = []
        if roe.get("prohibited_techniques"):
            roe_bits.append(f"prohibited: {', '.join(roe['prohibited_techniques'])}")
        if roe.get("max_requests_per_second"):
            roe_bits.append(f"max {roe['max_requests_per_second']} req/s")
        if roe.get("testing_hours"):
            roe_bits.append(f"hours {roe['testing_hours']}")
        if roe_bits:
            self.console.print(f"[yellow]RoE:[/] {' · '.join(roe_bits)}")
        if self.cipher.active:
            self.console.print("[green]Loot encryption: ON[/] (Fernet, at rest)")
        else:
            self.console.print(f"[red]Loot encryption: OFF — {self.cipher.error}[/]")
        self.console.print("Type /help for commands, or just chat.\n")
        while True:
            try:
                line = input("aegis> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            if not line.startswith("/"):
                self._chat(line)
                continue
            try:
                parts = shlex.split(line[1:])
            except ValueError:
                continue
            if not parts:
                continue
            cmd, args = parts[0].lower(), parts[1:]
            try:
                if cmd in ("quit", "exit", "q"):
                    break
                elif cmd == "help":
                    self.console.print(HELP)
                elif cmd == "target":
                    self.cmd_target(args)
                elif cmd == "osint":
                    self.cmd_osint(args)
                elif cmd in ("scan", "attack"):
                    self.cmd_agent(cmd, args)
                elif cmd == "run":
                    self.cmd_run(args)
                elif cmd == "findings":
                    self.cmd_findings(args)
                elif cmd == "attempts":
                    self.cmd_attempts(args)
                elif cmd == "loot":
                    self.cmd_loot(args)
                elif cmd == "hashes":
                    self.cmd_hashes(args)
                elif cmd == "map":
                    self.cmd_map(args)
                elif cmd == "webvuln":
                    self.cmd_webvuln(args)
                elif cmd == "lfi":
                    self.cmd_lfi(args)
                elif cmd == "privesc":
                    self.cmd_privesc(args)
                elif cmd == "lateral":
                    self.cmd_lateral(args)
                elif cmd == "msf":
                    self.cmd_msf(args)
                elif cmd == "opsec":
                    self.cmd_opsec(args)
                elif cmd == "parallel":
                    self.cmd_parallel(args)
                elif cmd == "dashboard":
                    self.cmd_dashboard(args)
                elif cmd == "diff":
                    self.cmd_diff(args)
                elif cmd == "doctor":
                    self.cmd_doctor()
                elif cmd == "logs":
                    self.cmd_logs(args)
                elif cmd == "authorize":
                    self.cmd_authorize(args)
                elif cmd == "kb":
                    self.cmd_kb(args)
                elif cmd == "missions":
                    self.cmd_missions()
                elif cmd == "stop":
                    self.cmd_stop(args)
                elif cmd == "mission":
                    self.cmd_mission(args)
                elif cmd == "refute":
                    self.cmd_refute(args)
                elif cmd == "disclose":
                    self.cmd_disclose(args)
                elif cmd == "proxy":
                    self.runner.use_proxychains = (args[:1] == ["on"])
                    self.console.print(f"proxychains: "
                                       f"{'ON' if self.runner.use_proxychains else 'OFF'}")
                elif cmd == "vpn":
                    up = self.runner.vpn_up()
                    self.console.print(f"VPN interface up: {'yes' if up else 'no'}")
                elif cmd == "report":
                    self.cmd_report(args)
                elif cmd == "verify-audit":
                    self.cmd_verify_audit()
                else:
                    self.console.print(f"[red]unknown command /{cmd} — try /help[/]")
            except ScopeError as exc:
                self.console.print(f"[red]SCOPE: {exc}[/]")
            except Exception as exc:  # keep the shell alive
                self.log.exception("command /%s failed", cmd)
                self.console.print(f"[red]error: {exc}[/] "
                                   f"[dim](traceback in {self.debug_log})[/]")
        if self.dashboard:
            self.dashboard.stop()
        self.audit.log("operator", "session", "end", {})
        self.db.close()
        self.console.print("[blue]Session closed. Audit chain intact.[/]")

    def _chat(self, text: str):
        targets = self.db.list_targets()
        target = targets[-1]["host"] if targets else "(no target selected)"
        self.audit.log("operator", "chat", "question", {"text": text})
        try:
            with self.console.status("Thinking…"):
                answer = self.agent.advise(target, text)
            self.console.print(answer)
            self.audit.log("planner", "chat", "answer", {"text": answer[:2000]})
        except LLMError as exc:
            self.console.print(f"[red]{exc}[/]")
