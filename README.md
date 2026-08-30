# Aegis Workbench

An agentic, autonomous, learning-guided **penetration testing workbench** for
**authorized** red-team and pentest engagements. Runs on Kali Linux, orchestrates
the CLI tools you already trust (nmap, nikto, gobuster, hydra, metasploit, …),
remembers everything it has tried, adapts its next move, and produces a
comprehensive engagement report.

> ⚖️ **Legal use only.** Aegis refuses to touch any target that is not listed in
> a signed scope/authorization file. It is built for professional penetration
> testers operating under a written rules-of-engagement agreement.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         aegis CLI / chat                        │
│  /scope /target /osint /scan /attack /findings /report  + chat │
└───────────────┬────────────────────────────────────────────────┘
                │
        ┌───────▼────────┐    plan → act → observe → adapt
        │   Agent Loop    │◄───────────────┐
        │ (scan / attack) │                │
        └───┬────────┬───┘                │
            │        │                    │
   ┌────────▼─┐  ┌───▼──────┐     ┌───────┴───────┐
   │  Runner   │  │  OSINT   │     │ Attempt Memory │
   │ proxy/VPN │  │ collector│     │  (SQLite DB)   │
   └────┬──────┘  └────┬─────┘     └───────┬───────┘
        │              │                    │
┌───────▼──────────────▼────────────────────▼───────┐
│  Scope Gate  ·  Audit Log (hash-chained JSONL)     │
│  Engagement DB  ·  Report Generator                │
└────────────────────────────────────────────────────┘
```

## Core guarantees

- **Scope gate** — every command target is validated against the engagement
  scope *before* execution. Out-of-scope = refused and logged.
- **Audit log** — append-only, hash-chained JSONL (`logs/audit-*.jsonl`).
  Tamper-evident: each entry embeds the hash of the previous one.
- **Memory** — every action, attempt (success *and* failure), finding and OSINT
  item lives in `engagement.db`. Agents query it before planning their next step.
- **Anonymity transport** — optional `proxychains4` wrapping of every tool call,
  plus VPN interface checks (tun0/wg0) before scans start.
- **Reporting** — one command renders the full engagement (actions, attempts,
  findings, evidence, timeline) to Markdown/HTML.

## Quick start (Kali)

```bash
git clone <repo> && cd aegis-workbench
pip install -r requirements.txt

# 1. Declare your authorized scope (required, nothing runs without it)
cp authorization.example.json authorization.json
$EDITOR authorization.json          # add your in-scope hosts/CIDRs

# 2. Configure LLM backend (Ollama local, or any OpenAI-compatible API)
cp config.example.json config.json
$EDITOR config.json

# 3. Start the workbench
python main.py
```

Then, inside the shell:

```
aegis> /target add 10.10.10.5 "web server from scope"
aegis> /osint 10.10.10.5
aegis> /scan 10.10.10.5            # autonomous scan agent
aegis> what's the best attack path against 10.10.10.5?   # chat with planner
aegis> /attack 10.10.10.5          # autonomous attack agent (adapts from memory)
aegis> /report engagement          # writes report-engagement.md + .html
```

## Lab validation — prove it before client use

The full **scan → attack → report** loop ships as an executable checklist:

```bash
python -m validation.run_lab_validation                 # simulation (any machine)
python -m validation.run_lab_validation --real --target 192.168.56.101   # Kali + lab VM
```

Simulation mode runs the *real* pipeline (planner → guard → runner →
parsers → encrypted loot → ATT&CK → report → audit verification) against
fake tools and a scripted planner — 16/16 checks must pass. Real mode runs
the same checklist against a live lab (Metasploitable, HTB, Juice Shop)
with real tools and a real LLM. Full procedure: [validation/RUNBOOK.md](validation/RUNBOOK.md).

## v0.3 — production hardening ("bulletproof" pass)

Built for client engagements and bug-bounty programs where a single
out-of-scope packet is a contract breach:

| Area | What changed |
|---|---|
| **Argument-level scope enforcement** | Every host/IP/URL embedded in command *arguments* is extracted and scope-checked before execution — a hallucinated `nmap target 8.8.8.8` or `sqlmap -u https://out-of-scope.com` is refused and audited. [guard.py](aegis/guard.py) |
| **Argument-safety policy** | Code-exec flags denied (`--script`, `-e`, `-r`), target-list files denied (`-iL` = scope bypass), output paths confined to the workspace. |
| **Bug-bounty Rules of Engagement** | `authorization.json` now models `prohibited_techniques`, `max_requests_per_second` (enforced rate limiter), and `testing_hours` (enforced time window). Violations are refused before execution. |
| **Deterministic parsers** | nmap/hydra/medusa/ncrack/nikto/whatweb outputs are parsed by code, not vibes — parser verdicts on success/loot/findings are authoritative; the LLM only summarizes when parsers are inconclusive. [parsers.py](aegis/parsers.py) |
| **Loot encryption at rest** | Credentials/hashes encrypted with Fernet (key from `AEGIS_LOOT_KEY` or auto-generated chmod-600 keyfile); reports and dashboard redact secrets by default (`report.include_secrets` to override). [crypto.py](aegis/crypto.py) |
| **Counter-attack hygiene** | Tool output is stripped of ANSI escapes and control characters before storage or display; console output is markup-escaped. |
| **Dashboard auth** | Per-session bearer token required; loot values masked in the API. |
| **Secrets hygiene** | Metasploit password reads from `AEGIS_MSF_PASSWORD` env var — no plaintext secrets in config. |
| **Circuit breakers** | Duplicate-command detector (3 strikes stops the agent) + per-target time budget. |
| **Validation ordering** | Guard/allowlist refusals enforced and audited even when the tool isn't installed locally. |
| **Test suite** | 44 pytest tests in [tests/](tests/) covering scope, guard, parsers, audit chain, crypto, concurrency, dashboard auth, runner policy. `python -m pytest tests/` |

## v0.2 — full engagement platform

Ten major capabilities on top of the agentic core:

| # | Feature | Command / module |
|---|---|---|
| 1 | **Loot vault** — credentials, hashes, captured files & screenshots, catalogued per target; one-command hash export for john/hashcat | `/loot`, `/hashes`, [loot.py](aegis/loot.py) |
| 2 | **MITRE ATT&CK mapping** — every attempt auto-tagged (word-boundary matched), tactic coverage heatmap, planner gets gap hints so it chases untouched tactics | `/map`, [attack_map.py](aegis/attack_map.py) |
| 3 | **Web vuln pipeline** — auto-discovers HTTP services (curl probes), runs nuclei, parses JSONL straight into CVSS-scored findings | `/webvuln`, [webvuln.py](aegis/webvuln.py) |
| 4 | **Client-grade reporting** — CVSS vectors, remediation text, ATT&CK coverage section, loot summary in MD + HTML | `/report`, [report.py](aegis/report.py) |
| 5 | **OPSEC profiles** — `stealth`/`paranoid` add jittered delays and *enforce* proxychains; unwrapped commands are refused and audited | `/opsec`, [opsec.py](aegis/opsec.py) |
| 6 | **Parallel agents** — scan one host while attacking another; thread-safe DB with serialized writes | `/parallel`, [parallel.py](aegis/parallel.py) |
| 7 | **Post-exploitation** — privesc research (searchsploit vs. discovered versions) and lateral-movement mining: new hosts found in memory are scope-checked before queueing | `/privesc`, `/lateral`, [postex.py](aegis/postex.py) |
| 8 | **Metasploit RPC** — validated exploitation + session management through msfrpcd, with explicit operator confirmation | `/msf`, [msf.py](aegis/msf.py) |
| 9 | **Live dashboard** — local web UI (127.0.0.1) auto-refreshing targets, findings, loot, activity, ATT&CK coverage | `/dashboard`, [dashboard.py](aegis/dashboard.py) |
| 10 | **Engagement diffing** — re-test comparison: new / resolved / persistent findings across engagement snapshots | `/diff`, [diff.py](aegis/diff.py) |

## Layout

| Path | Purpose |
|---|---|
| `aegis/audit.py` | Hash-chained append-only audit logger |
| `aegis/db.py` | Engagement database (targets, actions, attempts, findings, OSINT, loot) |
| `aegis/scope.py` | Scope/authorization gate — legal-use enforcement |
| `aegis/runner.py` | CLI tool execution: allowlist, proxychains, VPN check, OPSEC gate |
| `aegis/llm.py` | LLM backend (Ollama / OpenAI-compatible) |
| `aegis/agent.py` | Agentic scan & attack loops with attempt memory + ATT&CK tagging |
| `aegis/osint.py` | OSINT collectors (DNS, crt.sh, whois, subdomains) |
| `aegis/report.py` | Penetration-test report generator |
| `aegis/cli.py` | Interactive chat shell |
| `logs/` | Audit chain + full command output captures |
| `loot/` | Captured credentials, hashes, files, screenshots |
| `authorization.json` | Your signed scope (you create this) |
