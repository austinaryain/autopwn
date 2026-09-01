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

## Diagnostics & troubleshooting

Two logging layers, two different questions:

- **Audit chain** (`logs/audit-*.jsonl`) — *what did Aegis do?* Tamper-evident, for clients and legal defensibility. Verify with `/verify-audit`.
- **Debug log** (`logs/debug-*.log`) — *why did it misbehave?* Verbose per-module logging (planner decisions, LLM errors, guard refusals with full args, exec timings, timeouts). Tail it with `/logs [n]`; exceptions from any command land here with full tracebacks.

`/doctor` runs a 12-point environment health check: Python, deps, authorization, loot encryption, LLM reachability, proxychains, VPN interfaces, Kali tool inventory, OSV API.

First run on Kali: `bash setup_kali.sh` — checks/installs everything, pulls the Ollama model, walks you through scoping `authorization.json`, and gates on the full test suite + simulation validation before declaring readiness.

## v1.1 — reports that show the intelligence

Client deliverables now carry everything the engagement learned:

- **Infrastructure profile per target** — ports/services/versions as a proper table, web stack (server, X-Powered-By/PHP), OS, and detected technologies — all from the deterministic intel extraction, not LLM prose.
- **Flags in the loot summary** — captured flags are counted and listed in full (credentials stay masked unless `include_secrets`).
- **Engagement Knowledge Base section** — every live custom playbook rule (✅) and every auto-learned draft awaiting review (⏳) ships in the report, showing clients exactly which techniques were applied and accumulated.
- **HTML reports render tables properly** — the infrastructure tables now render as real HTML tables instead of raw markdown.

## v1.0 — the learning loop closes itself

**The tool now writes its own playbook from your wins.**

When an *attack* step succeeds against a service with known intel, Aegis
auto-drafts a KB rule: product+version → the technique and exact command that
worked (host generalized to `TARGET`). Drafts land in a **review queue** —
they never go live on their own:

- **War Room**: drafts appear under the KB card with **promote** / **dismiss**
- **CLI**: `/kb` lists drafts; `/kb promote 0` / `/kb dismiss 0`
- Promotion runs the same validation as manual rules; everything is
  audit-logged (`playbook / draft_rule / promote_rule / dismiss_rule`)

Guardrails: only attack-mode successes draft (scans teach nothing); no draft
when a bundled version-specific rule already covers the service; identical
drafts dedupe; drafts without service context are skipped. Successful
*scans* and parser-inconclusive steps never pollute the queue.

The flywheel: run engagement → wins become drafts → you promote the good ones
→ next engagement against that stack starts smarter. Per-workspace, so each
client's hard-won knowledge stays with that client.

## v0.9 — living knowledge base (your engagements make it smarter)

The playbook is now **data, not code** — every lesson from every engagement
becomes permanent capability:

| Feature | Detail |
|---|---|
| **JSON knowledge base** | All hint data lives in [aegis/playbook.json](aegis/playbook.json) (20 version-exploit + 21 service + 13 port rules + wordlist maps). Edit it directly — no Python required. |
| **Per-workspace overlay** | Drop a `playbook.custom.json` in the engagement directory; custom rules are checked **before** bundled ones. Client-specific knowledge (their stack, their quirks) goes here. |
| **Hot reload** | The KB is re-read on every planning step — add a rule mid-engagement and the agent's very next decision uses it. No restart. |
| **War Room editing** | "Playbook Knowledge Base" card: pick a group, give a regex/port + hint, done. Validated (bad regex/ports rejected with clear errors), audit-logged, duplicates ignored. |
| **Per-target recommendations** | The Command Center now shows **what the playbook recommends for this exact target right now** — full transparency into why the agent picks its moves. |
| **CLI** | `/kb` lists bundled counts + custom rules; `/kb add <group> <pattern> <hint>` adds one from the terminal. |

## v0.8 — engagement-grade knowledge base (labs AND real world)

The playbook grew from CTF-oriented to engagement-grade, covering real-world
services and bug-bounty methodology. Hints are priority-ordered so the
planner always sees the highest-value move first:

1. **Version-specific named exploits** — Apache 2.4.49/50, vsftpd 2.3.4, ProFTPD 1.3.5/1.3.3c, Samba usermap + SambaCry, OpenSSH ≤7.6 user-enum, IIS 6.0 WebDAV, Drupalgeddon2, Joomla CVE-2017-8917, Grafana CVE-2021-43798, Heartbleed, Struts2 CVE-2017-5638, UnrealIRCd / distcc / Webmin / Elasticsearch Groovy, Ghostcat (AJP) — each with the exact allowlisted command.
2. **Service playbooks** — SMB, FTP, SSH, MySQL/MSSQL/PostgreSQL, WordPress, phpMyAdmin, Tomcat/Jenkins, LDAP, SMTP, POP3/IMAP, VNC, RDP, Telnet, NFS, Redis, MongoDB, SNMP, IRC, AJP.
3. **Port fallbacks** — Docker API (2375), Elasticsearch (9200), Memcached, Kubernetes API/kubelet, Kibana, RabbitMQ, ActiveMQ, Solr, GlassFish, Webmin, Splunkd — for when banners give nothing.
4. **Bug-bounty web chain** — beyond nikto/gobuster: `/.git/HEAD`, `/.env`, `/.well-known/security.txt`, `/backup.zip`, and a CORS misconfiguration check (reflected origin + credentials = reportable finding).
5. **Domain recon chain** — when the target is a domain: sublist3r/amass passive enum + vhost fuzzing, with a built-in reminder to verify every discovered subdomain against `authorization.json` before touching it. (Also fixed a guard bug that made `sublist3r -d` unusable.)
6. **Credential reuse** — the moment any credential lands in loot, the planner is told to stuff it across every discovered login service (the #1 real-world escalation path) and pointed at `/privesc`.
7. **Version research fallback** — every detected product+version gets a `searchsploit` lookup hint.

## v0.7 — target intelligence & effectiveness (field feedback, round 3)

Built after Easy/Medium THM targets produced clean runs but empty results:

| Feature | Detail |
|---|---|
| **Target intel extraction** | Every captured output is deterministically mined: open ports + service versions (nmap), `Server:`/`X-Powered-By:` headers (curl/nikto/nmap), whatweb tech plugins, OS guesses → deduped `intel` table. Answers "what PHP/Apache version is running?" without digging through logs. |
| **Flag & secret hunter** | Every output is scanned for `THM{…}`, `HTB{…}`, `flag{…}`, context-aware 32-hex flags, and private keys → auto-recorded as loot + audit entry, even if the LLM misses them. |
| **Command Center** | Click any target in the War Room: infrastructure table (ports/versions), web stack chips (server, PHP, OS), findings, loot with reveal, attempts, and every action with its error reason and a **[log]** button that opens the full captured output. Auto-refreshes during runs. |
| **Playbook hints** | A deterministic service→attack knowledge base (Apache 2.4.49 → CVE-2021-41773 with the exact curl, vsftpd 2.3.4 → backdoor, SMB → enum4linux chain, HTTP → whatweb/robots/nikto/gobuster chain, …) is injected into the planner prompt, grounded in what was actually found. |
| **Command grounding** | The guard now refuses hallucinated arguments *before execution*: unknown NSE script names are checked against `/usr/share/nmap/scripts` with did-you-mean suggestions, and nonexistent file/wordlist paths (e.g. `/path/to/custom/wordlist`) are refused with a list of wordlists that actually exist. |
| **Adapt, don't die** | Guard refusals are recorded with their reason, fed back into planner memory, and the agent continues with a corrected command — only scope violations stop the loop. |

## v0.6 — diagnosability (field feedback, round 2)

| Feature | Detail |
|---|---|
| **Error reasons everywhere** | Failed actions now store a compact reason (stderr tail, timeout, cancel, bare exit code) in a new `actions.error` column. The War Room's Recent Activity shows it inline under the failed command — no more mystery "error" rows. |
| **The planner learns from failures** | `memory_summary` feeds the one-line failure reason back to the LLM, so the next planned step adapts (e.g. drops a nonexistent NSE script) instead of retrying the same broken command. |
| **Loot reveal that sticks** | Revealed values are cached client-side and survive the 3 s auto-refresh; failures surface as inline `⚠` messages instead of silently doing nothing. Reveals from the War Room are audit-logged (`war-room / loot / view`) just like `/loot show`. |
| **Injection hardening** | All target-influenced fields (command output, error text, loot, titles) are HTML-escaped before rendering — a hostile target banner can't inject markup into the operator's browser. Malformed `/api/loot` requests get a JSON error instead of a dropped connection. |

## v0.5 — operator UX (TryHackMe field feedback)

Driven by real lab usage — less typing, full control, loot at your fingertips:

| Feature | Detail |
|---|---|
| **Scope from the War Room** | "Add to Scope" form on the dashboard (host + network label) → atomic, idempotent write to `authorization.json` + auto-registers the target + audit entry. CLI equivalent: `/authorize 10.10.10.5 tryhackme`. |
| **Kill switch** | Every tool process and agent loop is cancellable: red **■ stop** button per running mission in the War Room, `POST /api/mission/stop`, `/stop <id>` or `/stop all` in the CLI. Cancellation kills the subprocess tree, marks the mission "stopped by operator", and is audit-logged. |
| **Loot viewing** | `/loot show <id>` prints the full decrypted credential/note/file path. War Room loot rows have **reveal** links (`GET /api/loot?id=N&reveal=1`) — masked by default, decrypted on demand, every view audit-logged. |
| **Mission visibility** | `/missions` lists all War Room missions (id, host, mode, status); running missions show live status in the dashboard. |

## v0.4 — trust & kill-chain maturity (T3MP3ST gap-closure)

| Feature | Detail |
|---|---|
| **Finding provenance** | Every finding labeled `tool-proven` (deterministic parser) or `model-asserted` (LLM claim). Only verified findings ship in the report's main section; the rest go to an "Unverified Candidates" appendix. |
| **Refuter pass** | `/refute <host>` — an adversarial reviewer prompt tries to *disprove* every model-asserted medium+ finding from the captured evidence. Outcomes: confirmed / needs-verification / rejected (rejected findings are excluded from reports). |
| **Operator chain** | `/mission <host>` runs Recon → Exploiter → Analyst via a [Coordinator](aegis/operators.py) sharing engagement memory; the Analyst refutes findings and writes the report's **Attack Narrative** section. |
| **War Room** | Dashboard is now interactive: mission launch form + `POST /api/mission/start` / mission status in `/api/state`, all behind the session token. |
| **Disclosure pipeline** | `/disclose <finding-id>` — OSV novelty check + HackerOne/Bugcrowd-style markdown draft in `disclosures/`. Aegis never sends anything; a human reviews and submits. Unverified findings require explicit confirmation before drafting. |

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
