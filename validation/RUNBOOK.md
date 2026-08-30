# Lab Validation Runbook — proving Aegis before client use

Goal: demonstrate the complete **scan → attack → report** loop against a
controlled lab target *before* the first client or bug-bounty engagement.
Do not skip this. A tool that has only run in simulation is not proven.

## Phase 0 — simulation gate (any machine, 1 minute)

```bash
cd aegis-workbench
python -m pytest tests/ -q                 # all unit tests incl. full loop
python -m validation.run_lab_validation    # 16/16 must pass
```

Simulation uses fake tools + a scripted planner but exercises the **real**
pipeline: guard, runner, parsers, memory, encrypted loot, ATT&CK tags,
report, audit chain. If this fails, do not proceed.

## Phase 1 — Kali setup (15 minutes)

```bash
# 1. Lab target (pick one, must be INSIDE your scope):
#    - Metasploitable 2/3 VM (recommended first run)
#    - OWASP Juice Shop in Docker
#    - An HTB/THM box you have an active subscription for

# 2. LLM backend
ollama pull llama3.1 && ollama serve &

# 3. Aegis
cd aegis-workbench
pip install -r requirements.txt
cp config.example.json config.json

# 4. Authorization — this is your legal scope document
cp authorization.example.json authorization.json
$EDITOR authorization.json
#    - scope: the lab VM's IP (e.g. "192.168.56.101")
#    - prohibited_techniques: keep "denial-of-service" for bug bounty
#    - set max_requests_per_second if the program requires it
```

## Phase 2 — real validation run

```bash
python -m validation.run_lab_validation --real --target 192.168.56.101
```

This drives the actual checklist: scope refusals → OSINT → scan agent →
attack agent → ATT&CK coverage → report → audit-chain verification.
You will be asked to confirm written authorization before anything runs.

**Pass criteria (all 16 checks):** same as simulation, plus:
- the scan agent discovers the lab's real services
- any captured credential is encrypted at rest (`loot` table values start
  with `enc:v1:`) and redacted in the report

## Phase 3 — interactive shakedown (30–60 min)

```bash
python main.py
```

```
aegis> /dashboard                  # open the printed token URL, watch live
aegis> /osint 192.168.56.101
aegis> /scan 192.168.56.101        # watch planner decisions step by step
aegis> what's the best attack path against 192.168.56.101?
aegis> /attack 192.168.56.101      # confirm; observe adaptation
aegis> /attempts 192.168.56.101    # verify memory: successes AND failures
aegis> /loot                       # verify vault contents
aegis> /map                        # ATT&CK coverage heatmap
aegis> /report lab                 # open the MD + HTML deliverables
aegis> /verify-audit
```

Manually confirm:
- [ ] planner never proposed an out-of-scope host (check `logs/audit-*.jsonl`
      for `guard`/`command_refused` events — there should be refusals, not
      violations)
- [ ] every finding in the report has evidence you can reproduce
- [ ] secrets appear masked in the report (`••••••`)
- [ ] audit chain verifies after the session

## Phase 4 — bug-bounty readiness checks

- [ ] `authorization.json` mirrors the program's exact scope, exclusions,
      prohibited techniques, rate limits, and testing hours
- [ ] `/opsec stealth` enforced proxychains during a test run
- [ ] `/diff` works between two engagement snapshots (re-test workflow)
- [ ] You know how to export hashes: `/hashes engagement-hashes.txt`

## When something fails

Every refusal is in `logs/audit-*.jsonl` (`guard`, `scope`, `opsec`
categories). `python -m pytest tests/ -q` isolates regressions. The most
common first-run issues: Ollama not serving, tool not in
`runner.allowed_tools`, or lab IP not in `authorization.json` scope.
