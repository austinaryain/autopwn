# Aegis vs T3MP3ST — Gap Analysis

Compared 2026-08-30 against https://github.com/elder-plinius/T3MP3ST
(AGPL-3.0 multi-agent offensive-security framework; README feature/status
tables as published).

Legend: ✅ Aegis has it · ⚡ partial · ❌ missing

## Head-to-head

| Capability | T3MP3ST | Aegis v0.3 |
|---|---|---|
| Scope/authorization enforcement | ✅ egress-scope containment (`SCOPE DENIED`) | ✅ arg-level guard + RoE (prohibited techniques, testing hours, rate limit) — arguably stricter |
| Audit trail | ⚡ receipts/integrity ledger for benchmarks | ✅ hash-chained tamper-evident JSONL per engagement |
| Loot/credential store | ✅ credential store | ✅ loot vault **encrypted at rest** + hash export for cracking |
| Deterministic verification of findings | ✅ "VERIFIED_PROVENANCE" (tool-proven vs model-asserted) | ⚡ deterministic parsers, but LLM-originated findings are not labeled by provenance |
| Report generator | ✅ reports + disclosure drafts | ✅ MD/HTML with CVSS, remediation, ATT&CK, redacted secrets |
| Re-test workflow | ❌ not listed | ✅ engagement diffing (`/diff`) |
| Lab validation harness | ✅ verify-claims benchmark re-derivation | ✅ 16-check full-loop harness + 48-test pytest suite |
| OPSEC | ✅ OPSEC layer | ✅ stealth/paranoid profiles, jitter, enforced proxychains, VPN checks |
| **Multi-operator kill chain** (Recon/Scanner/Exploiter/Infiltrator/Exfiltrator/Ghost/Coordinator/Analyst) | ✅ 8 specialized operators (swarm unproven, single-agent benchmarked) | ❌ two agent modes (scan/attack), no role specialization |
| **Browser War Room** (interactive mission control, Op Admiral natural-language launch) | ✅ | ⚡ read-only live dashboard; no web-based mission control |
| **Refuter / adversarial verification** (a panel that tries to disprove candidate findings) | ✅ refuter panel in disclosure pipeline | ❌ no adversarial second-pass on LLM findings |
| **HTTP API + MCP server** (expose tools to other agents) | ✅ | ❌ |
| **Local CLI-agent backends** (Claude Code / Codex / Hermes as the brain, keyless) | ✅ | ❌ Ollama / OpenAI-compatible only |
| **Coordinated disclosure pipeline** (OSV novelty check, CVSS, vendor-contact drafts; human sends) | ✅ | ❌ no bug-bounty submission workflow |
| **Benchmark suites** (XBEN, Cybench, CVE-Zero) measuring real capability | ✅ | ❌ no capability measurement, only functional tests |
| **Domain coverage** beyond network/web: white-box source audit (tree-sitter), CTF, cloud IaC, mobile, binary/RE, AD/identity, smart contracts | ✅/⚠️ several live, several scaffolding | ❌ network + web only |
| Docker packaging | ✅ | ❌ |
| Comms channel (operator notifications) | ✅ | ❌ |

## Priority gaps for Aegis v0.4

1. **P0 — Finding provenance + refuter pass.** ✅ **SHIPPED in v0.4** —
   `provenance` labels on every finding; refuter adversarial review for
   model-asserted medium+ findings; rejected findings excluded from reports.
2. **P1 — Operator roles.** ✅ **SHIPPED in v0.4** — Recon / Exploiter /
   Analyst operators sequenced by a Coordinator (`/mission`); analyst writes
   the report's attack narrative.
3. **P1 — HTTP API + dashboard→War Room upgrade.** ✅ **SHIPPED in v0.4** —
   `POST /api/mission/start`, mission status in `/api/state`, mission
   control UI in the War Room. MCP exposure remains open.
4. **P1 — Disclosure pipeline.** ✅ **SHIPPED in v0.4** — OSV novelty check,
   HackerOne/Bugcrowd-format draft, human-sends rule.
5. **P2 — Capability benchmark.** Open. A committed expected-findings
   oracle (Juice Shop / Metasploitable) re-derived by a verify-claims-style
   command.
6. **P2 — Keyless local-agent backends.** Open. Adapter to drive an
   installed Claude Code / Codex CLI as the brain.
7. **P3 — Domain expansion.** Open. White-box source audit, AD/identity,
   cloud IaC — each as a composable "loadout".

## Where Aegis already leads

- Tamper-evident hash-chained audit logging per engagement
- Loot encryption at rest with report/dashboard redaction
- Enforced RoE (prohibited techniques / testing hours / rate limits)
- Engagement diffing for re-tests
- Hash export pipeline into john/hashcat
- Cross-platform full-loop validation harness with committed pytest suite
