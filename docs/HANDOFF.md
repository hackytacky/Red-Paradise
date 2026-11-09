# G9 SPECTRE / Red-Paradise — Full Engineering Handoff

**Repo:** `hackytacky/Red-Paradise` (GitHub, all work pushed)
**Status:** control plane + contracts complete and tested; execution plane scaffolded; PR #4 open with the latest work
**Test totals at handoff:** 110 frontend (vitest) · 90 backend (pytest) · production build ✓

---

## 1. What this project is

G9 SPECTRE is an autonomous red-team/pentest control plane built on one inviolable
doctrine: **security decisions are enforced OUTSIDE the AI model.** The model can
propose, reason, and request — it cannot grant itself permissions, expand scope,
or declare its own results verified.

The build has two planes:
- **Control plane (complete, tested):** governance, verification, OPSEC, policy, budgets, evidence — every deterministic rule from the SPECTRE specs is enforced code.
- **Execution plane (contracts done, runtime pending):** adapters build real hardened commands; real KVM/Docker execution happens on the operator's G9 host (Ubuntu, RTX 5080/16GB).

**Honest boundary (never drop this from comms):** nothing here has yet found a real vulnerability. It is the defensible-findings machinery — the part XBOW-class demos lack. "SOTA" claims require measured results (Stage 06: Inspect AI + CyberGym-E2E + held-out suites).

## 2. Repository layout

```
/ (frontend: Vite + React 18 + Tailwind + Recharts)
  src/lib/            16 engines (all unit-tested)
  src/views1-9.jsx    18 UI views
  src/data.js         agents/OPPLAN/findings/chains data
  skills/opsec-stealth-cleanup/SKILL.md
  docs/architecture/  16 docs (README.md is the index)
backend/              FastAPI + Pydantic (uv; uv run pytest)
  g9_backend/core/    action_spec (SHA-256 digests), audit_ledger (hash-chained)
  g9_backend/policy/  deny-by-default engine (7 checks)
  g9_backend/executor/ state machine, broker, container_runtime, invoke_chain, worker_manager
  g9_backend/tools/   13 adapters + registry_data (346 tools) + registry_admission + web/recon/osint adapters
  g9_backend/mcp/     typed tool-family contracts (raw shell rejected)
  g9_backend/ops/    budget_controller (tokens/rate/CIDR/kill switch)
  g9_backend/evidence/ graph.py + collector.py (candidate findings only)
  g9_backend/intel/  sources.py (322 sources, 49 categories)
  tests/              90 pytest tests
```

## 3. The 16 frontend engines (src/lib)

| Engine | Enforced rule |
|---|---|
| evidenceGraph.js | typed nodes; attack paths over verified links only |
| verificationAuthority.js | agents never promote their own findings; evidence-gated ladder |
| actionSpec.js | digest-bound approval; tamper invalidates (demo FNV digest) |
| approvalStateMachine.js | OUTCOME_UNKNOWN blocks replay until reconciled |
| adversarialResilience.js | tripwires never consult the model's claim; halt never auto-retries |
| agentScheduler.js | cloud escalation needs approval; VRAM budgeting |
| temporalMemory.js | expired facts never resurface; never an auth source |
| toolRegistry.js | any tool via one-time recorded admission; grants over qualified only |
| policyEngine.js | deny-by-default; precise reasons |
| opsecGuardian.js | stealth gate, anonymity scan, no-traces close gate |
| auditLedger.js | hash-chained tamper-evident records |
| missionPipeline.js | composes policy→stealth→binding→tripwires |
| defenseCell.js | purple replay: loud chain undetected = headline finding |
| aiRedTeam.js | injection corpus; regressions block control changes |
| researchLoop.js | escalation-instead-of-invention; zero-day CVE discipline |
| advisoryWatch.js | 24/7 advisory→rescan queuing, dedupe |

## 4. The pipeline (the whole point)

```
typed MCP call → policy (deny-by-default) → budget/scope (tokens·rate·CIDR·kill switch)
  → [stealth gate (frontend pipeline)] → adapter (flag allowlists, spec-built argv)
  → hardened docker command → real execution (host) → evidence collector
  → candidate findings ONLY → Verification Authority confirms
```

Backend entry: `POST /tools/invoke` (api.py → invoke_chain.py). Every stage blocks
with a precise reason; every decision lands in the tamper-evident audit ledger.

## 5. Arsenal & intel (machine-readable, gated)

- **346 tools** (`tools/registry_data.py`) in 3 classes: container (restricted analysis), KVM (hostile research: untrusted code/disposable guests), service.
- **Admission gates** (`registry_admission.py`): `separate_auth` (phishing/on-path/credential tools — Metasploit, mimikatz, evilginx2, GoPhish… require a recorded separate RoE addendum), `license_required` (Cobalt Strike/Brute Ratel — valid license on record, cracked use prohibited), `legal_gate` (DeHashed, IntelligenceX, breach data — legal review), `lab_only`, `unverified` (onion.pet proxy, maktego/naubik — never auto-admitted).
- **322 intel sources / 49 categories** (`intel/sources.py`): governance automatic per category — 31 monitor-only (stealer logs, IAB listings, underground forums: metadata-level lawful CTI monitoring, never acquisition/possession), 39 legal-gated, 9 unverified (Tor).
- **Isolation decision** (docs/architecture/isolation-decision.md): hybrid — containers for analysis, KVM as the hostile-work boundary; hostile work NEVER downgrades to a container (enforced in worker_manager.py).
- **13 adapters implemented:** nmap-scoped, httpx, ffuf, nuclei, subfinder, masscan (rate from budget, `--rate` not flag-settable), testssl, theharvester, gitleaks, dig (AXFR refused), gowitness, amass (`-active` refused), dnsrecon.

## 6. Hard rules encoded (all test-proven)

1. Approval digest excludes `approval_id` (bug T-5 from the audit — regression-tested).
2. OUTCOME_UNKNOWN: no auto-replay; reconciliation evidence required.
3. Agents never self-promote findings; scanners are hypothesis generators only.
4. Raw shell strings rejected at the MCP contract boundary.
5. Targets come only from the authorized `target_set`, never model prose.
6. Flag allowlists are value-aware; flag values never re-validated as flags.
7. Loud chain undetected = detection finding (silence is a finding).
8. Engagement close blocked while any artifact is present (no traces).
9. Budget kill switch: operator-only reset; post-kill invocations halt.
10. Zero-day discipline: novel findings carry no CVE claims.

## 7. PR / branch state

- **Merged:** PR #1 (control plane UI), PR #2 (SPECTRE docs + engines + audit), PR #3 (backend scaffold + worker plane).
- **Open: PR #4** (`feature/tool-adapters`) — adapters, arsenal registry, MCP contracts, budget controller, invoke chain, evidence collector, intel registry. **The operator merges PRs (env blocks agent merges).** All work is pushed; branch is current.

## 8. Next steps (in order)

1. Operator merges PR #4.
2. **Feed adapters:** Shodan/Censys/abuse.ch/OTX API clients through the same gated chain (API keys admitted per source).
3. **Persistence (Stage 04):** PostgreSQL/Neo4j behind the existing contracts (evidence graph, audit ledger, registry).
4. **KVM worker (Stage 02 host-side):** libvirt/QEMU guest lifecycle behind `KvmWorkerManager` (currently raises NotImplementedError honestly — never faked).
5. **Orchestrator benchmark (Stage 03):** LangGraph vs Strands vs Pydantic AI on identical tasks.
6. **Specialist integrations (Stage 05)** in order: recon/graph → web/API → infra → RE → identity → vuln research → emulation → defensive validation → AI security.
7. **Measured evaluation (Stage 06)** — only then any SOTA claim.

## 9. Operating the repo

```bash
npm install && npm test && npm run build      # frontend (110 tests)
cd backend && uv sync && uv run pytest        # backend (90 tests)
cd backend && uv run uvicorn g9_backend.api:app --port 8700
```

Docs index: `docs/architecture/README.md`. Build audit: `triple-audit-build-1.md`.
Framework mapping: `framework-mapping.md`. Adapter approval list + arsenal: `adapter-approval-list.md`.

## 10. Communication norms for this project

- Always report honest boundaries (control plane vs execution plane; measured vs claimed).
- Benchmark numbers are developer-reported until independently established.
- Sensitive-category sources are monitoring-only with legal gates — never acquisition.
- Every capability claim in PRs/docs maps to a test that proves the failure mode fails closed.
