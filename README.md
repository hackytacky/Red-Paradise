# Red-Paradise

**G9 RED-OPS // CHIMERA COMMAND** — control-plane UI for the G9/CT9 autonomous red-team swarm.

Demo deployment: all telemetry is simulated. On the G9 host, the same gates and pipeline drive real scoped tool adapters via CERBERUS.

## Doctrine

- Graduated authorization — no offensive action runs until the operator signs the RoE
- Code-enforced verdicts — no LLM grades its own exploit success (deterministic CERBERUS post-conditions)
- Capability separation in code, not prompts — oversight agents hold no tools; the orchestrator routes but never executes
- Owner-facing reports — every finding ships with remediation, a re-test plan, and a purple-team package

## Governance concepts adapted from Decepticon

- **Immutable workflow pinning** — the execution workflow (id, version, full source, SHA-256) is pinned at dispatch; resumes keep the pin; conflicting pins fail closed
- **OPPLAN objective DAG** — readiness comes from real dependency paths and evidence, never a fixed kill-chain ladder; proof → independent verification → reporting
- **Soundwave planning documents** — `plan/roe.json` is operator-provisioned; the agent team may prepare the optional planning set but never rewrites it

## Views

| Route | Purpose |
|---|---|
| `/` | Mission control: stats, live cycle chart, gate summary |
| `/mission` | Phase 0 governance: scope, success criteria, RoE signing, planning docs |
| `/swarm` | The CT9 agent roster by tier (command / oversight / blue / red / AI / support / structural) |
| `/feed` | 24/7 live operations feed, filterable by kind |
| `/chains` | Attack-chain state maps with per-link verification |
| `/opplan` | Evidence-driven objective DAG + coverage truth |
| `/findings` | Findings pipeline: candidate → verified (deterministic PoV) → reported |
| `/gates` | CERBERUS code policy, approval queue, decision log |
| `/report` | CALLIOPE owner-facing Markdown report builder |
| `/setup` | Tool adapters, local model registry, mission configuration |
| `/architecture` | SPECTRE architecture: diagram, integration priorities, component map, capability tiers, final recommendations |
| `/evidence` | Evidence Graph + Verification Authority engines, live |
| `/execution` | Trusted execution: canonical action spec + approval state machine, live |
| `/resilience` | Tripwire scanner, model-routing scheduler, temporal memory, live |
| `/arsenal` | Universal tool registry admission + deny-by-default policy gate, live |
| `/opsec` | HYPNOS: stealth gate, anonymity scan, no-traces close gate, live |

## Implemented engines (`src/lib/`, 92 unit tests)

| Engine | Contract |
|---|---|
| `evidenceGraph.js` | Typed evidence nodes, verified-link attack-path reasoning, provenance, dedupe |
| `verificationAuthority.js` | Hypothesis → … → regression-verified ladder; agents never promote their own findings |
| `actionSpec.js` | Canonical 16-field action spec; digest-bound approval; tamper invalidates |
| `approvalStateMachine.js` | CREATED → EVIDENCE_PRESERVED; OUTCOME_UNKNOWN blocks replay until reconciled |
| `adversarialResilience.js` | Tripwires: canaries, injection, encoded payloads, scope hosts, self-authorization |
| `agentScheduler.js` | Task-aware routing; approval-gated cloud escalation; VRAM budgeting |
| `temporalMemory.js` | Expired/superseded facts never resurface as current; never an authorization source |
| `toolRegistry.js` | Any tool from anywhere via one-time recorded admission; capability grants |
| `policyEngine.js` | Cedar-style deny-by-default PDP; seven checks; precise deny reasons |
| `opsecGuardian.js` | Stealth gate, identifier scanning, no-traces artifact ledger + close gate |
| `auditLedger.js` | Hash-chained tamper-evident activity records; detectable modification |
| `missionPipeline.js` | Ordered composition: policy → stealth → approval-binding → tripwires |

Architecture docs: [`docs/architecture/`](docs/architecture/README.md) · OPSEC skill: [`skills/opsec-stealth-cleanup/SKILL.md`](skills/opsec-stealth-cleanup/SKILL.md) · Build audit: [`docs/architecture/triple-audit-build-1.md`](docs/architecture/triple-audit-build-1.md)

## Run

```bash
npm install
npm run dev      # dev server
npm run build    # production build to dist/
npm run preview  # preview the production build
```

Stack: React 18 · Vite 5 · Tailwind CSS 3 · Recharts · React Router 6.

## Safety note

This UI is a control plane for **authorized** engagements only (RED-LAB disposable-guest range in the demo data). The authorization gate, scope allowlist, per-action host-plane approvals, and fail-safe defaults are load-bearing parts of the design, not decoration.
