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
