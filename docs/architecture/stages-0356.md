# Stages 03 · 05 · 06 — Benchmark Harness, Specialist Pipelines, Measured Evaluation

## Stage 03 — orchestrator benchmark (`g9_backend/bench/`)

LangGraph vs Strands vs Pydantic AI on **identical tasks**, scored
deterministically. The deliverable is the harness:

- **Task suite** (`TASKS`, v1: 5 tasks): subdomain enum, web probe,
  TLS audit, typosquat check, threat-intel lookup — each with
  authorized scope, granted tools, and the expected typed call
- **Scorer** (`score_submission`): tool selection, typed-field
  match, MCP contract compliance (raw shell = fail), scope
  discipline (out-of-scope target = fail). No partial credit;
  failures are precise.
- **Pluggable orchestrators**: `load_langgraph_adapter()` reports
  unavailable when the framework isn't installed — it never fakes a
  run. Strands/Pydantic adapters follow the same seam host-side.
- **Reference baseline**: the `rulebook_orchestrator` — G9's own
  deterministic decision policy — runs the same suite in CI,
  proving the scorer works and freezing the baseline (5/5).

**Honest boundary:** the reference run says nothing about LangGraph
vs Strands vs Pydantic AI. Those numbers happen host-side with real
models on this identical suite.

## Stage 05 — specialist pipelines (`g9_backend/specialists/`)

Nine specialists, each a declared phase sequence over the admitted
arsenal — a mission shape, never a privilege:

| specialist | native (runs here) | container (host executes) |
|---|---|---|
| recon | portscan, http-probe | subfinder, sublist3r, dnstwist, hakrawler |
| web-api | http-probe, header-audit, content-discovery | ffuf, nuclei, whatweb |
| infra | portscan | masscan, testssl, dig |
| identity | — | sherlock, maigret, holehe, ghunt |
| reverse-engineering | — | exiftool, hachoir |
| vuln-research | portscan, http-probe | nuclei |
| emulation | header-audit, http-probe | — |
| defensive-validation | header-audit, tls-audit, content-discovery | — |
| ai-security | — | promptfoo, garak |

`run_specialist(name)` executes native phases for real through the
mission gates and builds the hardened container commands for the
rest (executed on the G9 host with real tools). Every phase: policy →
budget → adapter → evidence → candidates → verification.

## Stage 06 — measured evaluation (`g9_backend/eval/`)

The "only then any SOTA claim" stage. `evaluate_lab_pipeline(runs=N)`
measures the pipeline against **known ground truth** (10 planted
weaknesses across 9 template families):

| metric | measured (2 runs) |
|---|---|
| recall (planted weaknesses found) | **1.0** |
| false-positive rejection (planted FP never reproduces) | **1.0** |
| gate integrity: out-of-scope denied | **2/2** |
| gate integrity: kill switch halts | **2/2** |
| ledger verified after run | **2/2** |

Also fixed during this stage: a real shared-state bug — mission
grants referenced the module-level tool set, so one mission's grant
mutation stripped tools from all later missions. Grants are now
per-mission copies, with a regression test.

**Honest boundary:** these are PIPELINE metrics with known ground
truth, not model capability numbers. Model-facing evaluation (Inspect
AI, CyberGym-E2E, held-out suites) runs host-side on this harness
shape. No SOTA claim until those numbers exist.
