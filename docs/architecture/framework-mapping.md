# Framework Mapping — requirements → implementation

The operator's framework requirements, mapped to what exists in the build.

| Requirement | Status | Implementation |
|---|---|---|
| **MCP servers per tool family — typed interfaces, never LLM-composed shell strings** | ✅ implemented | `backend/g9_backend/mcp/contract.py`: 14 typed tool-family contracts; `validate_call` rejects raw shell strings at the boundary; `coverage_report` tracks which tools have contracts (28 contracted, the rest pending — contracts land with each adapter) |
| **Execution sandbox — per-engagement, snapshot, egress allowlist** | ✅ implemented | `executor/container_runtime.py` (hardened container profile) + `worker_manager.py` (KVM boundary for hostile work) + `ops/budget_controller.py` (CIDR egress scope) |
| **Findings graph — hosts/creds/services, reachable-via edges, plan over the graph not prose** | ✅ implemented | `src/lib/evidenceGraph.js` (typed nodes, verified-link attack-path reasoning) + `graph` module in the manifest (Neo4j on the host) |
| **Evidence store — raw stdout, timestamps, command hash** | ✅ implemented | `core/audit_ledger.py` (hash-chained) + action-spec digests + `opsecGuardian` artifact ledger |
| **Deterministic validators — cheap re-check after every exploit claim** | ✅ implemented | `verificationAuthority.js` (agents never self-promote; deterministic PoV required) + `researchLoop` reproduce stage |
| **Budget/scope controller — token budget, request rate, CIDR scope, kill switch** | ✅ implemented | `backend/g9_backend/ops/budget_controller.py`: token budget with kill-on-exhaust, sliding-window rate limit, CIDR + enrolled-hostname scope checks, operator-only reset |
| **Agent orchestration (LangGraph)** | selected | v3.0 selection; benchmark LangGraph vs Strands vs Pydantic AI at Stage 03 |
| **LiteLLM / vLLM / Ollama** | registered | model routing + air-gapped local inference entries in the registry |
| **Temporal (durable workflow)** | deferred | v3.0 decision: native checkpointing first; Temporal only when justified |
| **XBOW / Big Sleep / AIxCC CRS / commercial platforms** | registered as references | study patterns; closed-source ones are not integrable |

## Registry scale

346 entries across container (104), service (131), and KVM (109) classes;
20 unverified entries excluded from automated pipelines; every
`separate_auth` / `license_required` / `legal_gate` / `lab_only` flag enforced
by `registry_admission.py` before qualification.
