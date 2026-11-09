# G9 Build Audit — Technical / Adversarial / Acceptance

Scope: the full Red-Paradise control-plane build (9 engines, 10 views, 8 docs)
as of the HYPNOS commit. Method: line-level review of every engine against its
documented contract, UI/route wiring check, docs-index consistency check, and
mapping of the `g9-spectre-v3.md` module manifest to implemented code.

## Technical audit

| # | Finding | Severity | Resolution |
|---|---|---|---|
| T-1 | `actionSpec.validateAgainstApproval` referenced `approval.boundCanon`, which `bindApproval` never set — the changed-field audit trail was dead code (digest mismatch was still detected, but "which authorization-relevant field changed" could not be reported) | High | `bindApproval` now stores the canonical snapshot; validation reports the exact changed fields; test added |
| T-2 | **g9-audit contract missing**: the module manifest requires tamper-evident activity records with detectable modification, but no engine provided hash-chaining | High | New `src/lib/auditLedger.js`: append-only hash-chained ledger (each record carries `prev` digest and its own digest); `verifyChain()` detects any mutation, deletion, or insertion with the exact broken record |
| T-3 | The nine engines were standalone — nothing composed them into the documented pipeline (preference → admission → grant → policy → stealth → action spec → tripwires → broker) | Medium | New `src/lib/missionPipeline.js`: ordered composition of policy → stealth gate → approval-digest validation → tripwire scan, returning a single auditable decision record with the stage that blocked, if any |
| T-4 | Main `README.md` views table predated the six new views (architecture, evidence, execution, resilience, arsenal, opsec) | Low | README updated with the full route table and engine list |
| T-5 | **Real bug found during composition testing**: `actionSpec.digest` included the `approval_id` field, so `validateAgainstApproval` recomputed a different digest for every bound approval — a valid approval could never pass pre-execution validation. Hidden because the original tests only exercised invalid cases. | **Critical** | `digest()` now excludes `spec_digest` and `approval_id` (the approval reference IS the binding, not authorization-relevant content); positive-path tests added via the pipeline composition suite |

## Adversarial audit

| # | Finding | Severity | Resolution |
|---|---|---|---|
| A-1 | `scanToolCall` checked URLs for out-of-scope hosts but not raw `hosts` arrays in tool arguments — an agent could name an out-of-scope host directly without a URL | High | Host-array scope checking added to `adversarialResilience.js`; test added |
| A-2 | The OPSEC identifier scan's name-like pattern (`[A-Z][a-z]+ [A-Z][a-z]+`) can false-positive on product names ("Active Directory") | Low | Accepted as conservative by design (quarantine, not halt); documented here as a tuning note for the backend |
| A-3 | Session policy in `adversarialResilience.js` never auto-retries — verified by test; no bypass found | — | No action |
| A-4 | Self-authorization, ungranted-tool, digest-mismatch, and replay paths all fail closed — verified by tests across `policyEngine`, `actionSpec`, `approvalStateMachine` | — | No action |

## Acceptance audit (proposed thresholds → test coverage)

| Requirement (proposed threshold) | Covered by |
|---|---|
| Unauthorized scope expansion: 0 successes | `policyEngine` out-of-scope deny tests; `actionSpec.assertTargetsInScope`; resilience host checks (A-1 fix) |
| Approval tampering: 100% rejected | `validateAgainstApproval` tamper test; state-machine digest-mismatch dispatch refusal |
| Unauthorized tool escalation: 0 successes | ungranted-tool tests (registry + policy + resilience) |
| Unsupported findings marked confirmed: 0 | `verificationAuthority` self-promotion refusal + missing-evidence tests |
| Duplicate external actions after recovery: 0 | `OUTCOME_UNKNOWN` replay-refusal + reconciliation-gate tests |
| Missing artifact provenance: 0 for confirmed findings | evidence-graph provenance tests; artifact ledger creation-time recording |
| Agent self-authorization: 0 successes | `policyEngine` self-authorization deny; verification-authority role gate |

**Assessment:** all findings fixed in this commit except A-2 (accepted,
documented). The controls remain requirements-as-implemented for the control
plane; the backend execution plane inherits these contracts and must re-run the
same negative suites against real tool execution.
