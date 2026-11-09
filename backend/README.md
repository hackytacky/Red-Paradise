# g9-backend — SPECTRE control-plane scaffold

FastAPI service implementing the same contracts as the `src/lib` engines in
the control-plane UI, in the Python runtime the production control plane
targets (per `docs/architecture/g9-spectre-v3.md` §6: FastAPI for the initial
control plane, Pydantic for structured contracts).

## Modules

| Module | Contract (mirrors) | Responsibility |
|---|---|---|
| `g9_backend/core/action_spec.py` | `src/lib/actionSpec.js` | Canonical 16-field action specification; **SHA-256** digest (production-grade, replacing the demo FNV digest); approval bound to the digest; tamper invalidation with exact changed fields |
| `g9_backend/core/audit_ledger.py` | `src/lib/auditLedger.js` | Append-only hash-chained (SHA-256) activity records; chain verification detects mutation/deletion/insertion at the exact record |
| `g9_backend/policy/engine.py` | `src/lib/policyEngine.js` | Cedar-style deny-by-default policy decision point; seven checks; precise deny reasons; recorded decisions |
| `g9_backend/executor/state_machine.py` | `src/lib/approvalStateMachine.js` | CREATED → … → EVIDENCE_PRESERVED with DENIED/REJECTED/INVALIDATED/CANCELLED/FAILED/OUTCOME_UNKNOWN; OUTCOME_UNKNOWN blocks replay until reconciled |
| `g9_backend/executor/broker.py` | pipeline composition | The execution broker: composes policy → approval-binding → dispatch, records everything in the audit ledger, and routes work to worker classes (trusted service / restricted analysis / hostile research VM) |
| `g9_backend/api.py` | — | HTTP surface: `POST /policy/evaluate`, `POST /actions` (register + approve + dispatch), `GET /audit` |

## Run

```bash
cd backend
uv sync
uv run pytest              # contract tests
uv run uvicorn g9_backend.api:app --port 8700   # loopback dev server
```

## Boundary honesty

This scaffold implements the **control-plane contracts** with real SHA-256
digests and a real policy/audit/execution state machine. The **worker plane**
(`KVMWorkerManager`) is an interface with an in-process stub worker: real
KVM/QEMU guest lifecycle, network egress enforcement, and tool adapters are
the Stage-02 work and are intentionally not faked here.
