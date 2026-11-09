"""g9-executor: approval/execution state machine.
Mirrors src/lib/approvalStateMachine.js. OUTCOME_UNKNOWN blocks replay
until execution evidence is reconciled — never automatic."""

from __future__ import annotations

EXEC_TRANSITIONS = {
    "CREATED": {"schema_valid": "SCHEMA_VALIDATED"},
    "SCHEMA_VALIDATED": {"policy_evaluated": "POLICY_EVALUATED"},
    "POLICY_EVALUATED": {"denied": "DENIED", "approval_required": "AWAITING_APPROVAL"},
    "AWAITING_APPROVAL": {"approved": "APPROVED", "rejected": "REJECTED"},
    "APPROVED": {"pre_execution_validation": "PRE_EXECUTION_VALIDATION"},
    "PRE_EXECUTION_VALIDATION": {"invalidated": "INVALIDATED", "dispatched": "DISPATCHED"},
    "DISPATCHED": {"running": "RUNNING"},
    "RUNNING": {"completed": "COMPLETED", "cancelled": "CANCELLED", "failed": "FAILED", "outcome_unknown": "OUTCOME_UNKNOWN"},
    "COMPLETED": {"evidence_preserved": "EVIDENCE_PRESERVED"},
}

RETRYABLE_WITHOUT_RECONCILIATION = {"FAILED", "CANCELLED"}


class Execution:
    def __init__(self, action_id: str, spec_digest: str, tool_id: str | None = None):
        self.action_id = action_id
        self.spec_digest = spec_digest
        self.tool_id = tool_id
        self.state = "CREATED"
        self.attempts = 0
        self.reconciled = False
        self.audit_log: list[dict] = [{"event": "created", "to": "CREATED", "note": ""}]


def transition(exec: Execution, event: str, approval=None, note: str = "") -> tuple[bool, str]:
    allowed = EXEC_TRANSITIONS.get(exec.state, {})
    if event not in allowed:
        return False, f"event {event!r} is not valid from state {exec.state}"
    target = allowed[event]

    if event == "dispatched":
        if approval is None or approval.bound_digest != exec.spec_digest:
            exec.state = "INVALIDATED"
            exec.audit_log.append({"event": "invalidated", "to": "INVALIDATED", "note": "approval digest mismatch or missing — dispatch refused"})
            return False, "pre-execution validation failed: approval not bound to this action digest"

    if event == "outcome_unknown":
        exec.reconciled = False
        exec.audit_log.append({"event": event, "to": target, "note": "worker lost after possible external side effect — replay blocked pending reconciliation"})
        exec.state = target
        return True, ""

    if event in ("failed", "cancelled"):
        exec.attempts += 1

    exec.audit_log.append({"event": event, "to": target, "note": note})
    exec.state = target
    return True, ""


def reconcile(exec: Execution, evidence: dict, side_effects: str | None = None) -> tuple[bool, str]:
    if exec.state != "OUTCOME_UNKNOWN":
        return False, f"reconciliation is only valid from OUTCOME_UNKNOWN (state: {exec.state})"
    if not evidence:
        return False, "reconciliation requires execution evidence"
    exec.reconciled = True
    exec.audit_log.append({"event": "reconciled", "to": exec.state, "note": "execution evidence recorded; retry permitted"})
    return True, ""


def can_retry(exec: Execution) -> tuple[bool, str]:
    if exec.state in RETRYABLE_WITHOUT_RECONCILIATION:
        return True, ""
    if exec.state == "OUTCOME_UNKNOWN":
        if exec.reconciled:
            return True, ""
        return False, "OUTCOME_UNKNOWN cannot be replayed until execution evidence is reconciled — automatic replay is prohibited"
    return False, f"state {exec.state} is not retryable"


def reset_for_retry(exec: Execution) -> tuple[bool, str]:
    ok, reason = can_retry(exec)
    if not ok:
        return False, reason
    exec.state = "PRE_EXECUTION_VALIDATION"
    exec.attempts += 1
    exec.audit_log.append({"event": "retry", "to": "PRE_EXECUTION_VALIDATION", "note": "re-entering pre-execution validation"})
    return True, ""
