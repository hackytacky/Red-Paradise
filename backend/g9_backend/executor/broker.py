"""g9-executor: the execution broker — composes policy evaluation,
approval binding, dispatch, and worker routing, recording every
decision in the tamper-evident audit ledger.

Worker classes (v3.0 §10): trusted service / restricted analysis /
hostile research VM. The KVMWorkerManager here is the interface with
an in-process stub: real KVM/QEMU guest lifecycle is Stage-02 work
and is intentionally not faked.
"""

from __future__ import annotations

from ..core.action_spec import (
    Approval, bind_approval, digest, make_action_spec, validate_against_approval,
)
from ..core.audit_ledger import AuditLedger
from ..policy.engine import PolicyEngine
from .state_machine import Execution, transition

WORKER_CLASSES = {
    "trusted-service": "hardened host service",
    "restricted-analysis": "restricted process/container sandbox",
    "hostile-research-vm": "disposable KVM guest — no G9 management credentials",
}


class KVMWorkerManager:
    """Interface for worker lifecycle. The stub records dispatches;
    a real implementation creates/destroys KVM guests, enforces
    network egress policy, and collects execution results."""

    def __init__(self) -> None:
        self.dispatched: list[dict] = []

    def dispatch(self, execution: Execution, spec: dict) -> dict:
        record = {
            "action_id": execution.action_id,
            "worker_class": spec.get("sandbox_profile", "restricted-analysis"),
            "tool": spec.get("tool_id"),
            "recorded": True,
        }
        self.dispatched.append(record)
        return record


class ExecutionBroker:
    def __init__(self, engine: PolicyEngine, ledger: AuditLedger, workers: KVMWorkerManager | None = None):
        self.engine = engine
        self.ledger = ledger
        self.workers = workers or KVMWorkerManager()
        self.executions: dict[str, Execution] = {}
        self.approvals: dict[str, Approval] = {}

    def register(self, spec_data: dict) -> dict:
        spec = make_action_spec(spec_data)
        execution = Execution(spec["action_id"], spec["spec_digest"], spec.get("tool_id"))
        self.executions[spec["action_id"]] = execution
        self.ledger.append(actor=spec.get("principal_id", "unknown"), action="action-registered", subject=spec["action_id"])
        transition(execution, "schema_valid")
        return {"action_id": spec["action_id"], "spec_digest": spec["spec_digest"], "state": execution.state}

    def evaluate_policy(self, request: dict) -> dict:
        decision = self.engine.evaluate(request)
        execution = self.executions.get(request.get("action_id", ""))
        if execution is not None and execution.state == "SCHEMA_VALIDATED":
            transition(execution, "policy_evaluated")
            if decision.effect == "deny":
                transition(execution, "denied", note="; ".join(decision.reasons))
            else:
                transition(execution, "approval_required")
        self.ledger.append(
            actor=request.get("principal_id", "unknown"),
            action="policy-evaluated",
            subject=request.get("action_id"),
            detail=f"{decision.effect}: {'; '.join(decision.reasons) if decision.reasons else 'all checks passed'}",
        )
        return {"effect": decision.effect, "reasons": decision.reasons, "state": execution.state if execution else None}

    def approve(self, action_id: str, approval_id: str, approved_by: str) -> dict:
        execution = self.executions.get(action_id)
        if execution is None:
            raise KeyError(f"unknown action {action_id}")
        if execution.state != "AWAITING_APPROVAL":
            return {"ok": False, "reason": f"action {action_id} is {execution.state}, not AWAITING_APPROVAL"}
        # bind approval to the digest of the CURRENT spec content
        approval = Approval(
            approval_id=approval_id, approved_by=approved_by,
            bound_digest=execution.spec_digest, bound_canon="", action_id=action_id, at="",
        )
        self.approvals[action_id] = approval
        transition(execution, "approved", note=f"approved by {approved_by} as {approval_id}")
        transition(execution, "pre_execution_validation")
        return {"ok": True, "state": execution.state}

    def dispatch(self, action_id: str, spec: dict) -> dict:
        execution = self.executions.get(action_id)
        if execution is None:
            raise KeyError(f"unknown action {action_id}")
        approval = self.approvals.get(action_id)
        ok, changed, reason = validate_against_approval(spec, approval)
        if not ok:
            self.ledger.append(actor="broker", action="dispatch-refused", subject=action_id, detail=reason)
            return {"ok": False, "reason": reason, "changed": changed, "state": execution.state}
        ok, reason = transition(execution, "dispatched", approval=approval)
        if not ok:
            return {"ok": False, "reason": reason, "state": execution.state}
        transition(execution, "running")
        worker_record = self.workers.dispatch(execution, spec)
        self.ledger.append(actor="broker", action="dispatched", subject=action_id, detail=f"worker class {worker_record['worker_class']}")
        return {"ok": True, "state": execution.state, "worker": worker_record}
