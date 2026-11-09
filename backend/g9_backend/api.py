"""G9 control-plane HTTP surface (FastAPI).

Loopback dev server only in this scaffold; deployment hardening is
Stage-07/08 work.
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from .core.audit_ledger import AuditLedger
from .executor.broker import ExecutionBroker, KVMWorkerManager
from .policy.engine import PolicyEngine

app = FastAPI(title="G9 SPECTRE control plane", version="0.1.0")

# Demo engagement state — the real service loads this from the
# engagement scope manager (Stage 01).
ENGAGEMENTS = {
    "ENG-REDLAB-7": {
        "scope": ["lab-api.g9.local", "lab-portal.g9.local", "lab-dc-01.g9.local"],
        "roe_signed": True,
        "principals": {"agent:hydra-svc": {"revoked": False}, "agent:chimera": {"revoked": False}},
    },
}
GRANTS = {"ENG-REDLAB-7": {"tools": {"nmap-scoped", "httpx", "bloodhound-ce"}}}

_ledger = AuditLedger("ENG-REDLAB-7")
_engine = PolicyEngine(ENGAGEMENTS, GRANTS)
_broker = ExecutionBroker(_engine, _ledger, KVMWorkerManager())


class PolicyRequest(BaseModel):
    engagement_id: str
    principal_id: str
    tool_id: str
    targets: list[str]
    action_id: str | None = None
    sandbox_class: str | None = None
    required_sandbox_class: str | None = None
    high_impact: bool = False
    approval_id: str | None = None
    self_authorized: bool = False


class ActionSpecIn(BaseModel):
    action_id: str
    engagement_id: str
    principal_id: str
    agent_id: str
    tool_id: str
    tool_version: str
    normalized_arguments: dict
    target_set: list[str]
    working_directory: str
    environment_profile: str
    sandbox_profile: str
    network_policy_id: str
    resource_budget: dict
    policy_revision: str


@app.post("/policy/evaluate")
def evaluate_policy(req: PolicyRequest):
    return _engine.evaluate(req.model_dump())


@app.post("/actions")
def register_action(spec: ActionSpecIn):
    return _broker.register(spec.model_dump())


@app.post("/actions/{action_id}/approve")
def approve_action(action_id: str, approval_id: str, approved_by: str):
    return _broker.approve(action_id, approval_id, approved_by)


@app.post("/actions/{action_id}/dispatch")
def dispatch_action(action_id: str, spec: ActionSpecIn):
    return _broker.dispatch(action_id, spec.model_dump())


@app.get("/audit")
def audit(actor: str | None = None, action: str | None = None):
    ok, reason, records = _ledger.query(actor=actor, action=action)
    return {
        "integrity_ok": ok,
        "reason": reason,
        "records": [
            {"seq": r.seq, "actor": r.actor, "action": r.action, "subject": r.subject, "detail": r.detail, "digest": r.digest[:16] + "…"}
            for r in records
        ],
    }
