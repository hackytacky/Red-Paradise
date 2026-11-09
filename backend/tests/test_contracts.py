import pytest

from g9_backend.core.action_spec import (
    ActionSpecError, bind_approval, digest, make_action_spec, validate_against_approval,
    assert_targets_in_scope,
)
from g9_backend.core.audit_ledger import AuditLedger
from g9_backend.policy.engine import PolicyEngine
from g9_backend.executor.state_machine import Execution, transition, reconcile, can_retry, reset_for_retry
from g9_backend.executor.broker import ExecutionBroker, KVMWorkerManager

SPEC = {
    "action_id": "ACT-1", "engagement_id": "ENG-1", "principal_id": "agent:hydra-svc",
    "agent_id": "hydra-svc", "tool_id": "nmap-scoped", "tool_version": "7.95",
    "normalized_arguments": {"flags": "-sS", "hosts": ["lab-api.g9.local"]},
    "target_set": ["lab-api.g9.local"], "working_directory": "/run",
    "environment_profile": "lab-plane", "sandbox_profile": "restricted-analysis",
    "network_policy_id": "NETPOL-1", "resource_budget": {"cpu": 1}, "policy_revision": "ceder@v1",
}


class TestActionSpec:
    def test_digest_is_sha256_and_approval_independent(self):
        spec = make_action_spec(SPEC)
        assert len(spec["spec_digest"]) == 64
        # approval_id never affects the digest (T-5 regression guard)
        assert digest({**SPEC, "approval_id": "APR-1"}) == spec["spec_digest"]

    def test_valid_approval_passes_validation(self):
        spec = make_action_spec(SPEC)
        approval = bind_approval(spec, "APR-1", "operator")
        ok, changed, reason = validate_against_approval(spec, approval)
        assert ok, reason

    def test_tamper_invalidates_with_exact_changed_fields(self):
        spec = make_action_spec(SPEC)
        approval = bind_approval(spec, "APR-1", "operator")
        tampered = {**spec, "target_set": ["other.host"]}
        ok, changed, reason = validate_against_approval(tampered, approval)
        assert not ok
        assert changed == ["target_set"]

    def test_missing_fields_rejected(self):
        with pytest.raises(ActionSpecError):
            make_action_spec({k: v for k, v in SPEC.items() if k != "tool_id"})
        with pytest.raises(ActionSpecError):
            make_action_spec({**SPEC, "target_set": []})

    def test_scope_check(self):
        spec = make_action_spec(SPEC)
        ok, _ = assert_targets_in_scope(spec, ["lab-api.g9.local"])
        assert ok
        ok, reason = assert_targets_in_scope(spec, ["evil.host"])
        assert not ok and "evil.host" in reason


class TestAuditLedger:
    def test_chain_and_tamper_detection(self):
        ledger = AuditLedger("ENG-1")
        a = ledger.append("agent", "dispatch", "ACT-1")
        b = ledger.append("cerberus", "evidence-preserved", "F-1")
        assert b.prev == a.digest
        ok, _, _ = ledger.verify_chain()
        assert ok
        ledger.records[0].detail = "rewritten"
        ok, broken, reason = ledger.verify_chain()
        assert not ok and broken == 0 and "tampering" in reason

    def test_tampered_ledger_refuses_queries(self):
        ledger = AuditLedger("ENG-1")
        ledger.append("a", "one")
        ledger.append("a", "two")
        ledger.records[1].action = "TAMPERED"
        ok, reason, records = ledger.query()
        assert not ok and records == []


class TestPolicyEngine:
    def build(self, roe_signed=True):
        return PolicyEngine(
            engagements={"ENG-1": {
                "scope": ["lab-api.g9.local"],
                "roe_signed": roe_signed,
                "principals": {"agent:hydra-svc": {"revoked": False}},
            }},
            grants={"ENG-1": {"tools": {"nmap-scoped"}}},
        )

    def req(self, **over):
        r = {"engagement_id": "ENG-1", "principal_id": "agent:hydra-svc",
             "tool_id": "nmap-scoped", "targets": ["lab-api.g9.local"]}
        r.update(over)
        return r

    def test_allow(self):
        d = self.build().evaluate(self.req())
        assert d.effect == "allow"

    def test_denies(self):
        assert self.build().evaluate(self.req(targets=["x.host"])).effect == "deny"
        assert self.build(roe_signed=False).evaluate(self.req()).effect == "deny"
        assert self.build().evaluate(self.req(tool_id="other")).effect == "deny"
        assert self.build().evaluate(self.req(self_authorized=True)).effect == "deny"
        assert self.build().evaluate(self.req(high_impact=True)).effect == "deny"


class TestStateMachine:
    def test_outcome_unknown_blocks_replay_until_reconciled(self):
        from types import SimpleNamespace
        approval = SimpleNamespace(bound_digest=Execution.__init__ and "fake-digest")
        e = Execution("A", "fake-digest")
        for ev in ["schema_valid", "policy_evaluated", "approval_required", "approved", "pre_execution_validation"]:
            ok, reason = transition(e, ev)
            assert ok, reason
        ok, reason = transition(e, "dispatched", approval=approval)
        assert ok, reason
        ok, reason = transition(e, "running")
        assert ok, reason
        ok, _ = transition(e, "outcome_unknown")
        assert ok and e.state == "OUTCOME_UNKNOWN"
        ok, reason = can_retry(e)
        assert not ok and "reconciled" in reason
        assert not reset_for_retry(e)[0]
        ok, reason = reconcile(e, {"logs": "sha256:…"})
        assert ok
        assert can_retry(e)[0]
        assert reset_for_retry(e)[0] and e.state == "PRE_EXECUTION_VALIDATION"


class TestBroker:
    def test_full_flow_and_tamper_refusal(self):
        engine = PolicyEngine(
            engagements={"ENG-1": {"scope": SPEC["target_set"], "roe_signed": True,
                                    "principals": {"agent:hydra-svc": {"revoked": False}}}},
            grants={"ENG-1": {"tools": {"nmap-scoped"}}},
        )
        ledger = AuditLedger("ENG-1")
        broker = ExecutionBroker(engine, ledger, KVMWorkerManager())

        r = broker.register(SPEC)
        assert r["state"] == "SCHEMA_VALIDATED"

        pol = broker.evaluate_policy({"engagement_id": "ENG-1", "principal_id": "agent:hydra-svc",
                                       "tool_id": "nmap-scoped", "targets": SPEC["target_set"],
                                       "action_id": "ACT-1"})
        assert pol["effect"] == "allow" and pol["state"] == "AWAITING_APPROVAL"

        ap = broker.approve("ACT-1", "APR-1", "operator")
        assert ap["ok"] and ap["state"] == "PRE_EXECUTION_VALIDATION"

        spec = make_action_spec(SPEC)
        d = broker.dispatch("ACT-1", spec)
        assert d["ok"] and d["state"] == "RUNNING"
        assert d["worker"]["worker_class"] == "restricted-analysis"

        # tampered dispatch must be refused
        r2 = broker.register({**SPEC, "action_id": "ACT-2"})
        broker.evaluate_policy({"engagement_id": "ENG-1", "principal_id": "agent:hydra-svc",
                                 "tool_id": "nmap-scoped", "targets": SPEC["target_set"],
                                 "action_id": "ACT-2"})
        broker.approve("ACT-2", "APR-2", "operator")
        tampered = make_action_spec({**SPEC, "action_id": "ACT-2", "normalized_arguments": {"flags": "-T5", "hosts": ["lab-api.g9.local"]}})
        d2 = broker.dispatch("ACT-2", tampered)
        assert not d2["ok"] and "invalidated" in d2["reason"]

        ok, reason, records = ledger.query()
        assert ok and len(records) >= 6
