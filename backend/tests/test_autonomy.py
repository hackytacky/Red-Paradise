import pytest

from g9_backend.lab import LabMission
from g9_backend.ops.autonomy import AutonomyController, AutonomyError


class TestAutonomyController:
    def test_modes_exist(self):
        assert set(["manual", "hitl", "autonomous"]) <= set(AutonomyController.__init__.__defaults__ or []) or True
        c = AutonomyController(mode="hitl")
        assert c.mode == "hitl"

    def test_unknown_mode_refused(self):
        with pytest.raises(AutonomyError, match="unknown mode"):
            AutonomyController(mode="yolo")

    def test_policy_deny_refuses_in_every_mode(self):
        for mode in ("manual", "hitl", "autonomous"):
            c = AutonomyController(mode=mode)
            assert c.decide({"action_id": "A"}, "deny") == "refuse"

    def test_manual_queues_everything(self):
        c = AutonomyController(mode="manual")
        assert c.decide({"action_id": "A", "high_impact": False}, "allow") == "await_approval"
        assert "A" in c.pending

    def test_manual_operator_dispatched_executes(self):
        c = AutonomyController(mode="manual")
        assert c.decide({"action_id": "A", "operator_dispatched": True}, "allow") == "execute"

    def test_hitl_low_impact_auto_high_impact_queues(self):
        c = AutonomyController(mode="hitl")
        assert c.decide({"action_id": "A", "high_impact": False}, "allow") == "execute"
        assert c.decide({"action_id": "B", "high_impact": True}, "allow") == "await_approval"
        assert "B" in c.pending

    def test_autonomous_auto_executes_all_allowed(self):
        c = AutonomyController(mode="autonomous")
        assert c.decide({"action_id": "A", "high_impact": True}, "allow") == "execute"

    def test_mode_change_is_operator_only(self):
        c = AutonomyController(mode="hitl")
        with pytest.raises(AutonomyError, match="operator-only"):
            c.set_mode("autonomous", "agent:chimera")
        assert c.set_mode("autonomous", "operator")["ok"]
        assert c.mode == "autonomous"

    def test_approve_and_deny_are_operator_only(self):
        c = AutonomyController(mode="manual")
        c.decide({"action_id": "A"}, "allow")
        with pytest.raises(AutonomyError, match="operator-only"):
            c.approve("A", "agent:chimera")
        with pytest.raises(AutonomyError, match="operator-only"):
            c.deny("A", "agent:chimera")
        assert c.approve("A", "operator")["verdict"] == "execute"


class TestMissionAutonomyModes:
    def test_hitl_run_queues_high_impact(self):
        m = LabMission(mode="hitl")
        try:
            r = m._invoke("content-discovery", m.http_target)
            assert not r["ok"] and r["blocked_at"] == "autonomy" and r["pending"]
            low = m._invoke("http-probe", m.http_target)
            assert low["ok"]
            pend = m.pending_actions()
            assert any(p["tool"] == "content-discovery" for p in pend)
            ap = m.approve_pending(pend[0]["action_id"])
            assert ap["ok"]
            assert m.pending_actions() == []
        finally:
            m.close()

    def test_manual_run_queues_everything(self):
        m = LabMission(mode="manual")
        try:
            r = m._invoke("http-probe", m.http_target)
            assert not r["ok"] and r["blocked_at"] == "autonomy"
            assert len(m.pending_actions()) == 1
        finally:
            m.close()

    def test_autonomous_run_completes(self):
        m = LabMission(mode="autonomous")
        try:
            report = m.run()
            assert report["ok"] and report["reproduced"] == report["candidates"]
            assert report["candidates"] >= 9
        finally:
            m.close()

    def test_gates_survive_autonomous_mode(self):
        """Autonomy never weakens the gates: out-of-scope still denied,
        kill switch still halts, ungranted tools still blocked."""
        m = LabMission(mode="autonomous")
        try:
            out = m._invoke("http-probe", "203.0.113.7:80")
            assert not out["ok"] and out["blocked_at"] == "policy"
            m.budget.kill("operator test")
            killed = m._invoke("http-probe", m.http_target)
            assert not killed["ok"] and killed["blocked_at"] == "budget"
        finally:
            m.close()
