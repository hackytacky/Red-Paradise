import pytest

from g9_backend.lab import LabMission, run_full_lab_mission
from g9_backend.ops import BudgetError


class TestFullLabMission:
    def test_full_active_run_end_to_end(self):
        r = run_full_lab_mission()
        assert r["ok"]
        assert r["ledger_verified"] is True
        assert r["tokens_used"] > 0
        assert r["nodes"] > 10 and r["edges"] >= r["reproduced"]
        # every phase ran and every invocation cleared the gates
        for p in r["phases"]:
            for inv in p["invocations"]:
                assert inv["ok"], inv
        # real findings from the real chain
        templates = {f["template"] for f in r["findings_reproduced"]}
        assert "no-tls" in templates
        assert "outdated-server-banner" in templates
        assert any(t.startswith("missing-header-") for t in templates)
        assert any(t.startswith("exposed-path-") for t in templates)
        assert any(t == "open-port" for t in templates)
        # candidates were found and INDEPENDENTLY reproduced — never trusted
        assert r["candidates"] >= 9
        assert r["reproduced"] == r["candidates"]

    def test_durable_mission_survives_restart(self, tmp_path):
        db = tmp_path / "lab.db"
        r1 = run_full_lab_mission(db_path=str(db))
        assert r1["ledger_verified"]
        # a second mission on the same store continues the ledger chain
        m = LabMission(db_path=str(db))
        try:
            m.ledger.append("operator", "engagement.note", detail="restart check")
            ok, n, _ = m.ledger.verify_chain()
            # the chain CONTINUES: prior records + the report record + this note
            assert ok and n >= r1["ledger_records"] + 2
        finally:
            m.close()

    def test_out_of_scope_target_blocked(self):
        m = LabMission()
        try:
            r = m.invoke_out_of_scope("http-probe", "203.0.113.7:80")
            assert not r["ok"] and r["blocked_at"] == "policy"
            r2 = m.invoke_out_of_scope("portscan-scoped", "10.9.9.9:1234")
            assert not r2["ok"] and r2["blocked_at"] == "policy"
        finally:
            m.close()

    def test_ungranted_tool_blocked_at_policy(self):
        m = LabMission()
        try:
            m.engine.grants[m.engagement_id]["tools"].discard("tls-audit")
            r = m._invoke("tls-audit", m.http_target)
            assert not r["ok"] and r["blocked_at"] == "policy"
        finally:
            m.close()

    def test_kill_switch_halts_the_run(self):
        m = LabMission()
        try:
            m.budget.kill("operator test kill")
            r = m._invoke("http-probe", m.http_target)
            assert not r["ok"] and r["blocked_at"] in ("rate", "budget", "scope")
            # post-kill invocations keep failing until operator reset
            r2 = m._invoke("header-audit", m.http_target)
            assert not r2["ok"]
            m.budget.operator_reset()
            r3 = m._invoke("header-audit", m.http_target)
            assert r3["ok"], r3
        finally:
            m.close()

    def test_candidates_never_self_promote(self):
        m = LabMission()
        try:
            m.run()
            statuses = {n["validation_status"] for n in m.graph.nodes.values()
                        if n["klass"] == "finding"}
            # only candidate/reproduced — nothing enters as confirmed
            assert statuses <= {"candidate", "reproduced"}
        finally:
            m.close()

    def test_scanner_claim_alone_never_promotes(self):
        """A candidate whose re-probe does NOT reproduce stays a candidate."""
        m = LabMission()
        try:
            m.run()
            # plant a fake candidate (simulated scanner false positive)
            m.graph.add_node({
                "id": "find-cand-fake", "klass": "finding",
                "label": "[candidate] exposed-path-nope: 127.0.0.1:1",
                "scope": m.engagement_id, "source": "content-discovery",
                "provenance": {"tool": "content-discovery", "template": "exposed-path-nope"},
                "validation_status": "candidate", "meta": {"severity": "high"},
            })
            before = m.graph.nodes["find-cand-fake"]["validation_status"]
            report = m.verify_and_report([])
            after = m.graph.nodes["find-cand-fake"]["validation_status"]
            assert before == "candidate" and after == "candidate"
            assert not any(f["template"] == "exposed-path-nope"
                           for f in report["findings_reproduced"])
        finally:
            m.close()


class TestLabTargetLoopbackOnly:
    def test_binds_loopback_only(self):
        m = LabMission()
        try:
            assert m.target.host == "127.0.0.1"
            for scope in m.scopes:
                assert "127.0.0.1" in scope
        finally:
            m.close()
