import pytest

from g9_backend.ops.engagement_manager import EngagementError, EngagementManager


class TestEngagementManager:
    def test_quickstart_creates_lab_engagement(self):
        mgr = EngagementManager()
        rec = mgr.quickstart_lab()
        assert rec["roe_signed"] is True
        assert rec["status"] == "active"
        assert rec["tier"] == "lab"
        assert "portscan-scoped" in rec["grants"]
        assert len(mgr.list()) == 1

    def test_scope_required(self):
        mgr = EngagementManager()
        with pytest.raises(EngagementError, match="non-empty authorized scope"):
            mgr.create(engagement_id="E1", scope=[], roe_signed=True,
                       principals=["operator"], grants=set())

    def test_unsigned_roe_is_red_locked(self):
        mgr = EngagementManager()
        mgr.create(engagement_id="E2", scope=["t.example.com"], roe_signed=False,
                   principals=["operator"], grants={"nmap-scoped"})
        v = mgr.verify_target("E2", "t.example.com")
        assert not v["ok"] and "red tier locked" in v["reason"]

    def test_scope_is_the_only_source_of_targets(self):
        mgr = EngagementManager()
        mgr.create(engagement_id="E3", scope=["t.example.com"], roe_signed=True,
                   principals=["operator"], grants={"nmap-scoped"})
        assert mgr.verify_target("E3", "t.example.com")["ok"]
        v = mgr.verify_target("E3", "other.example.com")
        assert not v["ok"] and "outside authorized scope" in v["reason"]

    def test_duplicate_engagement_refused(self):
        mgr = EngagementManager()
        mgr.create(engagement_id="E4", scope=["a.com"], roe_signed=True,
                   principals=["o"], grants=set())
        with pytest.raises(EngagementError, match="already exists"):
            mgr.create(engagement_id="E4", scope=["a.com"], roe_signed=True,
                       principals=["o"], grants=set())
