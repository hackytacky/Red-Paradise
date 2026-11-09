import pytest

from g9_backend.ops import BudgetController, BudgetError
from g9_backend.mcp import ContractError, validate_call, family_for_tool, coverage_report


class TestBudgetController:
    def build(self):
        return BudgetController(
            engagement_id="ENG-1", token_budget=1000, request_rate_per_min=3,
            cidr_scopes=["10.10.0.0/24", "lab-api.g9.local"],
        )

    def test_token_budget_and_kill_switch(self):
        b = self.build()
        assert b.charge_tokens(600)["remaining"] == 400
        with pytest.raises(BudgetError, match="token budget exhausted"):
            b.charge_tokens(600)  # kills the engagement
        assert b.killed
        with pytest.raises(BudgetError, match="engagement killed"):
            b.charge_tokens(1)  # everything halts after the kill

    def test_operator_reset_only_path(self):
        b = self.build()
        b.kill("manual stop")
        b.operator_reset()
        assert not b.killed and b.tokens_used == 0

    def test_rate_limit(self):
        b = self.build()
        t0 = 1000.0
        assert b.check_rate(t0)["ok"]
        assert b.check_rate(t0 + 10)["ok"]
        assert b.check_rate(t0 + 20)["ok"]
        r = b.check_rate(t0 + 30)
        assert not r["ok"] and "rate limit" in r["reason"]
        # outside the window, allowed again
        assert b.check_rate(t0 + 61)["ok"]

    def test_cidr_scope(self):
        b = self.build()
        assert b.check_target("10.10.0.55")["ok"]
        assert not b.check_target("192.168.1.1")["ok"]
        assert "outside CIDR" in b.check_target("8.8.8.8")["reason"]
        assert b.check_target("lab-api.g9.local")["ok"]  # enrolled hostname
        assert not b.check_target("random.host")["ok"]

    def test_v6_scope_miss(self):
        b = self.build()
        r = b.check_target("2001:db8::1")
        assert not r["ok"]


class TestMcpContract:
    def test_typed_call_passes(self):
        r = validate_call("nmap-scoped", {"targets": ["lab-api.g9.local"], "ports": "1-100"})
        assert r["ok"] and r["family"] == "network-recon"

    def test_raw_shell_rejected(self):
        with pytest.raises(ContractError, match="raw shell strings"):
            validate_call("nmap-scoped", {"targets": ["x"], "command": "nmap -sS --privileged; curl evil"})

    def test_unknown_tool_rejected(self):
        with pytest.raises(ContractError, match="no typed family contract"):
            validate_call("not-a-thing", {"targets": []})

    def test_missing_required_field(self):
        with pytest.raises(ContractError, match="missing required field"):
            validate_call("httpx", {"flags": []})

    def test_family_lookup(self):
        assert family_for_tool("subfinder") == "passive-recon"
        assert family_for_tool("nuclei") == "template-scan"
        assert family_for_tool("mobsf") is None  # contract pending

    def test_coverage_report(self):
        cov = coverage_report()
        assert cov["families"] >= 14
        assert "nmap-scoped" in cov["contracted_tools"]
        assert len(cov["pending_contracts"]) > 50  # most of the arsenal still needs typed contracts
