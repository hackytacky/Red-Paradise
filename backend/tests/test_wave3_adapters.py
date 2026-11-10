import pytest

from g9_backend.core.action_spec import make_action_spec
from g9_backend.executor.invoke_chain import ADAPTERS, invoke_tool
from g9_backend.mcp import coverage_report, family_for_tool
from g9_backend.ops import BudgetController
from g9_backend.policy.engine import PolicyEngine
from g9_backend.tools.wave3_adapters import (
    build_dnstwist_argv, build_exiftool_argv, build_gobuster_argv,
    build_hakrawler_argv, build_holehe_argv, build_sherlock_argv,
    dispatch_ghunt, dispatch_garak,
)

SPEC = {
    "action_id": "ACT-W3", "engagement_id": "ENG-1", "principal_id": "agent:panoptes",
    "agent_id": "panoptes", "tool_id": "sherlock", "tool_version": "1",
    "normalized_arguments": {"usernames": ["labuser"]},
    "target_set": ["labuser"], "working_directory": "/workspace/run",
    "environment_profile": "lab-plane", "sandbox_profile": "restricted-analysis",
    "network_policy_id": "netpol", "resource_budget": {"cpu": 1, "mem_gb": 1},
    "policy_revision": "ceder@v1",
}


class TestWave3Adapters:
    def test_sherlock(self):
        argv = build_sherlock_argv(make_action_spec(SPEC))
        assert argv == ["labuser"]
        s = ADAPTERS["sherlock"](make_action_spec(SPEC)).shell()
        assert "sherlock" in s and "--cap-drop ALL" in s

    def test_sherlock_invalid_username_refused(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"usernames": ["rm -rf /"]}})
        with pytest.raises(Exception, match="invalid username"):
            build_sherlock_argv(spec)

    def test_holehe_requires_emails(self):
        spec = make_action_spec({**SPEC, "tool_id": "holehe", "normalized_arguments": {}})
        with pytest.raises(Exception, match="emails are required"):
            build_holehe_argv(spec)

    def test_ghunt_auth_env_name_only(self):
        spec = make_action_spec({**SPEC, "tool_id": "ghunt", "normalized_arguments": {"emails": ["a@b.c"]}})
        full = dispatch_ghunt(spec).argv
        assert "-e" in full and "GHUNT_COOKIES" in full
        assert not any("=" in a and a.startswith("GHUNT") for a in full)

    def test_gobuster_wordlist_and_target(self):
        spec = make_action_spec({
            **SPEC, "tool_id": "gobuster",
            "normalized_arguments": {"wordlist": "/words/admitted.txt"},
            "target_set": ["lab-api.g9.local"],
        })
        argv = build_gobuster_argv(spec)
        assert argv[0] == "dir" and "/words/admitted.txt" in argv and "https://lab-api.g9.local" in argv

    def test_gobuster_wordlist_required(self):
        spec = make_action_spec({**SPEC, "tool_id": "gobuster", "normalized_arguments": {}, "target_set": ["x.g9.local"]})
        with pytest.raises(Exception, match="wordlist"):
            build_gobuster_argv(spec)

    def test_exiftool_json_output(self):
        spec = make_action_spec({**SPEC, "tool_id": "exiftool", "normalized_arguments": {"files": ["/work/img.jpg"]}})
        assert build_exiftool_argv(spec) == ["-j", "/work/img.jpg"]

    def test_dnstwist_one_domain(self):
        spec = make_action_spec({**SPEC, "tool_id": "dnstwist", "target_set": ["g9.local"], "normalized_arguments": {}})
        assert build_dnstwist_argv(spec) == ["--registered", "g9.local"]
        two = make_action_spec({**SPEC, "tool_id": "dnstwist", "target_set": ["a.g9.local", "b.g9.local"], "normalized_arguments": {}})
        with pytest.raises(Exception, match="one authorized domain"):
            build_dnstwist_argv(two)

    def test_hakrawler_one_target(self):
        spec = make_action_spec({**SPEC, "tool_id": "hakrawler", "target_set": ["lab-api.g9.local"], "normalized_arguments": {}})
        argv = build_hakrawler_argv(spec)
        assert "-url" in argv and "https://lab-api.g9.local" in argv

    def test_garak_typed_target(self):
        spec = make_action_spec({**SPEC, "tool_id": "garak", "normalized_arguments": {"target_id": "local-lab-llm"}})
        argv = dispatch_garak(spec).shell()
        assert "--model local-lab-llm" in argv

    def test_all_registered_in_chain(self):
        for t in ["sherlock", "maigret", "holehe", "ghunt", "trufflehog", "gobuster",
                  "feroxbuster", "sublist3r", "wappalyzer-whatweb", "exiftool",
                  "hachoir", "dnstwist", "hakrawler", "promptfoo", "garak"]:
            assert t in ADAPTERS, f"{t} missing from invoke chain"

    def test_contracts_new_families(self):
        assert family_for_tool("exiftool") == "metadata-forensics"
        assert family_for_tool("dnstwist") == "typosquat-analysis"
        assert family_for_tool("hakrawler") == "web-crawl"
        cov = coverage_report()
        assert len(cov["contracted_tools"]) >= 40


class TestWave3ThroughChain:
    def build(self):
        engine = PolicyEngine(
            engagements={"ENG-1": {"scope": ["labuser", "lab-api.g9.local"], "roe_signed": True,
                                  "principals": {"agent:panoptes": {"revoked": False}}}},
            grants={"ENG-1": {"tools": {"sherlock", "exiftool"}}},
        )
        budget = BudgetController(engagement_id="ENG-1", token_budget=10_000,
                                  request_rate_per_min=60, cidr_scopes=["labuser", "lab-api.g9.local"])
        return engine, budget

    def test_sherlock_full_chain(self):
        engine, budget = self.build()
        r = invoke_tool(engine=engine, budget=budget,
                        spec=make_action_spec(SPEC), call={"usernames": ["labuser"]})
        assert r["ok"], r
        assert "sherlock" in r["command"] and "labuser" in r["command"]

    def test_exiftool_blocked_without_grant(self):
        engine, budget = self.build()
        engine.grants["ENG-1"]["tools"].discard("exiftool")
        spec = make_action_spec({**SPEC, "tool_id": "exiftool", "normalized_arguments": {"files": ["/work/x.jpg"]}})
        r = invoke_tool(engine=engine, budget=budget, spec=spec, call={"files": ["/work/x.jpg"]})
        assert not r["ok"] and r["blocked_at"] == "policy"
