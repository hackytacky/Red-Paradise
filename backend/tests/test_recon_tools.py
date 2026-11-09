import pytest

from g9_backend.core.action_spec import make_action_spec
from g9_backend.tools.recon_tools import (
    AdapterArgError, build_subfinder_argv, build_masscan_argv, build_testssl_argv,
    dispatch_subfinder, dispatch_masscan, dispatch_testssl,
)

SPEC = {
    "action_id": "ACT-R", "engagement_id": "ENG-1", "principal_id": "agent:panoptes",
    "agent_id": "panoptes", "tool_id": "subfinder", "tool_version": "1",
    "normalized_arguments": {"flags": ""},
    "target_set": ["g9.local"], "working_directory": "/workspace/run",
    "environment_profile": "lab-plane", "sandbox_profile": "restricted-analysis",
    "network_policy_id": "netpol-redlab", "resource_budget": {"cpu": 1, "mem_gb": 1, "max_pps": 500},
    "policy_revision": "ceder@v1",
}


class TestSubfinder:
    def test_passive_domain_only(self):
        spec = make_action_spec(SPEC)
        argv = build_subfinder_argv(spec)
        assert "-d" in argv and "g9.local" in argv

    def test_http_targets_refused(self):
        spec = make_action_spec({**SPEC, "target_set": ["https://g9.local"]})
        with pytest.raises(AdapterArgError, match="bare domains"):
            build_subfinder_argv(spec)

    def test_dispatch_hardened(self):
        s = dispatch_subfinder(make_action_spec(SPEC)).shell()
        assert "--cap-drop ALL" in s and "subfinder" in s


class TestMasscan:
    def test_rate_ceiling_from_budget_not_flags(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "-p 443 --open-only"}})
        argv = build_masscan_argv(spec)
        assert "--rate" in argv
        assert argv[argv.index("--rate") + 1] == "500"  # from resource_budget.max_pps

    def test_rate_flag_refused(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "--rate 100000"}})
        with pytest.raises(AdapterArgError, match="allowlist"):
            build_masscan_argv(spec)

    def test_dispatch(self):
        s = dispatch_masscan(make_action_spec(SPEC)).shell()
        assert "--rate 500" in s and "--read-only" in s


class TestTestssl:
    def test_single_target_quiet(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "--severity HIGH"}})
        argv = build_testssl_argv(spec)
        assert argv[0] == "--quiet" and "g9.local" in argv

    def test_multi_target_refused(self):
        spec = make_action_spec({**SPEC, "target_set": ["a.g9.local", "b.g9.local"]})
        with pytest.raises(AdapterArgError, match="one authorized target"):
            build_testssl_argv(spec)

    def test_dispatch(self):
        s = dispatch_testssl(make_action_spec(SPEC)).shell()
        assert "testssl" in s and "--cap-drop ALL" in s
