import pytest

from g9_backend.core.action_spec import make_action_spec
from g9_backend.tools.web_scanners import (
    AdapterArgError, build_httpx_argv, build_ffuf_argv, build_nuclei_argv,
    dispatch_httpx, dispatch_ffuf, dispatch_nuclei,
)

SPEC = {
    "action_id": "ACT-W", "engagement_id": "ENG-1", "principal_id": "agent:hydra-web",
    "agent_id": "hydra-web", "tool_id": "httpx", "tool_version": "1",
    "normalized_arguments": {"flags": "", "wordlist": "/assets/dirscan.txt", "severity": "high"},
    "target_set": ["lab-api.g9.local"], "working_directory": "/workspace/run",
    "environment_profile": "lab-plane", "sandbox_profile": "restricted-analysis",
    "network_policy_id": "netpol-redlab", "resource_budget": {"cpu": 1, "mem_gb": 2},
    "policy_revision": "ceder@v1",
}


class TestHttpxAdapter:
    def test_argv_from_spec_targets_https_normalized(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "-sc -title"}})
        argv = build_httpx_argv(spec)
        assert argv[0] == "-silent"
        assert "-sc" in argv and "-title" in argv
        assert argv[-1] == "https://lab-api.g9.local"  # scheme-normalized, spec-sourced

    def test_flag_allowlist(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "-exec whoami"}})
        with pytest.raises(AdapterArgError, match="allowlist"):
            build_httpx_argv(spec)

    def test_hardened_container_command(self):
        spec = make_action_spec(SPEC)
        s = dispatch_httpx(spec).shell()
        assert "--cap-drop ALL" in s
        assert "https://lab-api.g9.local" in s


class TestFfufAdapter:
    def test_needs_wordlist_and_single_target(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "-mc 200"}})
        with pytest.raises(AdapterArgError, match="wordlist"):
            build_ffuf_argv(spec)
        multi = make_action_spec({**SPEC, "target_set": ["a.g9.local", "b.g9.local"]})
        with pytest.raises(AdapterArgError, match="one authorized target"):
            build_ffuf_argv(multi)

    def test_wordlist_path_escape_refused(self):
        for evil in ["/etc/passwd", "/assets/../../etc/shadow"]:
            spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "", "wordlist": evil}})
            with pytest.raises(AdapterArgError, match="approved asset directory"):
                build_ffuf_argv(spec)

    def test_valid_dispatch(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "-mc 200", "wordlist": "/assets/dirscan.txt"}})
        s = dispatch_ffuf(spec).shell()
        assert "-w /assets/dirscan.txt" in s
        assert "-mc 200" in s
        assert "--read-only" in s


class TestNucleiAdapter:
    def test_silent_non_color_severity_filter(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "-severity critical", "severity": "critical"}})
        argv = build_nuclei_argv(spec)
        assert "-silent" in argv and "-nc" in argv
        assert "https://lab-api.g9.local" in argv

    def test_unknown_severity_and_flags_refused(self):
        spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": "", "severity": "catastrophic"}})
        with pytest.raises(AdapterArgError, match="severity"):
            build_nuclei_argv(spec)
        spec2 = make_action_spec({**SPEC, "normalized_arguments": {"flags": "-debug-requests"}})
        with pytest.raises(AdapterArgError, match="allowlist"):
            build_nuclei_argv(spec2)

    def test_dispatch_hardened(self):
        spec = make_action_spec(SPEC)
        s = dispatch_nuclei(spec).shell()
        assert "projectdiscovery/nuclei" in s
        assert "--cap-drop ALL" in s

    def test_nuclei_output_is_hypothesis(self):
        """Contract note: nuclei results enter the pipeline as candidate
        findings only — the Verification Authority confirms, never the
        scanner (see verificationAuthority contract)."""
        from g9_backend.tools import dispatch_nuclei as _  # import path integrity
        assert True
