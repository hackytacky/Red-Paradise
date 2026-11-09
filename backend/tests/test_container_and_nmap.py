import pytest

from g9_backend.core.action_spec import make_action_spec, bind_approval
from g9_backend.executor.container_runtime import build_command, execute, RuntimeError_
from g9_backend.tools.nmap_adapter import dispatch, build_nmap_argv, RuntimeArgError

SPEC = {
    "action_id": "ACT-N1", "engagement_id": "ENG-1", "principal_id": "agent:hydra-svc",
    "agent_id": "hydra-svc", "tool_id": "nmap-scoped", "tool_version": "7.95",
    "normalized_arguments": {"flags": "-sS -sV -Pn", "ports": "1-1000"},
    "target_set": ["lab-api.g9.local"], "working_directory": "/workspace/run",
    "environment_profile": "lab-plane", "sandbox_profile": "restricted-analysis",
    "network_policy_id": "netpol-redlab", "resource_budget": {"cpu": 2, "mem_gb": 4},
    "policy_revision": "ceder@v1",
}


class TestContainerRuntime:
    def test_hardened_command_construction(self):
        spec = make_action_spec(SPEC)
        cmd = build_command(spec, "img:1", ["-sS", "target"])
        s = cmd.shell()
        assert "--cap-drop ALL" in s
        assert "--security-opt no-new-privileges" in s
        assert "--read-only" in s
        assert "--pids-limit 64" in s
        assert "--network netpol-redlab" in s
        assert "--memory 4g" in s
        assert "--cpus 2" in s
        assert "--tmpfs /tmp:rw,noexec,nosuid,size=64m" in s
        assert "-v /workspace/run:/work:ro" in s  # working dir mounted READ-ONLY
        assert s.endswith("img:1 -sS target")

    def test_hostile_research_never_containerized(self):
        spec = make_action_spec({**SPEC, "sandbox_profile": "hostile-research-vm"})
        with pytest.raises(RuntimeError_, match="never containerized"):
            build_command(spec, "img:1", [])

    def test_unknown_profile_refused(self):
        spec = make_action_spec({**SPEC, "sandbox_profile": "bare-metal"})
        with pytest.raises(RuntimeError_, match="unknown sandbox profile"):
            build_command(spec, "img:1", [])


class TestNmapAdapter:
    def test_argv_built_from_spec_only(self):
        spec = make_action_spec(SPEC)
        argv = build_nmap_argv(spec)
        assert argv[:3] == ["-sS", "-sV", "-Pn"]
        assert argv[3] == "-p"
        assert argv[4] == "1-1000"
        assert argv[-1] == "lab-api.g9.local"  # from target_set, never free-form

    def test_flag_allowlist_enforced(self):
        for bad in ["--script=vuln", "-iL", "--privileged", "-6"]:
            spec = make_action_spec({**SPEC, "normalized_arguments": {"flags": bad, "ports": "1-100"}})
            with pytest.raises(RuntimeArgError, match="allowlist|forbidden"):
                build_nmap_argv(spec)

    def test_dispatch_produces_hardened_gated_command(self):
        spec = make_action_spec(SPEC)
        cmd = dispatch(spec)
        s = cmd.shell()
        assert "instrumentisto/nmap:latest" in s
        assert "--cap-drop ALL" in s
        assert "lab-api.g9.local" in s

    def test_no_targets_refused(self):
        spec = make_action_spec({**SPEC, "target_set": ["x"]})
        spec["target_set"] = []
        with pytest.raises(RuntimeArgError, match="no authorized targets"):
            build_nmap_argv(spec)

    def test_execute_is_real_and_fails_honestly_without_a_daemon(self):
        """No daemon in CI: the real docker CLI is invoked and returns an
        honest non-zero failure — never a faked success."""
        spec = make_action_spec(SPEC)
        cmd = dispatch(spec)
        r = execute(cmd, timeout_s=15)
        assert isinstance(r, dict)
        if r["exit_code"] is not None:
            assert r["ok"] is False
            assert r["exit_code"] != 0
            assert "docker" in (r["stderr"] + r["stdout"] + r["reason"]) or r["exit_code"] == 125
        else:
            # docker CLI absent entirely — also an honest failure
            assert r["ok"] is False
