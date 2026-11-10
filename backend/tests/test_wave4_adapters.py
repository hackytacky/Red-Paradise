import pytest

from g9_backend.core.action_spec import make_action_spec
from g9_backend.executor.invoke_chain import ADAPTERS
from g9_backend.tools.wave4_adapters import (
    build_azurehound_argv, build_bloodhound_argv, build_grype_argv,
    build_ldapsearch_argv, build_pyrit_argv, build_trivy_argv,
    build_windapsearch_argv, build_zap_argv,
)

SPEC = {
    "action_id": "ACT-W4", "engagement_id": "ENG-1", "principal_id": "agent:panoptes",
    "agent_id": "panoptes", "tool_id": "owasp-zap", "tool_version": "1",
    "normalized_arguments": {},
    "target_set": ["lab-api.g9.local"], "working_directory": "/workspace/run",
    "environment_profile": "lab-plane", "sandbox_profile": "restricted-analysis",
    "network_policy_id": "netpol", "resource_budget": {"cpu": 2, "mem_gb": 2},
    "policy_revision": "ceder@v1",
}


class TestWave4Adapters:
    def test_zap_baseline(self):
        argv = build_zap_argv(make_action_spec(SPEC))
        assert argv[0] == "-cmd" and "-quickurl" in argv and "lab-api.g9.local" in argv

    def test_grype_requires_artifact(self):
        spec = make_action_spec({**SPEC, "tool_id": "grype-syft", "normalized_arguments": {}})
        with pytest.raises(Exception, match="image_or_dir"):
            build_grype_argv(spec)
        ok = make_action_spec({**SPEC, "tool_id": "grype-syft", "normalized_arguments": {"image_or_dir": "lab-app:1"}})
        assert "lab-app:1" in build_grype_argv(ok)

    def test_trivy_image_scan(self):
        spec = make_action_spec({**SPEC, "tool_id": "trivy", "normalized_arguments": {"image_or_dir": "lab-app:1"}})
        argv = build_trivy_argv(spec)
        assert argv[0] == "image" and "--no-progress" in argv

    def test_ldapsearch_read_only(self):
        spec = make_action_spec({
            **SPEC, "tool_id": "ldapsearch",
            "normalized_arguments": {"server": "lab-dc-01.g9.local", "filter": "(objectClass=user)"},
        })
        argv = build_ldapsearch_argv(spec)
        assert "ldap://lab-dc-01.g9.local" in argv and "(objectClass=user)" in argv

    def test_ldapsearch_credential_filters_refused(self):
        for bad in ["(password=*)", "(userPassword=x)", "write cn"]:
            spec = make_action_spec({
                **SPEC, "tool_id": "ldapsearch",
                "normalized_arguments": {"server": "lab-dc-01.g9.local", "filter": bad},
            })
            with pytest.raises(Exception, match="read-only"):
                build_ldapsearch_argv(spec)

    def test_windapsearch(self):
        spec = make_action_spec({
            **SPEC, "tool_id": "windapsearch",
            "normalized_arguments": {"server": "lab-dc-01.g9.local", "filter": "(objectClass=*)"},
        })
        argv = build_windapsearch_argv(spec)
        assert "--dc-ip" in argv and "lab-dc-01.g9.local" in argv

    def test_identity_collectors_enforce_collector_field(self):
        from g9_backend.tools.wave4_adapters import build_sharphound_argv
        spec = make_action_spec({**SPEC, "tool_id": "bloodhound", "normalized_arguments": {"collector": "BloodHound", "targets": ["lab-dc-01.g9.local"]}})
        assert "--collection" in build_bloodhound_argv(spec)
        wrong = make_action_spec({**SPEC, "tool_id": "sharphound", "normalized_arguments": {"collector": "Mimikatz", "targets": ["x"]}})
        with pytest.raises(Exception, match="SharpHound only"):
            build_sharphound_argv(wrong)

    def test_azurehound_requires_tenant(self):
        spec = make_action_spec({**SPEC, "tool_id": "azurehound", "normalized_arguments": {"collector": "AzureHound", "targets": ["t"]}})
        with pytest.raises(Exception, match="--tenants"):
            build_azurehound_argv(spec)
        ok = make_action_spec({**SPEC, "tool_id": "azurehound",
                               "normalized_arguments": {"collector": "AzureHound", "targets": ["t"], "flags": "--tenants 11111111-2222-3333-4444-555555555555"}})
        assert "11111111-2222-3333-4444-555555555555" in build_azurehound_argv(ok)

    def test_pyrit_typed_fields(self):
        spec = make_action_spec({**SPEC, "tool_id": "pyrit", "normalized_arguments": {}})
        with pytest.raises(Exception, match="corpus and control_version"):
            build_pyrit_argv(spec)

    def test_all_in_chain(self):
        for t in ["owasp-zap", "caido", "grype-syft", "trivy", "ldapsearch",
                  "windapsearch", "bloodhound", "sharphound", "azurehound", "pyrit"]:
            assert t in ADAPTERS, f"{t} missing"

    def test_hardened_profile(self):
        s = ADAPTERS["owasp-zap"](make_action_spec(SPEC)).shell()
        assert "--cap-drop ALL" in s and "no-new-privileges" in s and "--read-only" in s
