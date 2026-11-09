import pytest

from g9_backend.core.action_spec import make_action_spec
from g9_backend.evidence import EvidenceGraph, EvidenceGraphError, ResultCollector
from g9_backend.tools.gowitness_amass_dnsrecon import (
    AdapterArgError, build_gowitness_argv, build_amass_argv, build_dnsrecon_argv,
    dispatch_gowitness, dispatch_amass, dispatch_dnsrecon,
)

SPEC = {
    "action_id": "ACT-X", "engagement_id": "ENG-1", "principal_id": "agent:panoptes",
    "agent_id": "panoptes", "tool_id": "gowitness", "tool_version": "1",
    "normalized_arguments": {"flags": ""},
    "target_set": ["lab-api.g9.local"], "working_directory": "/workspace/run",
    "environment_profile": "lab-plane", "sandbox_profile": "restricted-analysis",
    "network_policy_id": "netpol", "resource_budget": {"cpu": 1, "mem_gb": 1},
    "policy_revision": "ceder@v1",
}


class TestNewAdapters:
    def test_gowitness(self):
        spec = make_action_spec(SPEC)
        argv = build_gowitness_argv(spec)
        assert argv[0] == "scan" and "https://lab-api.g9.local" in argv
        s = dispatch_gowitness(spec).shell()
        assert "gowitness" in s and "--cap-drop ALL" in s

    def test_amass_passive_active_refused(self):
        spec = make_action_spec({**SPEC, "tool_id": "amass", "normalized_arguments": {"flags": "-active"}})
        with pytest.raises(AdapterArgError, match="allowlist|-active"):
            build_amass_argv(spec)
        spec2 = make_action_spec({**SPEC, "tool_id": "amass", "normalized_arguments": {"flags": ""}})
        argv = build_amass_argv(spec2)
        assert "enum" in argv and "-passive" in argv and "-d" in argv

    def test_dnsrecon_axfr_refused(self):
        spec = make_action_spec({**SPEC, "tool_id": "dnsrecon", "normalized_arguments": {"flags": "", "types": ["axfr"]}})
        with pytest.raises(AdapterArgError, match="zone transfer is not permitted"):
            build_dnsrecon_argv(spec)
        spec2 = make_action_spec({**SPEC, "tool_id": "dnsrecon", "normalized_arguments": {"flags": "", "types": ["std", "srv"]}})
        argv = build_dnsrecon_argv(spec2)
        assert "-t std,srv" in " ".join(argv)
        multi = make_action_spec({**SPEC, "tool_id": "dnsrecon", "normalized_arguments": {"flags": "", "types": ["std"]}, "target_set": ["a.g9.local", "b.g9.local"]})
        with pytest.raises(AdapterArgError, match="one authorized domain"):
            build_dnsrecon_argv(multi)


class TestEvidenceGraph:
    def test_typed_nodes_and_verified_paths(self):
        g = EvidenceGraph(scope="REDLAB")
        g.add_node({"id": "F1", "klass": "finding", "label": "f1", "scope": "REDLAB", "validation_status": "confirmed"})
        g.add_node({"id": "F2", "klass": "finding", "label": "f2", "scope": "REDLAB", "validation_status": "reproduced"})
        g.add_node({"id": "F3", "klass": "finding", "label": "f3", "scope": "REDLAB", "validation_status": "candidate"})
        g.add_edge("chains-to", "F1", "F2")
        g.add_edge("chains-to", "F2", "F3")
        assert g.shortest_attack_path("F1", "F2") == ["F1", "F2"]
        assert g.shortest_attack_path("F1", "F3") is None  # unverified link never satisfies a path

    def test_scope_and_class_enforcement(self):
        g = EvidenceGraph(scope="REDLAB")
        with pytest.raises(EvidenceGraphError, match="authoritative engagement scope"):
            g.add_node({"id": "X", "klass": "asset", "label": "x", "scope": "OTHER"})
        g.add_node({"id": "A", "klass": "asset", "label": "a", "scope": "REDLAB"})
        g.add_node({"id": "F", "klass": "finding", "label": "f", "scope": "REDLAB"})
        with pytest.raises(EvidenceGraphError, match="source class"):
            g.add_edge("evidences", "A", "F")


class TestResultCollector:
    def graph(self):
        return EvidenceGraph(scope="REDLAB")

    def test_raw_output_becomes_provenance_tagged_observation(self):
        c = ResultCollector(self.graph())
        rec = c.ingest_tool_result(
            tool_id="nmap-scoped", command="docker run … nmap -sV lab-api",
            stdout="PORT STATE SERVICE\n443 open https", targets=["lab-api.g9.local"], exit_code=0,
        )
        assert rec["artifact"].startswith("sha256:")
        obs = c.graph.nodes[rec["observation"]]
        assert obs["klass"] == "observation"
        assert obs["provenance"]["tool"] == "nmap-scoped"
        assert rec["candidates"] == []  # plain text: observation only, no invented findings

    def test_nuclei_json_becomes_candidate_findings_never_confirmed(self):
        c = ResultCollector(self.graph())
        line = '{"template-id": "CVE-2024-X", "host": "lab-api.g9.local", "matched-at": "https://lab-api/x", "info": {"severity": "critical"}}'
        rec = c.ingest_tool_result(
            tool_id="nuclei", command="docker run … nuclei", stdout=line,
            targets=["lab-api.g9.local"], exit_code=0,
        )
        assert len(rec["candidates"]) == 1
        cand = c.graph.nodes[rec["candidates"][0]]
        assert cand["klass"] == "finding"
        assert cand["validation_status"] == "candidate"  # NEVER confirmed by the collector
        assert cand["meta"]["severity"] == "critical"
        # dedupe: same template+host does not re-create
        rec2 = c.ingest_tool_result(
            tool_id="nuclei", command="docker run … nuclei", stdout=line,
            targets=["lab-api.g9.local"], exit_code=0,
        )
        assert rec2["candidates"] == []

    def test_evidence_edge_links_observation_to_finding(self):
        c = ResultCollector(self.graph())
        line = '{"template-id": "T-1", "host": "h.g9.local"}'
        rec = c.ingest_tool_result(tool_id="nuclei", command="cmd", stdout=line, targets=["h.g9.local"], exit_code=0)
        edges = [e for e in c.graph.edges if e["type"] == "evidences"]
        assert any(e["from"] == rec["observation"] and e["to"] == rec["candidates"][0] for e in edges)

    def test_collector_requires_tool_and_command(self):
        c = ResultCollector(self.graph())
        with pytest.raises(ValueError, match="required"):
            c.ingest_tool_result(tool_id="", command="", stdout="", targets=[], exit_code=0)
