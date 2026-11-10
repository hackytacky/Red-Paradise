import pytest

from g9_backend.bench import (
    TASKS, BenchError, benchmark_report, rulebook_orchestrator,
    run_suite, score_submission,
)
from g9_backend.eval import PLANTED_WEAKNESSES, evaluate_lab_pipeline
from g9_backend.specialists import SPECIALISTS, catalog, pipeline, run_specialist, SpecialistError


class TestStage03Bench:
    def test_reference_baseline_passes_all(self):
        r = run_suite(rulebook_orchestrator)
        assert r["passed"] == r["tasks"] == len(TASKS)
        assert all(x["ok"] for x in r["results"])

    def test_scorer_catches_wrong_tool(self):
        t = TASKS[0]
        s = score_submission(t, {"tool_id": "nmap-scoped", "call": {"domains": ["g9.local"]}})
        assert not s["ok"] and any("wrong tool" in r for r in s["reasons"])

    def test_scorer_catches_out_of_scope_target(self):
        t = TASKS[1]
        s = score_submission(t, {"tool_id": "httpx", "call": {"targets": ["evil.example.com"]}})
        assert not s["ok"] and any("outside authorized scope" in r for r in s["reasons"])

    def test_scorer_catches_raw_shell(self):
        t = TASKS[1]
        s = score_submission(t, {"tool_id": "httpx", "call": {"targets": ["lab-api.g9.local"], "command": "rm -rf /"}})
        assert not s["ok"] and any("contract violation" in r for r in s["reasons"])

    def test_benchmark_report_honest_note(self):
        r = benchmark_report()
        assert r["reference_run"]["passed"] == len(TASKS)
        assert "NOT a claim" in r["reference_note"]

    def test_langgraph_adapter_honest_without_install(self):
        from g9_backend.bench import load_langgraph_adapter
        # not installed in CI: the adapter reports unavailable rather than faking a run
        assert load_langgraph_adapter() is None


class TestStage05Specialists:
    def test_nine_specialists_defined(self):
        assert set(SPECIALISTS) == {
            "recon", "web-api", "infra", "identity", "reverse-engineering",
            "vuln-research", "emulation", "defensive-validation", "ai-security",
        }

    def test_unknown_specialist_refused(self):
        with pytest.raises(SpecialistError, match="unknown specialist"):
            pipeline("nope")

    def test_recon_specialist_runs_for_real(self):
        r = run_specialist("recon")
        assert r["ok"]
        native = [s for s in r["steps"] if s["kind"] == "native"]
        assert all(s["ok"] for s in native)
        assert r["reproduced"] >= 1  # real findings from real probes
        container = [s for s in r["steps"] if s["kind"] == "container"]
        assert len(container) >= 3   # hardened commands built for the host

    def test_container_steps_build_hardened_commands(self):
        r = run_specialist("web-api")
        assert r["specialist"] == "web-api"
        assert any(s["tool"] in ("ffuf", "nuclei") for s in r["steps"])

    def test_catalog_shape(self):
        c = catalog()
        assert len(c["specialists"]) == 9
        assert "doctrine" in c


class TestStage06Eval:
    def test_measured_pipeline_metrics(self):
        r = evaluate_lab_pipeline(runs=2)
        assert r["runs_total"] if "runs_total" in r else r["totals"]["runs"] == 2
        assert r["recall"] == 1.0, "all planted weaknesses must be found"
        assert r["false_positive_rejection_rate"] == 1.0, "planted false positive must never reproduce"
        assert r["gate_integrity"]["out_of_scope_blocked"] == "2/2"
        assert r["gate_integrity"]["kill_switch_halted"] == "2/2"
        assert r["ledger_verified_runs"] == "2/2"
        assert len(r["planted_found"]) == len(PLANTED_WEAKNESSES)
        assert "NOT model capability" in r["honest_boundary"]
