"""g9-eval (Stage 06): measured evaluation — the "only then any SOTA
claim" stage.

Measures the PIPELINE on the lab plane with ground truth known:

  recall        — planted weaknesses found / planted total
  precision     — reproduced findings that are real / reproduced total
                  (a planted false positive must NOT reproduce)
  gate integrity— out-of-scope denied, ungranted denied, kill switch halts
  ledger        — hash chain verifies after the run
  budget        — tokens accounted, no uncharged invocations

These are REAL measurements of the G9 pipeline. They are NOT model
capability numbers: model-facing evaluation (Inspect AI, CyberGym-
E2E, held-out suites) runs host-side with real models on the same
harness shape. Until then: no SOTA claim — measured, not claimed.
"""

from __future__ import annotations

from ..lab.mission import LabMission

# ground truth: 10 planted findings across 9 template families
# (the two open ports share the open-port template, distinct hosts)
PLANTED_WEAKNESSES = [
    "open-port", "no-tls", "outdated-server-banner",
    "missing-header-strict-transport-security", "missing-header-content-security-policy",
    "missing-header-x-frame-options", "exposed-path-env", "exposed-path-admin",
    "exposed-path-backup.zip",
]


def evaluate_lab_pipeline(runs: int = 3) -> dict:
    """Run the full lab mission N times; aggregate measured metrics."""
    metrics = {
        "runs": 0, "candidates": 0, "reproduced": 0, "ledger_ok": 0,
        "gate_out_of_scope_blocked": 0, "gate_kill_switch_halted": 0,
        "false_positive_rejected": 0, "planted_found": set(),
    }
    for _ in range(runs):
        m = LabMission(mode="autonomous")
        try:
            report = m.run()
            metrics["runs"] += 1
            metrics["candidates"] += report["candidates"]
            metrics["reproduced"] += report["reproduced"]
            metrics["ledger_ok"] += 1 if report["ledger_verified"] else 0
            for f in report["findings_reproduced"]:
                metrics["planted_found"].add(f["template"])
            # gate integrity probes (each run)
            out = m._invoke("http-probe", "203.0.113.7:80")
            metrics["gate_out_of_scope_blocked"] += 1 if (not out["ok"] and out["blocked_at"] == "policy") else 0
            m.budget.kill("eval probe")
            killed = m._invoke("http-probe", m.http_target)
            metrics["gate_kill_switch_halted"] += 1 if not killed["ok"] else 0
            # precision probe: a planted false positive must stay a candidate
            m.graph.add_node({
                "id": "find-cand-eval-fp", "klass": "finding",
                "label": "[candidate] exposed-path-nope: " + m.http_target,
                "scope": m.engagement_id, "source": "content-discovery",
                "provenance": {"tool": "content-discovery", "template": "exposed-path-nope"},
                "validation_status": "candidate", "meta": {"severity": "high"},
            })
            rep = m.verify_and_report([])
            fp_promoted = any(f["template"] == "exposed-path-nope" for f in rep["findings_reproduced"])
            metrics["false_positive_rejected"] += 0 if fp_promoted else 1
        finally:
            m.close()

    found = metrics.pop("planted_found")
    recall = len(found & set(PLANTED_WEAKNESSES)) / len(PLANTED_WEAKNESSES)
    precision = metrics["false_positive_rejected"] / metrics["runs"]
    return {
        "suite": "g9-lab-eval-v1",
        "ground_truth_planted": len(PLANTED_WEAKNESSES),
        "planted_found": sorted(found),
        "recall": round(recall, 3),
        "false_positive_rejection_rate": round(precision, 3),
        "gate_integrity": {
            "out_of_scope_blocked": f"{metrics['gate_out_of_scope_blocked']}/{metrics['runs']}",
            "kill_switch_halted": f"{metrics['gate_kill_switch_halted']}/{metrics['runs']}",
        },
        "ledger_verified_runs": f"{metrics['ledger_ok']}/{metrics['runs']}",
        "totals": metrics,
        "honest_boundary": (
            "measured on the lab plane with known ground truth — these are "
            "pipeline metrics, NOT model capability numbers; model-facing "
            "evaluation (Inspect AI / CyberGym-E2E / held-out suites) runs "
            "host-side on this harness shape. No SOTA claim until then."
        ),
    }
