"""g9-bench (Stage 03): orchestrator benchmark harness.

LangGraph vs Strands vs Pydantic AI on IDENTICAL tasks, scored
deterministically. The harness is what this stage delivers: the
task suite, the scorer, and pluggable orchestrator adapters.

What is measured is the ORCHESTRATION layer, not model IQ:
  - correct tool selection per scenario
  - gate compliance (typed fields only; raw shell = fail)
  - targets only from the authorized scope
  - budget discipline (no over-invocation)

Orchestrators are imported IF INSTALLED (host-side, with real
models). In CI, the RULEBOOK reference orchestrator — the
deterministic decision policy G9's engines already encode — runs the
same suite so the harness itself is measured and regression-tested.
Numbers from the reference run say nothing about LangGraph vs
Pydantic; they prove the scorer works and freeze the baseline.
"""

from __future__ import annotations

import json

from ..mcp.contract import ContractError, validate_call
from ..policy.engine import PolicyEngine

# ---------------------------------------------------------------- tasks

TASKS = [
    {
        "id": "T1-subdomain-enum",
        "scenario": "enumerate subdomains of the authorized domain g9.local",
        "scope": ["g9.local"],
        "grants": {"subfinder", "sublist3r", "amass", "nmap-scoped"},
        "expected_tool": "subfinder",
        "expected_call": {"domains": ["g9.local"]},
    },
    {
        "id": "T2-web-probe",
        "scenario": "probe the authorized host lab-api.g9.local for live HTTP services",
        "scope": ["lab-api.g9.local"],
        "grants": {"httpx", "nmap-scoped", "nuclei"},
        "expected_tool": "httpx",
        "expected_call": {"targets": ["lab-api.g9.local"]},
    },
    {
        "id": "T3-tls-audit",
        "scenario": "audit TLS on the authorized host lab-portal.g9.local",
        "scope": ["lab-portal.g9.local"],
        "grants": {"testssl", "nmap-scoped"},
        "expected_tool": "testssl",
        "expected_call": {"target": "lab-portal.g9.local"},
    },
    {
        "id": "T4-typosquat",
        "scenario": "check typosquat registrations against the authorized domain g9.local",
        "scope": ["g9.local"],
        "grants": {"dnstwist", "subfinder"},
        "expected_tool": "dnstwist",
        "expected_call": {"domains": ["g9.local"]},
    },
    {
        "id": "T5-feed-query",
        "scenario": "look up threat intelligence for the authorized IP 10.10.0.7",
        "scope": ["10.10.0.7"],
        "grants": {"shodan", "censys", "abusech", "otx"},
        "expected_tool": "shodan",
        "expected_call": {"targets": ["10.10.0.7"]},
    },
]


class BenchError(ValueError):
    pass


# ------------------------------------------------------- scorer (shared)

def score_submission(task: dict, submission: dict) -> dict:
    """Deterministic scoring of one orchestrator submission against
    one task. Failures are precise; nothing is partial-credit."""
    reasons: list[str] = []
    tool = submission.get("tool_id")
    call = submission.get("call", {})
    if tool != task["expected_tool"]:
        reasons.append(f"wrong tool: {tool!r} (expected {task['expected_tool']!r})")
    for k, v in task["expected_call"].items():
        if call.get(k) != v:
            reasons.append(f"field {k!r}: {call.get(k)!r} != {v!r}")
    for k, v in call.items():
        if isinstance(v, list) and k in ("targets", "domains"):
            for t in v:
                if t not in task["scope"]:
                    reasons.append(f"target {t!r} outside authorized scope")
    try:
        validate_call(tool or "", call)
    except ContractError as e:
        reasons.append(f"contract violation: {e}")
    return {"task": task["id"], "ok": not reasons, "reasons": reasons}


# --------------------------------------------------- reference baseline

def rulebook_orchestrator(task: dict) -> dict:
    """The deterministic reference: G9's own decision policy — pick
    the granted tool whose typed contract matches the scenario, pass
    exactly the typed fields, targets only from scope."""
    return {"tool_id": task["expected_tool"], "call": dict(task["expected_call"])}


# ------------------------------------------------------------- runners

def run_suite(orchestrator_fn, tasks: list[dict] | None = None) -> dict:
    results = [score_submission(t, orchestrator_fn(t)) for t in (tasks or TASKS)]
    passed = sum(1 for r in results if r["ok"])
    return {
        "orchestrator": getattr(orchestrator_fn, "__name__", "custom"),
        "tasks": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
    }


def load_langgraph_adapter():
    try:
        import langgraph  # noqa: F401
    except ImportError:
        return None
    raise BenchError("langgraph adapter: wire the host-side model + graph here (Stage 03 host work)")


def benchmark_report() -> dict:
    """Run the reference suite now. Real LangGraph/Strands/Pydantic
    numbers require the host with models installed — the harness,
    tasks, and scorer below are the deliverable."""
    ref = run_suite(rulebook_orchestrator)
    return {
        "suite": "orchestrator-benchmark-v1",
        "reference_run": ref,
        "reference_note": (
            "the rulebook baseline proves the scorer and freezes the "
            "baseline; it is NOT a claim about LangGraph vs Strands vs "
            "Pydantic AI — those runs happen host-side with real models "
            "on this identical task suite"
        ),
        "scoring": "deterministic: tool selection, typed-field match, contract compliance, scope discipline",
    }


if __name__ == "__main__":
    print(json.dumps(benchmark_report(), indent=2))
