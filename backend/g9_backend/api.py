"""G9 control-plane HTTP surface (FastAPI).

Loopback dev server only in this scaffold; deployment hardening is
Stage-07/08 work.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .core.audit_ledger import AuditLedger
from .executor.broker import ExecutionBroker, KVMWorkerManager
from .lab import LabMission
from .ops.engagement_manager import EngagementManager
from .executor.invoke_chain import invoke_tool
from .ops.budget_controller import BudgetController
from .policy.engine import PolicyEngine

app = FastAPI(title="G9 SPECTRE control plane", version="0.1.0")

# The UI is served from 127.0.0.1:5173 and calls this loopback-only API
# at 127.0.0.1:8700 - cross-origin from the browser. Allow exactly the
# loopback UI origins, nothing else; the API still binds loopback only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Demo engagement state — the real service loads this from the
# engagement scope manager (Stage 01).
ENGAGEMENTS = {
    "ENG-REDLAB-7": {
        "scope": ["lab-api.g9.local", "lab-portal.g9.local", "lab-dc-01.g9.local"],
        "roe_signed": True,
        "principals": {"agent:hydra-svc": {"revoked": False}, "agent:chimera": {"revoked": False}},
    },
}
GRANTS = {"ENG-REDLAB-7": {"tools": {"nmap-scoped", "httpx", "bloodhound-ce"}}}

_ledger = AuditLedger("ENG-REDLAB-7")
_engine = PolicyEngine(ENGAGEMENTS, GRANTS)
_broker = ExecutionBroker(_engine, _ledger, KVMWorkerManager())
_budget = BudgetController(
    engagement_id="ENG-REDLAB-7", token_budget=1_000_000,
    request_rate_per_min=60, cidr_scopes=["lab-api.g9.local", "lab-portal.g9.local", "10.10.0.0/24"],
)


class PolicyRequest(BaseModel):
    engagement_id: str
    principal_id: str
    tool_id: str
    targets: list[str]
    action_id: str | None = None
    sandbox_class: str | None = None
    required_sandbox_class: str | None = None
    high_impact: bool = False
    approval_id: str | None = None
    self_authorized: bool = False


class ActionSpecIn(BaseModel):
    action_id: str
    engagement_id: str
    principal_id: str
    agent_id: str
    tool_id: str
    tool_version: str
    normalized_arguments: dict
    target_set: list[str]
    working_directory: str
    environment_profile: str
    sandbox_profile: str
    network_policy_id: str
    resource_budget: dict
    policy_revision: str


@app.post("/policy/evaluate")
def evaluate_policy(req: PolicyRequest):
    return _engine.evaluate(req.model_dump())


@app.post("/actions")
def register_action(spec: ActionSpecIn):
    return _broker.register(spec.model_dump())


@app.post("/actions/{action_id}/approve")
def approve_action(action_id: str, approval_id: str, approved_by: str):
    return _broker.approve(action_id, approval_id, approved_by)


@app.post("/actions/{action_id}/dispatch")
def dispatch_action(action_id: str, spec: ActionSpecIn):
    return _broker.dispatch(action_id, spec.model_dump())


@app.get("/audit")
def audit(actor: str | None = None, action: str | None = None):
    ok, reason, records = _ledger.query(actor=actor, action=action)
    return {
        "integrity_ok": ok,
        "reason": reason,
        "records": [
            {"seq": r.seq, "actor": r.actor, "action": r.action, "subject": r.subject, "detail": r.detail, "digest": r.digest[:16] + "…"}
            for r in records
        ],
    }


class InvokeRequest(BaseModel):
    spec: ActionSpecIn
    call: dict
    execute_now: bool = False


@app.post("/tools/invoke")
def invoke(req: InvokeRequest):
    """End-to-end: MCP contract -> policy -> budget/scope -> adapter ->
    hardened container command (optional real execution)."""
    result = invoke_tool(
        engine=_engine, budget=_budget,
        spec=req.spec.model_dump(), call=req.call,
        execute_now=req.execute_now,
    )
    _ledger.append(
        actor=req.spec.principal_id,
        action="tool-invoke",
        subject=f"{req.spec.tool_id}:{req.spec.action_id}",
        detail=f"{result.get('ok')}: {result.get('blocked_at', 'cleared')}",
    )
    return result


# ---------------------------------------------------------------- lab run
# The full end-to-end active mission against the loopback lab target.
# The lab target binds 127.0.0.1 with an ephemeral port; the mission
# stops the target when the run completes.

_lab_state: dict = {"report": None, "mission": None, "live": None}
_engagements = EngagementManager()
_live_cursor = {"idx": 0}


@app.post("/engagements/quickstart")
def engagement_quickstart(mode: str = "autonomous", planner: str = "rulebook"):
    """ONE CLICK: create the lab-tier engagement (loopback scope, lab RoE
    pre-signed, all lab tools granted) and launch the live mission.
    The UI asks the operator YES/NO before this is called."""
    record = _engagements.quickstart_lab()
    result = lab_run_live(mode=mode, planner=planner)
    return {"ok": True, "engagement": record, "launch": result}


@app.get("/brains")
def agent_brains():
    """The configured brain stack by role (planner / specialist / fast /
    fallback) - each an OpenAI-compatible loopback endpoint."""
    from .agent import brains
    return {"ok": True, "brains": brains()}


@app.get("/brains/discover")
def agent_brains_discover():
    """Probe every configured endpoint and report what weights are
    actually being served - the build binds to what you installed."""
    from .agent import discover_brains
    return {"ok": True, "discovery": discover_brains()}


@app.get("/engagements")
def engagements_list():
    """The engagement registry: scope, RoE state, principals, grants."""
    return {"ok": True, "engagements": _engagements.list()}


@app.post("/lab/run/live")
def lab_run_live(mode: str = "autonomous", planner: str = "rulebook"):
    """Kick off a live mission in the background — the Mission Console
    UI polls /lab/events to watch every decision, gate, execution and
    verification step as it happens.

    planner: rulebook (deterministic reference) | llm (the local model
    at G9_LLM_ENDPOINT proposes typed actions; every gate still
    applies — the model proposes, the code disposes)."""
    import threading
    prev = _lab_state.get("live")
    if prev is not None and prev.get("mission") is not None:
        try:
            prev["mission"].close()
        except Exception:
            pass
    mission = LabMission(mode=mode)
    _lab_state["live"] = {"mission": mission, "done": False, "error": None}

    def _run():
        try:
            if planner == "llm":
                import os
                from .agent import Agent, LLMPlanner, FallbackPlanner
                main = LLMPlanner()
                fb_endpoint = os.environ.get("G9_LLM_FALLBACK_ENDPOINT", "")
                fb_model = os.environ.get("G9_LLM_FALLBACK_MODEL", "local")
                if fb_endpoint:
                    p = FallbackPlanner(main, LLMPlanner(endpoint=fb_endpoint, model=fb_model))
                else:
                    p = main
                _lab_state["report"] = Agent(mission, p).run()
            else:
                from .agent import Agent, RulebookPlanner
                _lab_state["report"] = Agent(mission, RulebookPlanner()).run()
        except Exception as e:  # surface honestly, never silently
            _lab_state["live"]["error"] = str(e)
        finally:
            _lab_state["live"]["done"] = True

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "mode": mode, "note": "poll GET /lab/events for the live stream"}


@app.get("/lab/events")
def lab_events(since: int = 0):
    """Incremental live event stream: returns all events after index
    `since` plus the run status. Frontend polls this every second."""
    live = _lab_state.get("live")
    if live is None:
        return {"ok": False, "reason": "no live mission - POST /lab/run/live first",
                "events": [], "next": 0, "done": True}
    mission = live["mission"]
    events = mission.events
    batch = events[since:]
    return {
        "ok": True,
        "mode": mission.autonomy.mode,
        "pending": mission.pending_actions() if hasattr(mission, "pending_actions") else [],
        "events": batch,
        "next": len(events),
        "done": live["done"],
        "error": live["error"],
        "report": _lab_state["report"] if live["done"] else None,
    }


@app.post("/lab/run")
def lab_run(mode: str = "autonomous"):
    """Run the full active mission now: policy → budget → lab-native
    adapters → real execution → evidence → candidates → deterministic
    verification → report. mode: autonomous | hitl | manual."""
    prev = _lab_state.get("mission")
    if prev is not None:
        prev.close()
    mission = LabMission(mode=mode)
    _lab_state["mission"] = mission
    try:
        report = mission.run()
    except Exception as e:
        mission.close()
        _lab_state["mission"] = None
        return {"ok": False, "reason": str(e)}
    _lab_state["report"] = report
    _ledger.append(actor="operator", action="lab.run",
                   detail=f"mode={mode} candidates={report['candidates']} reproduced={report['reproduced']}")
    return report


@app.get("/lab/report")
def lab_report():
    if _lab_state["report"] is None:
        return {"ok": False, "reason": "no lab run yet — POST /lab/run first"}
    return _lab_state["report"]


@app.get("/lab/arsenal")
def lab_arsenal():
    from .lab.native_adapters import LAB_ADAPTERS
    return {"ok": True, "lab_tools": sorted(LAB_ADAPTERS)}


@app.get("/lab/pending")
def lab_pending():
    m = _lab_state.get("mission")
    if m is None:
        return {"ok": False, "reason": "no active mission"}
    return {"ok": True, "mode": m.autonomy.mode, "pending": m.pending_actions()}


@app.post("/lab/approve")
def lab_approve(action_id: str):
    m = _lab_state.get("mission")
    if m is None:
        return {"ok": False, "reason": "no active mission"}
    return m.approve_pending(action_id)


@app.post("/lab/mode")
def lab_mode(mode: str):
    """Operator switches the active mission's autonomy mode."""
    m = _lab_state.get("mission")
    if m is None:
        return {"ok": False, "reason": "no active mission"}
    return m.autonomy.set_mode(mode, "operator")


# ------------------------------------------- real engagements (live)

class EngagementIn(BaseModel):
    """A REAL engagement: the operator registers the authorized scope
    from their signed RoE. roe_signed=False creates the record
    red-locked - the mission refuses to run unsigned."""

    engagement_id: str
    scope: list[str]
    roe_signed: bool = False
    principals: list[str] = ["agent:chimera"]
    grants: list[str] = []
    # everything the operator already knows about the authorized target:
    # architecture, known hosts/URLs, tech stack, creds env names, prior
    # findings, priorities. The planner reads it as trusted context - it
    # grants nothing (scope/tools come only from the fields above).
    brief: dict = {}


@app.post("/engagements/create")
def engagement_create(req: EngagementIn):
    try:
        record = _engagements.create(
            engagement_id=req.engagement_id, scope=req.scope,
            roe_signed=req.roe_signed, principals=req.principals,
            grants=set(req.grants), tier="real", brief=req.brief,
        )
    except Exception as e:
        return {"ok": False, "reason": str(e)}
    _ledger.append(actor="operator", action="engagement.create",
                   subject=req.engagement_id,
                   detail=f"scope={req.scope} roe_signed={req.roe_signed} grants={sorted(req.grants)}")
    return {"ok": True, "engagement": record}


_real_state: dict = {}


def _get_real(eid: str) -> dict:
    st = _real_state.get(eid)
    if st is None:
        raise KeyError(f"no live mission for engagement {eid!r} - POST /engagements/{eid}/mission/live first")
    return st


@app.post("/engagements/{eid}/mission/live")
def real_mission_live(eid: str, mode: str = "hitl", planner: str = "rulebook", execute: bool = True):
    """Launch the agent-driven REAL mission in the background. Default
    mode is human-in-the-loop - escalate to autonomous only when you
    trust the stack. planner: rulebook | llm. execute=true runs the
    real tool containers (requires Docker + pinned images); false
    builds the hardened commands without executing."""
    import threading
    from .real_mission import RealMission, RealMissionError
    rec = _engagements.engagements.get(eid)
    if rec is None:
        return {"ok": False, "reason": f"unknown engagement {eid!r} - POST /engagements/create first"}
    try:
        mission = RealMission(engagement=rec, mode=mode, execute=execute)
    except RealMissionError as e:
        return {"ok": False, "reason": str(e)}
    prev = _real_state.get(eid)
    if prev is not None:
        try:
            prev["mission"].close()
        except Exception:
            pass
    _real_state[eid] = {"mission": mission, "done": False, "error": None}

    def _run():
        try:
            if planner == "llm":
                import os
                from .agent import LLMPlanner, FallbackPlanner
                main = LLMPlanner()
                fb_endpoint = os.environ.get("G9_LLM_FALLBACK_ENDPOINT", "")
                fb_model = os.environ.get("G9_LLM_FALLBACK_MODEL", "local")
                p = FallbackPlanner(main, LLMPlanner(endpoint=fb_endpoint, model=fb_model)) if fb_endpoint else main
                mission.run(planner=p)
            else:
                mission.run()
        except Exception as e:  # surface honestly, never silently
            mission.error = str(e)
        finally:
            mission.done = True

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "engagement_id": eid, "mode": mode, "planner": planner,
            "execute": execute, "note": f"poll GET /engagements/{eid}/mission/events for the live stream"}


@app.get("/engagements/{eid}/mission/events")
def real_mission_events(eid: str, since: int = 0):
    try:
        st = _get_real(eid)
    except KeyError as e:
        return {"ok": False, "reason": str(e), "events": [], "next": 0, "done": True}
    m = st["mission"]
    batch = m.events[since:]
    return {"ok": True, "mode": m.autonomy.mode, "pending": m.pending_actions(),
            "events": batch, "next": len(m.events), "done": m.done,
            "error": m.error, "report": m.report if m.done else None}


@app.get("/engagements/{eid}/mission/pending")
def real_mission_pending(eid: str):
    try:
        st = _get_real(eid)
    except KeyError as e:
        return {"ok": False, "reason": str(e)}
    m = st["mission"]
    return {"ok": True, "mode": m.autonomy.mode, "pending": m.pending_actions()}


@app.post("/engagements/{eid}/mission/approve")
def real_mission_approve(eid: str, action_id: str):
    try:
        st = _get_real(eid)
    except KeyError as e:
        return {"ok": False, "reason": str(e)}
    return st["mission"].approve_pending(action_id)


@app.get("/engagements/{eid}/mission/report")
def real_mission_report(eid: str):
    try:
        st = _get_real(eid)
    except KeyError as e:
        return {"ok": False, "reason": str(e)}
    m = st["mission"]
    if m.report is None:
        return {"ok": False, "reason": "mission still running (or not started) - poll the events stream"}
    return m.report


@app.get("/engagements/{eid}/verify-target")
def engagement_verify_target(eid: str, target: str):
    """Scope is the ONLY source of targets - the manager answers whether
    a target is authorized before anything is proposed."""
    return _engagements.verify_target(eid, target)


# ------------------------------------------------- admission desk (live)

class AdmitRequest(BaseModel):
    tool_id: str
    proofs: dict


@app.get("/arsenal/registry")
def arsenal_registry(search: str | None = None):
    """The full admitted-candidate arsenal with per-entry gates —
    usable at any time via one-time recorded admission."""
    from .tools.registry_admission import required_proofs, validate_registry
    entries = validate_registry()
    if search:
        s = search.lower()
        entries = [e for e in entries if s in e["id"] or s in e["name"].lower() or s in e["category"]]
    return {"ok": True, "total": len(entries), "entries": [
        {**e, "required_proofs": required_proofs(e["id"])} for e in entries
    ]}


@app.post("/arsenal/admit")
def arsenal_admit(req: AdmitRequest):
    """One-time recorded admission: every flagged proof must be present
    and truthy; UNVERIFIED entries need a manual-review override."""
    from .tools.registry_admission import admit
    result = admit(req.tool_id, req.proofs)
    _ledger.append(actor="operator", action="arsenal.admit",
                   subject=req.tool_id, detail=str(result.get("result", result.get("reason"))))
    return result


# ------------------------------------------- eval / bench / specialists

@app.get("/eval/lab")
def eval_lab(runs: int = 2):
    """Stage 06, live: measured pipeline metrics against known ground
    truth — recall, FP rejection, gate integrity, ledger verification."""
    from .eval import evaluate_lab_pipeline
    return evaluate_lab_pipeline(runs=max(1, min(runs, 5)))


@app.get("/bench/report")
def bench_report():
    """Stage 03: the orchestrator benchmark harness — identical task
    suite, deterministic scorer, reference baseline."""
    from .bench import benchmark_report
    return benchmark_report()


@app.get("/specialists/catalog")
def specialists_catalog():
    """Stage 05: the nine specialist pipelines and their phase shapes."""
    from .specialists import catalog
    return catalog()


@app.post("/specialists/{name}/run")
def specialists_run(name: str):
    """Execute a specialist pipeline (native phases run for real; container
    phases build hardened commands for the host)."""
    from .specialists import run_specialist, SpecialistError
    try:
        return run_specialist(name)
    except SpecialistError as e:
        return {"ok": False, "reason": str(e)}


@app.get("/intel/sources")
def intel_sources(category: str | None = None, flag: str | None = None):
    """The full intel source registry (542 sources) with governance
    flags — queryable at any time."""
    from .intel import all_sources
    srcs = all_sources()
    if category:
        srcs = [s for s in srcs if s["category"] == category]
    if flag:
        srcs = [s for s in srcs if flag in s["flags"]]
    return {"ok": True, "total": len(srcs), "sources": srcs}
