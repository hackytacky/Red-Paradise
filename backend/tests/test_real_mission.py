"""Real-engagement mission tests: the gated chain against a real
authorized target — RoE lock, scope enforcement, approval flow,
agent-driven run, honest verification."""

from fastapi.testclient import TestClient

from g9_backend.api import app
from g9_backend.real_mission import (
    RealMission, RealMissionError, RealRulebookPlanner, build_call,
)

client = TestClient(app)

ENG = {
    "engagement_id": "ENG-TEST-1",
    "scope": ["target1.authorized-lab.example"],
    "roe_signed": True,
    "principals": ["agent:chimera"],
    "grants": ["nmap-scoped", "httpx", "testssl", "nuclei"],
}


def _mission(mode="hitl", execute=False, **over):
    eng = {**ENG, **over}
    return RealMission(engagement=eng, mode=mode, execute=execute)


# ------------------------------------------------------------ doctrine

def test_unsigned_roe_is_red_locked():
    try:
        _mission(roe_signed=False)
        assert False, "unsigned RoE must refuse to construct"
    except RealMissionError as e:
        assert "RoE" in str(e)


def test_empty_scope_refuses():
    try:
        _mission(scope=[])
        assert False, "empty scope must refuse"
    except RealMissionError:
        pass


def test_out_of_scope_target_dies_at_policy():
    m = _mission()
    r = m._invoke("nmap-scoped", "evil.example.com")
    assert r["ok"] is False and r["blocked_at"] == "policy"
    assert any("scope" in x for x in r["reasons"])


def test_ungranted_tool_dies_at_policy():
    m = _mission(grants=["nmap-scoped"])
    r = m._invoke("nuclei", "target1.authorized-lab.example")
    assert r["ok"] is False and r["blocked_at"] == "policy"


def test_no_adapter_refused():
    m = _mission(grants=["nmap-scoped"])
    r = m._invoke("not-a-tool", "target1.authorized-lab.example")
    assert r["ok"] is False and r["blocked_at"] == "adapter"


def test_build_call_rejects_shell_strings():
    try:
        build_call("nmap-scoped", "t", {"command": "rm -rf /"})
        assert False
    except RealMissionError:
        pass


def test_build_call_fills_family_defaults():
    call = build_call("nmap-scoped", "target1.authorized-lab.example")
    assert call["targets"] == ["target1.authorized-lab.example"]
    assert "ports" in call
    tls = build_call("testssl", "target1.authorized-lab.example")
    assert tls["target"] == "target1.authorized-lab.example"


# ------------------------------------------------------------- the run

def test_rulebook_run_builds_hardened_commands():
    m = _mission(mode="autonomous", execute=False)
    report = m.run()
    assert report["ok"] is True
    assert report["executed"] is False
    # every granted tool with an adapter ran against the scoped target
    tools = {r["tool"] for p in report["phases"] for r in p["invocations"] if r.get("ok")}
    assert {"nmap-scoped", "httpx", "testssl", "nuclei"} <= tools
    assert report["verification_note"].startswith("execution disabled")
    assert report["ledger_verified"] is True
    # events streamed the full decision trace
    kinds = {e["kind"] for e in m.events}
    assert {"phase", "thinking", "execution"} <= kinds


def test_hitl_queues_high_impact_for_operator():
    m = _mission(mode="hitl", execute=False)
    r = m._invoke("nmap-scoped", "target1.authorized-lab.example")
    assert r["ok"] is False and r.get("pending") is True
    pending = m.pending_actions()
    assert len(pending) == 1 and pending[0]["tool"] == "nmap-scoped"
    approved = m.approve_pending(pending[0]["action_id"])
    assert approved["ok"] is True  # executes through the same gates


def test_agent_llm_refusal_recorded():
    from g9_backend.agent import Agent, AgentError, Planner

    class EvilPlanner(Planner):
        name = "evil"
        def decide(self, state):
            return {"tool": "nmap-scoped", "target": "beyond-scope.example",
                    "args": {}, "reason": "probe outside the RoE"}

    m = _mission(mode="autonomous", execute=False)
    report = Agent(m, EvilPlanner(), max_steps=3).run()
    assert report["agent"]["refusals"], "the evil proposal must be refused and recorded"
    assert any("scope" in r for r in report["agent"]["refusals"])


# --------------------------------------------------------------- API

def test_api_engagement_lifecycle():
    r = client.post("/engagements/create", json={
        "engagement_id": "ENG-API-1",
        "scope": ["api-target.authorized-lab.example"],
        "roe_signed": True,
        "grants": ["httpx"],
    })
    assert r.json()["ok"] is True
    listed = client.get("/engagements").json()["engagements"]
    assert any(e["engagement_id"] == "ENG-API-1" for e in listed)
    v = client.get("/engagements/ENG-API-1/verify-target",
                   params={"target": "api-target.authorized-lab.example"}).json()
    assert v["ok"] is True
    bad = client.get("/engagements/ENG-API-1/verify-target",
                     params={"target": "other.example"}).json()
    assert bad["ok"] is False


def test_api_real_mission_live_stream():
    eid = "ENG-API-LIVE-1"
    client.post("/engagements/create", json={
        "engagement_id": eid, "scope": ["api-live.authorized-lab.example"],
        "roe_signed": True, "grants": ["httpx"],
    })
    r = client.post(f"/engagements/{eid}/mission/live",
                    params={"mode": "autonomous", "planner": "rulebook", "execute": False})
    assert r.json()["ok"] is True
    import time
    for _ in range(50):
        ev = client.get(f"/engagements/{eid}/mission/events").json()
        if ev["done"]:
            break
        time.sleep(0.1)
    assert ev["done"] is True and ev["error"] is None
    assert ev["report"]["ok"] is True
    assert ev["report"]["executed"] is False


def test_api_unsigned_engagement_refuses_to_launch():
    eid = "ENG-API-LOCKED-1"
    client.post("/engagements/create", json={
        "engagement_id": eid, "scope": ["locked.example"], "roe_signed": False,
    })
    r = client.post(f"/engagements/{eid}/mission/live", params={"execute": False})
    assert r.json()["ok"] is False and "RoE" in r.json()["reason"]


def test_planner_state_only_grants_admitted_tools():
    m = _mission(grants=["httpx", "not-a-tool"])
    state = m.planner_state(0, 10)
    assert state["allowed_tools"] == {"httpx"}
    assert set(state["targets"].values()) == {"target1.authorized-lab.example"}


# ------------------------------------------------- operator target brief

def test_brief_flows_to_planner_state():
    eng = {**ENG, "brief": {
        "architecture": "Windows AD",
        "start_here": "Tomcat manager on :8080",
        "creds_env": "G9_AD_CREDS",
    }}
    m = RealMission(engagement=eng, mode="autonomous", execute=False)
    state = m.planner_state(0, 10)
    assert state["brief"]["start_here"] == "Tomcat manager on :8080"
    # the brief is context only - it never widens tools or targets
    assert state["allowed_tools"] <= set(ENG["grants"]) & {"nmap-scoped", "httpx", "testssl", "nuclei"}
    assert set(state["targets"].values()) == {"target1.authorized-lab.example"}


def test_brief_grants_nothing():
    eng = {**ENG, "brief": {"targets": ["evil.example"], "tools": ["sqlmap"]}}
    m = RealMission(engagement=eng, mode="autonomous", execute=False)
    r = m._invoke("sqlmap", "target1.authorized-lab.example")
    assert r["ok"] is False and r["blocked_at"] == "policy"  # ungranted stays ungranted
    r2 = m._invoke("nmap-scoped", "evil.example")
    assert r2["ok"] is False and r2["blocked_at"] == "policy"  # brief targets aren't scope


def test_api_stores_brief():
    r = client.post("/engagements/create", json={
        "engagement_id": "ENG-BRIEF-1",
        "scope": ["brief.example"],
        "roe_signed": True,
        "grants": ["httpx"],
        "brief": {"start_here": "the old /admin path", "tech": ["nginx"]},
    })
    assert r.json()["ok"] is True
    listed = client.get("/engagements").json()["engagements"]
    rec = [e for e in listed if e["engagement_id"] == "ENG-BRIEF-1"][0]
    assert rec["brief"]["start_here"] == "the old /admin path"


def test_llm_prompt_includes_brief():
    from g9_backend.agent import LLMPlanner
    import g9_backend.agent as agent_mod
    captured = {}

    class FakePlanner(LLMPlanner):
        def __init__(self):
            super().__init__.__wrapped__ if False else None
            self.endpoint = "http://127.0.0.1:9/v1"
            self.model = "m"
            self.temperature = 0.0
            self._auto_bound = "m"
        def _complete(self, prompt, temperature=None):
            captured["prompt"] = prompt
            return '{"tool": "httpx", "target": "t1.example", "args": {}, "reason": "r"}'

    p = FakePlanner()
    state = {
        "allowed_tools": {"httpx"},
        "targets": {"target-0": "t1.example"},
        "brief": {"start_here": "check the login page first"},
        "findings": [], "steps": 0, "max_steps": 10,
    }
    action = p.decide(state)
    assert action["tool"] == "httpx"
    assert "check the login page first" in captured["prompt"]
    assert "OPERATOR ENGAGEMENT BRIEF" in captured["prompt"]
