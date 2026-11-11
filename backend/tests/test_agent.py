import json

import pytest

from g9_backend.agent import Agent, AgentError, LLMPlanner, Planner, RulebookPlanner
from g9_backend.lab import LabMission


class TestRulebookAgent:
    def test_full_autonomous_agent_run(self):
        m = LabMission(mode="autonomous")
        try:
            report = Agent(m, RulebookPlanner(), max_steps=15).run()
            assert report["ok"]
            assert report["reproduced"] == report["candidates"] >= 9
            assert report["agent"]["planner"] == "rulebook"
            assert report["agent"]["steps"] == 6
            assert report["ledger_verified"]
            kinds = {e["kind"] for e in m.events}
            assert "thinking" in kinds and "execution" in kinds and "finding" in kinds
        finally:
            m.close()

    def test_step_limit_enforced(self):
        class NeverDone(Planner):
            name = "neverdone"

            def __init__(self):
                self.n = 0

            def decide(self, state):
                self.n += 1
                return {"tool": "http-probe", "target": state["targets"]["http"], "args": {}, "reason": "again"}

        m = LabMission(mode="autonomous")
        try:
            report = Agent(m, NeverDone(), max_steps=3).run()
            assert report["agent"]["steps"] == 3
            assert any("STEP LIMIT" in e["msg"] for e in m.events)
        finally:
            m.close()

    def test_gates_survive_the_agent(self):
        """The agent never weakens the gates: out-of-scope proposals
        die at policy; the kill switch halts the loop."""
        class EvilPlanner(Planner):
            name = "evil"

            def decide(self, state):
                return {"tool": "http-probe", "target": "203.0.113.7:80", "args": {}, "reason": "probing beyond scope"}

        m = LabMission(mode="autonomous")
        try:
            Agent(m, EvilPlanner(), max_steps=2).run()
            assert any("POLICY DENY" in e["msg"] for e in m.events)
            # and the honest path still works after the refusal
            m.budget.kill("operator test")
            halted = m._invoke("http-probe", m.http_target)
            assert not halted["ok"]
        finally:
            m.close()


class TestLLMPlanner:
    def test_no_endpoint_refuses_honestly(self):
        import os
        old = os.environ.pop("G9_LLM_ENDPOINT", None)
        try:
            with pytest.raises(AgentError, match="no LLM endpoint"):
                LLMPlanner()
        finally:
            if old:
                os.environ["G9_LLM_ENDPOINT"] = old

    def _fake_llm(self, responses):
        class FakeLLM(LLMPlanner):
            def __init__(self):
                super().__init__(endpoint="http://fake.local/v1", model="fake")
                self.calls = 0

            def _complete(self, prompt):
                r = responses[self.calls]
                self.calls += 1
                return r

        return FakeLLM()

    def test_valid_proposal_executes(self):
        m = LabMission(mode="autonomous")
        try:
            target = m.http_target
            planner = self._fake_llm([
                json.dumps({"tool": "http-probe", "target": target, "args": {}, "reason": "identify the service", "done": False}),
                json.dumps({"done": True}),
            ])
            report = Agent(m, planner, max_steps=5).run()
            assert report["agent"]["steps"] == 1
            assert any("identify the service" in e["msg"] for e in m.events)
        finally:
            m.close()

    def test_ungranted_tool_refused(self):
        m = LabMission(mode="autonomous")
        try:
            planner = self._fake_llm([
                json.dumps({"tool": "hydra", "target": m.http_target, "args": {}, "reason": "brute force", "done": False}),
            ])
            Agent(m, planner, max_steps=5).run()
            assert any("cannot grant itself capabilities" in e["msg"] for e in m.events)
        finally:
            m.close()

    def test_out_of_scope_target_refused(self):
        m = LabMission(mode="autonomous")
        try:
            planner = self._fake_llm([
                json.dumps({"tool": "http-probe", "target": "evil.example.com", "args": {}, "reason": "beyond the RoE", "done": False}),
            ])
            Agent(m, planner, max_steps=5).run()
            assert any("outside the authorized scope" in e["msg"] for e in m.events)
        finally:
            m.close()

    def test_raw_shell_refused(self):
        m = LabMission(mode="autonomous")
        try:
            planner = self._fake_llm([
                json.dumps({"tool": "http-probe", "target": m.http_target, "args": {"command": "rm -rf /"}, "reason": "shell", "done": False}),
            ])
            Agent(m, planner, max_steps=5).run()
            assert any("raw shell" in e["msg"] for e in m.events)
        finally:
            m.close()

    def test_malformed_json_refused(self):
        m = LabMission(mode="autonomous")
        try:
            planner = self._fake_llm(["not json at all"])
            Agent(m, planner, max_steps=5).run()
            assert any("malformed JSON" in e["msg"] for e in m.events)
        finally:
            m.close()


class TestFallbackPlanner:
    def _flaky(self, responses, name="fake"):
        from g9_backend.agent import LLMPlanner

        class Fake(LLMPlanner):
            def __init__(self, responses, name="fake"):
                super().__init__(endpoint="http://fake.local/v1", model="fake")
                self.name = name
                self.responses = responses
                self.calls = 0

            def _complete(self, prompt):
                r = self.responses[min(self.calls, len(self.responses) - 1)]
                self.calls += 1
                if r is None:
                    raise AgentError("LLM endpoint 'http://fake.local/v1' unreachable: down")
                return r

        return Fake(responses)

    def test_failover_to_fallback_brain(self):
        from g9_backend.agent import FallbackPlanner
        import json
        m = LabMission(mode="autonomous")
        try:
            target = m.http_target
            main = self._flaky([None, None])  # main endpoint always down
            fb = self._flaky([
                json.dumps({"tool": "http-probe", "target": target, "args": {}, "reason": "fallback brain", "done": False}),
                json.dumps({"done": True}),
            ], name="fallback")
            planner = FallbackPlanner(main, fb)
            report = Agent(m, planner, max_steps=5).run()
            assert report["agent"]["steps"] == 1
            assert planner.switched and "switching to fallback" in planner.switched
            assert any("PLANNER FAILOVER" in e["msg"] for e in m.events)
            assert any("fallback brain" in e["msg"] for e in m.events)
        finally:
            m.close()

    def test_no_failover_when_main_healthy(self):
        from g9_backend.agent import FallbackPlanner
        import json
        m = LabMission(mode="autonomous")
        try:
            target = m.http_target
            main = self._flaky([json.dumps({"done": True})], name="main")
            fb = self._flaky([json.dumps({"done": True})], name="fallback")
            planner = FallbackPlanner(main, fb)
            Agent(m, planner, max_steps=3).run()
            assert planner.switched is None
        finally:
            m.close()
