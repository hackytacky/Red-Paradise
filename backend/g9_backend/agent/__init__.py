"""g9-agent: the agent layer — an AI drives the mission, the code
keeps every gate.

Doctrine, welded in:

  - the planner (rulebook or LLM) PROPOSES one typed action per step:
    {tool, target, args, reason} — nothing else
  - the AGENT submits it through the same invoke chain: policy →
    budget/scope → autonomy → adapter → evidence → candidates only
  - a proposal outside scope/tools/contracts is refused at the gate
    and recorded — the model cannot grant itself permissions
  - hard limits: max steps, token budget, kill switch, operator-only
    mode changes. The loop terminates honestly.

Planners:
  RulebookPlanner — deterministic, works with zero dependencies; the
    mission shape the lab plane already proves.
  LLMPlanner — any OpenAI-compatible local endpoint (Ollama, vLLM,
    llama.cpp server) on the G9 host. G9_LLM_ENDPOINT / G9_LLM_MODEL.
    Endpoint missing → honest AgentError, never a faked run.
"""

from __future__ import annotations

import json
import os
import urllib.request


class AgentError(ValueError):
    pass


class Planner:
    name = "planner"

    def decide(self, state: dict) -> dict | None:
        """Return the next action {tool, target, args, reason} or None
        when the mission is complete. `state` carries everything the
        planner may observe — it grants nothing."""
        raise NotImplementedError


class RulebookPlanner(Planner):
    """The deterministic reference agent: the proven mission shape
    (recon → tls → web-audit), expressed as a checklist with reasons."""

    name = "rulebook"

    CHECKLIST = [
        ("portscan-scoped", "http", {}, "recon: enumerate open ports on the primary service"),
        ("portscan-scoped", "debug", {}, "recon: check the secondary service port"),
        ("http-probe", "http", {}, "identify the service and banner on the primary port"),
        ("tls-audit", "http", {}, "check for transport security on the primary service"),
        ("header-audit", "http", {}, "audit security response headers"),
        ("content-discovery", "http", {}, "discover exposed paths from the allowlisted wordlist"),
    ]

    def __init__(self):
        self.step = 0

    def decide(self, state: dict) -> dict | None:
        if self.step >= len(self.CHECKLIST):
            return None
        tool, which, args, reason = self.CHECKLIST[self.step]
        self.step += 1
        target = state["targets"].get(which) or state["targets"].get("http")
        if target is None:
            return None
        return {"tool": tool, "target": target, "args": args, "reason": reason}


class LLMPlanner(Planner):
    """A local model proposes one typed action per step. The response
    is parsed and validated BEFORE anything executes: unknown tool,
    out-of-scope target, raw shell, or malformed JSON all refuse with
    a precise recorded reason."""

    name = "llm"

    def __init__(self, endpoint: str | None = None, model: str | None = None):
        self.endpoint = endpoint or os.environ.get("G9_LLM_ENDPOINT", "")
        self.model = model or os.environ.get("G9_LLM_MODEL", "local")
        if not self.endpoint:
            raise AgentError(
                "no LLM endpoint configured — set G9_LLM_ENDPOINT (e.g. "
                "http://127.0.0.1:11434/v1 for Ollama) or use the rulebook planner"
            )

    def _complete(self, prompt: str) -> str:
        req = urllib.request.Request(
            self.endpoint.rstrip("/") + "/chat/completions",
            data=json.dumps({
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.load(resp)
        return data["choices"][0]["message"]["content"]

    def decide(self, state: dict) -> dict:
        prompt = (
            "You are the G9 red-team planning agent. Propose the NEXT single action "
            "as strict JSON: {\"tool\": str, \"target\": str, \"args\": {}, \"reason\": str, \"done\": bool}. "
            f"Allowed tools (typed contracts only, raw shell is forbidden): {sorted(state['allowed_tools'])}. "
            f"Authorized targets (the ONLY valid target values): {sorted(set(state['targets'].values()))}. "
            f"Findings so far: {json.dumps(state['findings'])}. Steps used: {state['steps']}/{state['max_steps']}. "
            "If the mission is complete, return done=true."
        )
        raw = self._complete(prompt)
        try:
            action = json.loads(raw)
        except json.JSONDecodeError:
            raise AgentError(f"LLM returned malformed JSON — refusing to act: {raw[:200]}")
        if not isinstance(action, dict):
            raise AgentError("LLM response is not an object — refusing to act")
        if action.get("done"):
            return None
        if action.get("tool") not in state["allowed_tools"]:
            raise AgentError(
                f"LLM proposed tool {action.get('tool')!r} outside the granted set — "
                "the model cannot grant itself capabilities"
            )
        if action.get("target") not in set(state["targets"].values()):
            raise AgentError(
                f"LLM proposed target {action.get('target')!r} outside the authorized scope — "
                "targets come from the engagement, never model prose"
            )
        if any(k in (action.get("args") or {}) for k in ("command", "shell", "argv")):
            raise AgentError("LLM proposed a raw shell string — rejected at the agent boundary")
        return action


class Agent:
    """The loop: propose → gate → execute → observe, until done or a
    hard limit. Every step is emitted to the mission event stream."""

    def __init__(self, mission, planner: Planner, max_steps: int = 15):
        self.mission = mission
        self.planner = planner
        self.max_steps = max_steps
        self.steps = 0
        self.refusals: list[str] = []

    def run(self) -> dict:
        m = self.mission
        m.emit("phase", f"AGENT ONLINE: planner={self.planner.name} mode={m.autonomy.mode} max_steps={self.max_steps}")
        results = []
        while self.steps < self.max_steps:
            state = {
                "allowed_tools": set(m.engine.grants[m.engagement_id]["tools"]),
                "targets": {"http": m.http_target, "debug": m.debug_target},
                "findings": [
                    {"template": n["provenance"].get("template"), "status": n["validation_status"]}
                    for n in m.graph.nodes.values() if n["klass"] == "finding"
                ],
                "steps": self.steps,
                "max_steps": self.max_steps,
            }
            try:
                action = self.planner.decide(state)
            except AgentError as e:
                m.emit("gate", f"AGENT REFUSAL: {e}")
                self.refusals.append(str(e))
                break
            if action is None:
                m.emit("thinking", f"planner {self.planner.name}: mission complete after {self.steps} steps")
                break
            m.emit("thinking", f"planner {self.planner.name} proposes: {action['tool']} on {action['target']} — {action.get('reason', '')}")
            r = m._invoke(action["tool"], action["target"], action.get("args") or {})
            results.append(r)
            self.steps += 1
            if not r.get("ok") and r.get("blocked_at") in ("budget", "rate"):
                m.emit("gate", f"AGENT HALT: {r.get('reason')} — operator attention required")
                break
            if not r.get("ok") and r.get("blocked_at") == "autonomy":
                m.emit("gate", "AGENT PAUSED: action queued for operator approval")
        else:
            m.emit("gate", f"AGENT STEP LIMIT reached ({self.max_steps}) — stopping honestly")
        report = m.verify_and_report([{"phase": f"agent:{self.planner.name}", "results": results}])
        report["agent"] = {
            "planner": self.planner.name,
            "steps": self.steps,
            "refusals": self.refusals,
        }
        return report
