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
        self.temperature = float(os.environ.get("G9_LLM_TEMPERATURE", "0"))
        self._auto_bound: str | None = None
        if not self.endpoint:
            raise AgentError(
                "no LLM endpoint configured — set G9_LLM_ENDPOINT (e.g. "
                "http://127.0.0.1:11434/v1 for Ollama) or use the rulebook planner"
            )

    def _resolve_model(self) -> str:
        """Bind to the weights AS INSTALLED: if the configured model name
        isn't what the endpoint serves, auto-bind to the served model
        and record the adjustment - never fail on a name mismatch."""
        if self._auto_bound:
            return self._auto_bound
        try:
            req = urllib.request.Request(self.endpoint.rstrip("/") + "/models")
            with urllib.request.urlopen(req, timeout=5) as resp:
                served = [m.get("id") for m in json.load(resp).get("data", []) if m.get("id")]
        except Exception:
            return self.model  # endpoint may not expose /models - use as configured
        if self.model in served:
            return self.model
        if served:
            self._auto_bound = served[0]
            return self._auto_bound
        return self.model

    def _complete(self, prompt: str, temperature: float | None = None) -> str:
        req = urllib.request.Request(
            self.endpoint.rstrip("/") + "/chat/completions",
            data=json.dumps({
                "model": self._resolve_model(),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.temperature if temperature is None else temperature,
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.load(resp)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as e:
            raise AgentError(
                f"LLM endpoint {self.endpoint!r} unreachable or returned an invalid "
                f"response: {e} - never a faked run"
            )
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
            action = _extract_json(raw)
        except AgentError:
            # adaptive retry: many reasoning weights loop at very low
            # temperature (documented on Qwythos-class cards) - retry once
            # at the recommended 0.6 before refusing
            if self.temperature <= 0.3:
                raw = self._complete(prompt, temperature=0.6)
                action = _extract_json(raw)
            else:
                raise
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


def _strip_reasoning(text: str) -> str:
    """Reasoning models (Qwythos-class, Qwen-thinking, R1-style) open
    with a think block before the answer. Strip it, then extract the
    first JSON object from whatever preamble remains - the build adapts
    to how the installed weights answer."""
    import re
    text = re.sub(r"<think(?:ing)?>.*?</think(?:ing)?>", "", text, flags=re.DOTALL | re.IGNORECASE)
    return text.strip()


def _extract_json(text: str) -> dict:
    """Pull the first JSON object out of arbitrary model preamble."""
    import re
    cleaned = _strip_reasoning(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            raise AgentError(
                f"LLM returned text but no parseable JSON action - refusing to act: {cleaned[:200]}"
            )
    raise AgentError(f"LLM returned no JSON action - refusing to act: {cleaned[:200]}")


def discover_brains() -> dict:
    """Probe every configured endpoint (OpenAI-compatible GET /models)
    and report what is actually being served. The build binds to the
    weights you installed - it never demands specific ones."""
    out = {}
    for role, cfg in brains().items():
        status = {"configured": cfg, "live": False, "served_models": [], "note": ""}
        try:
            req = urllib.request.Request(cfg["endpoint"].rstrip("/").replace("/v1", "") + "/v1/models")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.load(resp)
            served = [m.get("id") for m in data.get("data", []) if m.get("id")]
            status["live"] = True
            status["served_models"] = served
            if cfg["model"] in served:
                status["note"] = "configured model is served - exact match"
            elif served:
                status["note"] = (
                    f"configured model {cfg['model']!r} not in served list - the planner "
                    f"will auto-bind to {served[0]!r} (weights as installed)"
                )
        except Exception as e:
            status["note"] = f"unreachable: {e} - role stays unbound, mission continues without it"
        out[role] = status
    return out


def brains() -> dict:
    """The configured brain stack, by role. Each role is an
    OpenAI-compatible loopback endpoint; admission records the HF
    repo revision the weights came from."""
    import os
    roles = {}
    for role, env_ep, env_m in [
        ("planner", "G9_LLM_ENDPOINT", "G9_LLM_MODEL"),
        ("specialist", "G9_LLM_SPECIALIST_ENDPOINT", "G9_LLM_SPECIALIST_MODEL"),
        ("fast", "G9_LLM_FAST_ENDPOINT", "G9_LLM_FAST_MODEL"),
        ("fallback", "G9_LLM_FALLBACK_ENDPOINT", "G9_LLM_FALLBACK_MODEL"),
    ]:
        ep = os.environ.get(env_ep, "")
        if ep:
            roles[role] = {"endpoint": ep, "model": os.environ.get(env_m, "local")}
    return roles


class FallbackPlanner(Planner):
    """Main brain first; on failure (endpoint down, malformed output)
    switch to the fallback brain for the rest of the mission. The
    switch is sticky and recorded — never silent."""

    name = "llm+fallback"

    def __init__(self, main: Planner, fallback: Planner):
        self.main = main
        self.fallback = fallback
        self.active = main
        self.switched: str | None = None

    def decide(self, state: dict) -> dict | None:
        if self.active is not self.main:
            return self.fallback.decide(state)
        try:
            return self.main.decide(state)
        except AgentError as e:
            if self.fallback is None:
                raise
            self.active = self.fallback
            self.switched = f"{self.main.name} failed ({e}) - switching to fallback {self.fallback.name}"
            return self.fallback.decide(state)


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
            if hasattr(m, "planner_state"):
                state = m.planner_state(self.steps, self.max_steps)
            else:
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
            switch = getattr(self.planner, "switched", None)
            if switch and switch not in [e.get("msg") for e in m.events]:
                m.emit("gate", f"PLANNER FAILOVER: {switch}")
            try:
                action = self.planner.decide(state)
            except AgentError as e:
                m.emit("gate", f"AGENT REFUSAL: {e}")
                self.refusals.append(str(e))
                break
            if action is None:
                m.emit("thinking", f"planner {self.planner.name}: mission complete after {self.steps} steps")
                break
            # the agent boundary itself validates the proposal — defense in
            # depth before the policy gate: ungranted tool or out-of-scope
            # target is refused and recorded, whatever the planner was
            if action.get("tool") not in state["allowed_tools"]:
                msg = f"planner proposed ungranted tool {action.get('tool')!r} — the model cannot grant itself capabilities"
                m.emit("gate", f"AGENT REFUSAL: {msg}")
                self.refusals.append(msg)
                break
            if action.get("target") not in set(state["targets"].values()):
                msg = (f"planner proposed target {action.get('target')!r} outside the authorized "
                       "scope — targets come from the engagement, never model prose")
                m.emit("gate", f"AGENT REFUSAL: {msg}")
                self.refusals.append(msg)
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
