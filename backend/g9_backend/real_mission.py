"""g9 real-engagement mission — the agent-driven run against an
AUTHORIZED third-party target, through the full gated chain with real
tool execution.

Doctrine, unchanged and load-bearing:

  - an engagement without a signed RoE is red-tier locked — the
    mission refuses to construct, never runs unsigned
  - scope is the ONLY source of targets; every proposal outside it
    dies at the policy gate
  - grants are explicit; the planner (rulebook or LLM) proposes one
    typed action per step and the code disposes
  - every invocation passes MCP contract → policy → budget/scope →
    autonomy → adapter → hardened container (cap-drop ALL,
    no-new-privileges, read-only rootfs), optionally executed for
    real against Docker
  - scanner output enters as CANDIDATES only; the Verification
    Authority re-runs the source probe independently — promotion to
    `reproduced` happens only on reproduction. With execution
    disabled the report says so honestly; nothing is invented.

Default autonomy for a real engagement is human-in-the-loop — the
operator escalates to autonomous only when they trust the stack
(manual → hitl → autonomous, operator-only).
"""

from __future__ import annotations

import time

from .agent import Planner
from .core.audit_ledger import AuditLedger
from .evidence import EvidenceGraph, ResultCollector
from .executor.invoke_chain import ADAPTERS, invoke_tool, required_sandbox_class
from .mcp.contract import family_for_tool
from .ops import BudgetController, BudgetError
from .ops.autonomy import AutonomyController
from .policy.engine import PolicyEngine


class RealMissionError(ValueError):
    pass


# tools whose invocation against a live third-party target is loud
# enough to require operator approval in hitl/manual modes - every
# offensive-tier tool is approval-gated by default
HIGH_IMPACT_REAL_TOOLS = {
    "nmap-scoped", "masscan", "nuclei", "ffuf", "gobuster",
    "feroxbuster", "owasp-zap", "caido", "hakrawler",
    # offensive waves
    "sqlmap", "xsstrike-dalfox", "commix", "ssrfmap-gopherus",
    "hydra", "hashcat", "john", "kerbrute", "getnpusers",
    "getuserspnss", "secretsdump", "wmiexec-psexec", "certipy",
}

TOKEN_COST_PER_ACTION = 500

# sensible per-family defaults for required typed fields; the planner
# can always supply its own args — these make the rulebook path work
_FAMILY_DEFAULTS = {
    "ports": "1-1000",
    "flags": [],
    "wordlist": "/opt/assets/common.txt",
    "severity": "medium,high,critical",
    "tags": [],
    "sources": ["crtsh"],
    "record": "A",
    "collector": "BloodHound",
    "filter": "(objectClass=*)",
    "profile": "baseline",
    "orgs": [],
    "corpus": "default",
    "control_version": "v1",
    "feed": "default",
    "platforms": [],
    "purpose": "engagement",
    # offensive waves
    "risk": "1",
    "level": "1",
    "params": "id=1",
    "param": "url",
    "service": "ssh",
    "usernames": ["admin"],
    "users_file": "/opt/assets/users.txt",
    "hashes_file": "/opt/assets/hashes.txt",
    "domain": "TARGET",
    "credentials_env": "G9_AD_CREDS",
    "technique": "wmiexec",
    "command_id": "whoami",
    "dc": "TARGET",
    "output_format": "hashcat",
}


def build_call(tool_id: str, target: str, args: dict | None = None) -> dict:
    """A typed contract call from the family schema — never a shell
    string. Single-target form; list fields wrap the target."""
    family = family_for_tool(tool_id)
    if family is None:
        raise RealMissionError(
            f"tool {tool_id!r} has no typed family contract — not callable by agents"
        )
    from .mcp.contract import TOOL_FAMILIES
    schema = TOOL_FAMILIES[family]["schema"]
    call: dict = dict(args or {})
    for field, ftype in schema.items():
        if field in call:
            continue
        if ftype.startswith("list[str]"):
            call[field] = [target]
        elif ftype.startswith("str"):
            call[field] = _FAMILY_DEFAULTS.get(field, target)
    # TARGET sentinel: the scope entry stands in for the domain/dc
    for k in ("domain", "dc"):
        if call.get(k) == "TARGET":
            call[k] = target
    if "command" in call or "shell" in call or "argv" in call:
        raise RealMissionError("raw shell strings are rejected at the contract boundary")
    return call


def _spec(engagement_id: str, principal: str, tool_id: str, target: str, args: dict | None = None) -> dict:
    return {
        "action_id": f"ACT-REAL-{tool_id}-{int(time.time() * 1000) % 100000000}",
        "engagement_id": engagement_id,
        "principal_id": principal,
        "agent_id": principal.split(":")[-1],
        "tool_id": tool_id,
        "tool_version": "admitted-1",
        "normalized_arguments": args or {},
        "target_set": [target],
        "working_directory": "/workspace/engagement-run",
        "environment_profile": "host-plane",
        "sandbox_profile": "restricted-analysis",
        "network_policy_id": "engagement-scoped",
        "resource_budget": {"cpu": 1, "mem_gb": 2, "max_pps": 500},
        "policy_revision": "ceder@v1",
    }


class RealRulebookPlanner(Planner):
    """The deterministic reference shape for a real engagement, built
    from what the engagement actually granted: recon → web-probe →
    tls → template-scan, one target at a time."""

    name = "rulebook-real"

    PRIORITY = [
        # recon tier
        ("network-recon", "nmap-scoped"),
        ("web-probe", "httpx"),
        ("tls-audit", "testssl"),
        ("template-scan", "nuclei"),
        ("passive-recon", "subfinder"),
        ("content-discovery", "ffuf"),
        ("screenshot-recon", "gowitness"),
        ("dns-query", "dig"),
        ("osint-harvest", "theharvester"),
        ("web-crawl", "hakrawler"),
        # offensive wave 1: web exploitation (only runs if granted)
        ("web-exploit-sqli", "sqlmap"),
        ("web-exploit-xss", "xsstrike-dalfox"),
        ("web-exploit-commix", "commix"),
        ("web-exploit-ssrf", "ssrfmap-gopherus"),
        # offensive wave 2: credential attacks (only runs if granted)
        ("credential-brute", "hydra"),
        ("hash-crack", "hashcat"),
        ("kerb-enum", "kerbrute"),
        ("kerb-asreproast", "getnpusers"),
        ("kerb-kerberoast", "getuserspnss"),
        # offensive wave 3: AD kill-chain (only runs if granted)
        ("ad-secret-dump", "secretsdump"),
        ("ad-cert-abuse", "certipy"),
        ("ad-remote-exec", "wmiexec-psexec"),
    ]

    def __init__(self, tools: set[str], targets: list[str]):
        self.plan: list[tuple[str, str, str]] = []
        for family, tool in self.PRIORITY:
            if tool not in tools:
                continue
            for t in targets:
                self.plan.append((tool, t, f"{family}: {tool} against {t}"))
        self.step = 0

    def decide(self, state: dict) -> dict | None:
        if self.step >= len(self.plan):
            return None
        tool, target, reason = self.plan[self.step]
        self.step += 1
        return {"tool": tool, "target": target, "args": {}, "reason": reason}


class RealMission:
    """One gated mission against one real engagement's scope."""

    def __init__(self, *, engagement: dict, mode: str = "hitl",
                 execute: bool = True, principal: str = "agent:chimera",
                 token_budget: int = 200_000, rate_per_min: int = 120):
        if not engagement.get("roe_signed"):
            raise RealMissionError(
                f"engagement {engagement.get('engagement_id', '?')!r} has no signed RoE — "
                "red tier locked; the mission refuses to construct"
            )
        scope = engagement.get("scope") or []
        if not scope:
            raise RealMissionError("an engagement requires a non-empty authorized scope")
        self.engagement_id = engagement["engagement_id"]
        self.scope = list(scope)
        self.brief = dict(engagement.get("brief") or {})
        self.principal = principal
        self.execute = execute
        self.autonomy = AutonomyController(mode=mode, engagement_id=self.engagement_id)
        principals = engagement.get("principals") or [principal]
        self.engine = PolicyEngine(
            engagements={self.engagement_id: {
                "scope": self.scope,
                "roe_signed": True,
                "principals": {p: {"revoked": False} for p in principals},
            }},
            grants={self.engagement_id: {"tools": set(engagement.get("grants") or [])}},
        )
        self.budget = BudgetController(
            engagement_id=self.engagement_id, token_budget=token_budget,
            request_rate_per_min=rate_per_min, cidr_scopes=self.scope,
        )
        self.ledger = AuditLedger(self.engagement_id)
        self.graph = EvidenceGraph(self.engagement_id)
        self.collector = ResultCollector(self.graph)
        self.events: list[dict] = []
        self.report: dict | None = None
        self.error: str | None = None
        self.done = False

    # ------------------------------------------------------------ stream

    def emit(self, kind: str, msg: str, **data) -> None:
        self.events.append({"t": round(time.time(), 3), "kind": kind, "msg": msg, **data})

    def planner_state(self, steps: int, max_steps: int) -> dict:
        """Everything the planner may observe — it grants nothing."""
        return {
            "allowed_tools": set(self.engine.grants[self.engagement_id]["tools"]) & set(ADAPTERS),
            "targets": {f"target-{i}": t for i, t in enumerate(self.scope)},
            # the operator's brief is trusted CONTEXT - it tells the planner
            # where to start; it never widens scope, tools, or permissions
            "brief": self.brief,
            "findings": [
                {"template": n["provenance"].get("template"), "status": n["validation_status"]}
                for n in self.graph.nodes.values() if n["klass"] == "finding"
            ],
            "steps": steps,
            "max_steps": max_steps,
        }

    def pending_actions(self) -> list[dict]:
        return [
            {"action_id": a, "tool": act["spec"]["tool_id"], "target": act["target"],
             "high_impact": act.get("high_impact", False)}
            for a, act in self.autonomy.pending.items()
        ]

    # ------------------------------------------------------------- gates

    def _invoke(self, tool_id: str, target: str, args: dict | None = None) -> dict:
        if tool_id not in ADAPTERS:
            self.emit("gate", f"REFUSED: tool {tool_id!r} has no admitted adapter")
            return {"ok": False, "blocked_at": "adapter", "reason": f"no adapter for {tool_id}"}
        spec = _spec(self.engagement_id, self.principal, tool_id, target, args)
        decision = self.engine.evaluate({
            "engagement_id": self.engagement_id,
            "principal_id": self.principal,
            "tool_id": tool_id,
            "targets": spec["target_set"],
            "sandbox_class": "restricted-analysis",
            "required_sandbox_class": required_sandbox_class(tool_id),
        })
        if decision.effect == "deny":
            self.emit("gate", f"POLICY DENY {tool_id} -> {target}: {'; '.join(decision.reasons)}")
            self.ledger.append(self.principal, "gate.block", subject=tool_id,
                               detail=f"stage=policy target={target}")
            return {"ok": False, "blocked_at": "policy", "reasons": decision.reasons}
        self.emit("thinking", f"policy cleared {tool_id} on {target} - evaluating autonomy mode '{self.autonomy.mode}'")
        verdict = self.autonomy.decide(
            {"action_id": spec["action_id"],
             "high_impact": tool_id in HIGH_IMPACT_REAL_TOOLS,
             "spec": spec, "target": target},
            decision.effect,
        )
        if verdict == "await_approval":
            self.emit("gate", f"AUTONOMY: action queued for operator approval ({tool_id} on {target})")
            return {"ok": False, "blocked_at": "autonomy", "pending": True,
                    "action_id": spec["action_id"], "tool": tool_id, "target": target,
                    "reason": f"mode={self.autonomy.mode}: operator approval required"}
        if verdict == "refuse":
            self.emit("gate", f"AUTONOMY: refused {tool_id}")
            return {"ok": False, "blocked_at": "autonomy", "reason": "refused"}
        return self._execute_gated(spec, target, args)

    def _execute_gated(self, spec: dict, target: str, args: dict | None = None) -> dict:
        tool_id = spec["tool_id"]
        try:
            check = self.budget.check_target(target)
            if not check["ok"]:
                self.emit("gate", f"SCOPE DENY {tool_id} -> {target}: {check['reason']}")
                return {"ok": False, "blocked_at": "scope", "reason": check["reason"]}
            rate = self.budget.check_rate()
            if not rate["ok"]:
                return {"ok": False, "blocked_at": "rate", "reason": rate["reason"]}
            self.budget.charge_tokens(TOKEN_COST_PER_ACTION)
        except BudgetError as e:
            return {"ok": False, "blocked_at": "budget", "reason": str(e)}
        try:
            call = build_call(tool_id, target, args)
        except RealMissionError as e:
            self.emit("gate", f"CONTRACT REFUSAL: {e}")
            return {"ok": False, "blocked_at": "mcp-contract", "reason": str(e)}
        self.emit("execution", f"EXECUTING {tool_id} against {target} "
                 f"({'real container run' if self.execute else 'command build — execution disabled'})")
        result = invoke_tool(
            engine=self.engine, budget=self.budget, spec=spec,
            call=call, execute_now=self.execute, collector=self.collector,
        )
        if result.get("ok"):
            self.emit("execution", f"{tool_id} finished - output entering evidence collector as observations + candidates")
        else:
            self.emit("gate", f"{tool_id} blocked at {result.get('blocked_at')}: {result.get('reason')}")
        self.ledger.append(self.principal, "tool.invoke", subject=tool_id,
                           detail=f"target={target} executed={result.get('executed', False)} "
                                  f"ok={result.get('ok')}")
        result["tool"] = tool_id
        result["target"] = target
        return result

    def approve_pending(self, action_id: str) -> dict:
        """Operator approves a queued action — it executes NOW through
        the same budget/scope gates, with the approval recorded."""
        action = self.autonomy.pending.get(action_id)
        if action is None:
            return {"ok": False, "reason": f"no pending action {action_id!r}"}
        self.autonomy.approve(action_id, "operator")
        spec = action["spec"]
        self.ledger.append("operator", "action.approve", subject=action_id,
                           detail=f"tool={spec['tool_id']} target={spec['target_set'][0]}")
        return self._execute_gated(spec, spec["target_set"][0], spec.get("normalized_arguments"))

    # ---------------------------------------------------------- the run

    def run(self, planner: Planner | None = None, max_steps: int = 25) -> dict:
        """Agent-driven: the planner proposes, the gates dispose."""
        from .agent import Agent
        if planner is None:
            planner = RealRulebookPlanner(
                set(self.engine.grants[self.engagement_id]["tools"]) & set(ADAPTERS),
                self.scope,
            )
        self.ledger.append("operator", "engagement.open",
                           detail=f"real-plane run - RoE signed, scope={self.scope}")
        report = Agent(self, planner, max_steps=max_steps).run()
        self.report = report
        return report

    # -------------------------------------------- verification authority

    def verify_and_report(self, phases: list[dict]) -> dict:
        """Deterministic Verification Authority: every candidate is
        re-probed by re-running its source tool against the same
        target. Promotion only on reproduction. With execution
        disabled the report states it honestly — nothing invented."""
        candidates = [n for n in self.graph.nodes.values()
                      if n["klass"] == "finding" and n["validation_status"] == "candidate"]
        self.emit("phase", f"VERIFICATION AUTHORITY: independently re-probing {len(candidates)} candidates - promotion only on reproduction")
        reproduced: list[dict] = []
        unverifiable = 0
        for cand in candidates:
            template = cand["provenance"].get("template", "")
            host = cand["meta"].get("matched_at") or cand["meta"].get("host") or ""
            tool = cand["source"]
            target = cand["meta"].get("host") or self._scope_for_label(cand["label"])
            if tool not in ADAPTERS or target is None:
                unverifiable += 1
                continue
            if not self.execute:
                unverifiable += 1
                continue
            spec = _spec(self.engagement_id, "verification:authority", tool, target)
            rerun = invoke_tool(
                engine=self.engine, budget=self.budget, spec=spec,
                call=build_call(tool, target), execute_now=True,
            )
            run = rerun.get("run") or {}
            found_again = False
            import json as _json
            for line in (run.get("stdout") or "").splitlines():
                try:
                    data = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                if data.get("template-id") == template:
                    found_again = True
                    break
            if found_again:
                self.emit("finding", f"REPRODUCED: {template} on {host} - promoted to reproduced")
                cand["validation_status"] = "reproduced"
                reproduced.append({
                    "id": cand["id"], "template": template, "host": host,
                    "severity": cand["meta"].get("severity", "unknown"),
                })
            else:
                self.emit("finding", f"NOT REPRODUCED: {template} on {host} - stays a candidate")
        ok, seq, reason = self.ledger.verify_chain()
        self.emit("ledger", f"hash chain verified: {ok} over {len(self.ledger.records)} records")
        self.ledger.append("operator", "engagement.report",
                           detail=f"candidates={len(candidates)} reproduced={len(reproduced)}")
        return {
            "ok": True,
            "engagement_id": self.engagement_id,
            "scope": self.scope,
            "mode": self.autonomy.mode,
            "executed": self.execute,
            "phases": [{"phase": p["phase"], "invocations": p["results"]} for p in phases],
            "candidates": len(candidates),
            "reproduced": len(reproduced),
            "unverifiable": unverifiable,
            "findings_reproduced": reproduced,
            "nodes": len(self.graph.nodes),
            "edges": len(self.graph.edges),
            "tokens_used": self.budget.tokens_used,
            "ledger_verified": ok,
            "ledger_records": len(self.ledger.records),
            "verification_note": (
                "real re-probe reproduction" if self.execute
                else "execution disabled - candidates remain candidates; nothing promoted without reproduction"
            ),
        }

    def _scope_for_label(self, label: str) -> str | None:
        for s in self.scope:
            if s in label:
                return s
        return self.scope[0] if self.scope else None

    def invoke_out_of_scope(self, tool_id: str, target: str) -> dict:
        """Prove the gate: an out-of-scope target is blocked."""
        return self._invoke(tool_id, target)
