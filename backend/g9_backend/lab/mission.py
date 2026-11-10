"""g9-lab: the full mission orchestrator — one real end-to-end run.

The pipeline the whole control plane exists for, executed for real
against the loopback lab target:

  policy (deny-by-default) → budget/scope → lab-native adapter
    → REAL execution → evidence collector → CANDIDATE findings only
    → deterministic Verification Authority (reproduction, never
      self-promotion) → report

Every decision lands in the tamper-evident ledger. The verification
step is deterministic code outside any model: a candidate is
promoted to `reproduced` ONLY when an independent re-probe emits the
same template-id again.
"""

from __future__ import annotations

import time

from ..core.audit_ledger import AuditLedger
from ..evidence import EvidenceGraph, ResultCollector
from ..ops import BudgetController, BudgetError
from ..policy.engine import PolicyEngine
from ..storage import SqliteEvidenceStore, SqliteLedgerStore, durable_graph, durable_ledger
from .native_adapters import LAB_ADAPTERS
from .target import LabTarget

LAB_TOOLS = set(LAB_ADAPTERS)
PHASES = [
    ("recon", ["portscan-scoped", "http-probe"]),
    ("tls", ["tls-audit"]),
    ("web-audit", ["header-audit", "content-discovery"]),
]
TOKEN_COST_PER_ACTION = 200


def _spec(engagement_id: str, principal: str, tool_id: str, target: str, args: dict | None = None) -> dict:
    return {
        "action_id": f"ACT-LAB-{tool_id}-{int(time.time() * 1000) % 100000}",
        "engagement_id": engagement_id,
        "principal_id": principal,
        "agent_id": principal.split(":")[-1],
        "tool_id": tool_id,
        "tool_version": "lab-native-1",
        "normalized_arguments": args or {},
        "target_set": [target],
        "working_directory": "/workspace/lab-run",
        "environment_profile": "lab-plane",
        "sandbox_profile": "restricted-analysis",
        "network_policy_id": "lab-loopback",
        "resource_budget": {"cpu": 1, "mem_gb": 1, "max_pps": 500},
        "policy_revision": "ceder@v1",
    }


class LabMission:
    def __init__(self, *, db_path: str | None = None, engagement_id: str = "ENG-LAB-1"):
        self.engagement_id = engagement_id
        self.target = LabTarget().start()
        self.http_target = f"127.0.0.1:{self.target.http_port}"
        self.debug_target = f"127.0.0.1:{self.target.debug_port}"
        self.scopes = [self.http_target, self.debug_target, "127.0.0.1"]
        self.engine = PolicyEngine(
            engagements={engagement_id: {
                "scope": self.scopes,
                "roe_signed": True,
                "principals": {"agent:chimera-lab": {"revoked": False}},
            }},
            grants={engagement_id: {"tools": LAB_TOOLS}},
        )
        self.budget = BudgetController(
            engagement_id=engagement_id, token_budget=50_000,
            request_rate_per_min=600, cidr_scopes=self.scopes,
        )
        if db_path:
            self.ledger = durable_ledger(engagement_id, SqliteLedgerStore(db_path))
            self.graph = durable_graph(engagement_id, SqliteEvidenceStore(db_path))
        else:
            self.ledger = AuditLedger(engagement_id)
            self.graph = EvidenceGraph(engagement_id)
        self.collector = ResultCollector(self.graph)

    def close(self):
        self.target.stop()

    # ------------------------------------------------------------- gates

    def _invoke(self, tool_id: str, target: str, args: dict | None = None) -> dict:
        spec = _spec(self.engagement_id, "agent:chimera-lab", tool_id, target, args)
        decision = self.engine.evaluate({
            "engagement_id": self.engagement_id,
            "principal_id": spec["principal_id"],
            "tool_id": tool_id,
            "targets": spec["target_set"],
            "sandbox_class": "restricted-analysis",
            "required_sandbox_class": "restricted-analysis",
        })
        if decision.effect == "deny":
            return {"ok": False, "blocked_at": "policy", "reasons": decision.reasons}
        try:
            check = self.budget.check_target(target)
            if not check["ok"]:
                return {"ok": False, "blocked_at": "scope", "reason": check["reason"]}
            rate = self.budget.check_rate()
            if not rate["ok"]:
                return {"ok": False, "blocked_at": "rate", "reason": rate["reason"]}
        except BudgetError as e:
            return {"ok": False, "blocked_at": "budget", "reason": str(e)}
        try:
            self.budget.charge_tokens(TOKEN_COST_PER_ACTION)
        except BudgetError as e:
            return {"ok": False, "blocked_at": "budget", "reason": str(e)}
        adapter = LAB_ADAPTERS[tool_id]
        run = adapter(spec)  # REAL execution against the lab target
        self.ledger.append("agent:chimera-lab", "tool.invoke", subject=tool_id,
                          detail=f"target={target} exit={run['exit_code']}")
        rec = self.collector.ingest_tool_result(
            tool_id=tool_id, command=f"lab-native {tool_id} {target}",
            stdout=run["stdout"], stderr="", targets=[target], exit_code=run["exit_code"],
        )
        return {"ok": True, "tool": tool_id, "target": target, "evidence": rec}

    # ---------------------------------------------------------- the run

    def run(self) -> dict:
        self.ledger.append("operator", "engagement.open",
                           detail="lab-plane full active run — RoE signed, loopback scope")
        phases: list[dict] = []
        for phase, tools in PHASES:
            results = []
            for tool in tools:
                targets = [self.http_target]
                if tool == "portscan-scoped":
                    targets = [self.http_target, self.debug_target]
                for t in targets:
                    r = self._invoke(tool, t)
                    results.append(r)
                    if r.get("ok"):
                        continue
                    self.ledger.append("cerberus", "gate.block", subject=tool,
                                       detail=f"stage={r['blocked_at']} reason={r.get('reason') or r.get('reasons')}")
            phases.append({"phase": phase, "results": results})
        report = self.verify_and_report(phases)
        self.ledger.append("operator", "engagement.report",
                           detail=f"candidates={report['candidates']} reproduced={report['reproduced']}")
        return report

    # -------------------------------------------- verification authority

    def verify_and_report(self, phases: list[dict]) -> dict:
        """Deterministic Verification Authority: every candidate finding
        is re-probed independently. Promotion happens ONLY on
        reproduction — the scanner's claim is never trusted."""
        candidates = [n for n in self.graph.nodes.values()
                      if n["klass"] == "finding" and n["validation_status"] == "candidate"]
        reproduced: list[dict] = []
        for cand in candidates:
            template = cand["provenance"].get("template", "")
            host = cand["meta"].get("matched_at", "")
            tool = cand["source"]
            probe = LAB_ADAPTERS.get(tool)
            if probe is None:
                continue
            target = self._target_for(cand)
            if target is None:
                continue
            rerun = probe(_spec(self.engagement_id, "verification:authority", tool, target))
            for line in rerun["stdout"].splitlines():
                import json as _json
                try:
                    data = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                if data.get("template-id") == template:
                    cand["validation_status"] = "reproduced"
                    reproduced.append({
                        "id": cand["id"], "template": template, "host": host,
                        "severity": cand["meta"].get("severity", "unknown"),
                    })
                    break
        ok, seq, reason = self.ledger.verify_chain()
        return {
            "ok": True,
            "engagement_id": self.engagement_id,
            "scope": self.scopes,
            "phases": [{"phase": p["phase"],
                        "invocations": [r for r in p["results"]]} for p in phases],
            "candidates": len(candidates),
            "reproduced": len(reproduced),
            "findings_reproduced": reproduced,
            "nodes": len(self.graph.nodes),
            "edges": len(self.graph.edges),
            "tokens_used": self.budget.tokens_used,
            "ledger_verified": ok,
            "ledger_records": len(self.ledger.records),
        }

    def _target_for(self, cand: dict) -> str | None:
        # candidate host labels carry host:port
        host = cand["label"].split("]:")[0].split("[")[-1] if "[" in cand["label"] else None
        for scope in [self.http_target, self.debug_target]:
            if scope in cand["label"] or scope in str(cand.get("meta", {})):
                return scope
        return self.http_target if host is None else None

    # -------------------------------------------------------- out-of-run

    def invoke_out_of_scope(self, tool_id: str, target: str) -> dict:
        """Prove the gate: an out-of-scope target is blocked."""
        return self._invoke(tool_id, target)


def run_full_lab_mission(db_path: str | None = None) -> dict:
    """One-shot: spin target, run the full active mission, stop target."""
    mission = LabMission(db_path=db_path)
    try:
        return mission.run()
    finally:
        mission.close()
