"""g9-policy: Cedar-style deny-by-default policy decision point.
Mirrors src/lib/policyEngine.js."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PolicyDecision:
    effect: str  # allow | deny
    reasons: list[str]
    policy_revision: str


class PolicyEngine:
    def __init__(self, engagements: dict, grants: dict, policy_revision: str = "ceder@v1"):
        self.engagements = engagements
        self.grants = grants
        self.policy_revision = policy_revision
        self.decisions: list[PolicyDecision] = []

    def evaluate(self, request: dict) -> PolicyDecision:
        reasons: list[str] = []

        eng = self.engagements.get(request.get("engagement_id", ""))
        if eng is None:
            reasons.append("unknown engagement")
        else:
            if not eng.get("roe_signed", False):
                reasons.append("rules of engagement unsigned — red tier locked")
            principal = (eng.get("principals") or {}).get(request.get("principal_id", ""))
            if principal is None:
                reasons.append(f"unknown principal {request.get('principal_id')}")
            elif principal.get("revoked", False):
                reasons.append(f"principal {request.get('principal_id')} revoked")
            for t in request.get("targets", []):
                if t not in eng.get("scope", []):
                    reasons.append(f"target {t} outside authorized scope")

        grant = self.grants.get(request.get("engagement_id", ""))
        if grant is None:
            reasons.append("no capability grant issued for engagement")
        elif request.get("tool_id") not in grant.get("tools", set()):
            reasons.append(f"tool {request.get('tool_id')} not in capability grant")

        if request.get("sandbox_class") and request.get("required_sandbox_class") and request["sandbox_class"] != request["required_sandbox_class"]:
            reasons.append(f"sandbox class {request['sandbox_class']} does not satisfy required {request['required_sandbox_class']}")

        if request.get("high_impact") and not request.get("approval_id"):
            reasons.append("high-impact action requires an operator approval reference")
        if request.get("approval_id") and request.get("bound_digest") and request.get("action_digest") != request["bound_digest"]:
            reasons.append("approval digest mismatch — action specification changed after approval")
        if request.get("self_authorized"):
            reasons.append("agent self-authorization attempt — the model is not an authorization source")

        decision = PolicyDecision(
            effect="allow" if not reasons else "deny",
            reasons=reasons,
            policy_revision=self.policy_revision,
        )
        self.decisions.append(decision)
        return decision
