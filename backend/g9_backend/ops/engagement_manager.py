"""g9-ops: engagement/scope manager (Stage 01) — quick-start edition.

The engagement registry: scope, RoE state, principals, and grants per
engagement, created at runtime instead of hardcoded demo state. The
1-click QUICK START creates a lab-tier engagement (loopback-only
scope, lab RoE pre-signed for the disposable lab target, all lab
tools granted) and launches the live mission — the UI asks the
operator YES/NO before anything runs.

Doctrine unchanged: an engagement without a signed RoE is red-tier
locked; scope is the ONLY source of targets; grants are explicit.
"""

from __future__ import annotations


class EngagementError(ValueError):
    pass


class EngagementManager:
    def __init__(self):
        self.engagements: dict[str, dict] = {}

    def create(self, *, engagement_id: str, scope: list[str], roe_signed: bool,
               principals: list[str], grants: set[str], tier: str = "lab") -> dict:
        if engagement_id in self.engagements:
            raise EngagementError(f"engagement {engagement_id!r} already exists")
        if not scope:
            raise EngagementError("an engagement requires a non-empty authorized scope")
        record = {
            "engagement_id": engagement_id,
            "scope": scope,
            "roe_signed": roe_signed,
            "principals": principals,
            "grants": sorted(grants),
            "tier": tier,
            "status": "active" if roe_signed else "red-locked",
        }
        self.engagements[engagement_id] = record
        return record

    def quickstart_lab(self) -> dict:
        """The 1-click lab engagement: loopback-only scope, lab RoE
        (the disposable lab target is ours — no third-party RoE needed),
        all lab tools granted. The UI asks YES/NO first."""
        return self.create(
            engagement_id=f"ENG-LAB-QUICK-{len(self.engagements) + 1}",
            scope=["127.0.0.1 (loopback lab target, ephemeral ports)"],
            roe_signed=True,
            principals=["agent:chimera-lab", "operator"],
            grants={"portscan-scoped", "http-probe", "tls-audit",
                    "header-audit", "content-discovery"},
            tier="lab",
        )

    def list(self) -> list[dict]:
        return [
            {**r, "grants": sorted(r["grants"])}
            for r in self.engagements.values()
        ]

    def verify_target(self, engagement_id: str, target: str) -> dict:
        """Scope is the ONLY source of targets — the manager answers
        whether a target is authorized for an engagement."""
        rec = self.engagements.get(engagement_id)
        if rec is None:
            return {"ok": False, "reason": f"unknown engagement {engagement_id!r}"}
        if rec["status"] != "active":
            return {"ok": False, "reason": f"engagement {engagement_id} is {rec['status']} — red tier locked"}
        if target not in rec["scope"]:
            return {"ok": False, "reason": f"target {target!r} outside authorized scope"}
        return {"ok": True}
