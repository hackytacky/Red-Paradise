"""g9 ops: autonomy controller — HOW the platform executes, separate
from WHAT it may execute.

Three operating modes, one invariant: the policy engine, budget,
scope, and kill switch are load-bearing in ALL modes. Autonomy never
adds capability — it only changes who dispatches an action the gates
already cleared.

  manual       — nothing executes without an explicit operator
                 dispatch (approval-gated per action)
  hitl         — human-in-the-loop: low-impact actions auto-execute
                 within policy+budget; high-impact actions queue for
                 operator approval (approval state machine applies)
  autonomous   — everything policy allows auto-executes within
                 budget; the kill switch and CIDR scope still halt
                 everything, and only an operator resets them

Mode changes are operator actions, recorded in the ledger. An agent
cannot switch its own autonomy mode — that would be the model
granting itself permissions.
"""

from __future__ import annotations

MODES = ("manual", "hitl", "autonomous")


class AutonomyError(ValueError):
    pass


class AutonomyController:
    def __init__(self, mode: str = "hitl", engagement_id: str = ""):
        if mode not in MODES:
            raise AutonomyError(f"unknown mode {mode!r} — modes: {', '.join(MODES)}")
        self.mode = mode
        self.engagement_id = engagement_id
        self.pending: dict[str, dict] = {}
        self.decisions: list[dict] = []

    def set_mode(self, mode: str, actor: str) -> dict:
        """Only the operator changes the mode — agents never do."""
        if not actor.startswith("operator"):
            raise AutonomyError("autonomy mode changes are operator-only — agents cannot widen their own dispatch rights")
        if mode not in MODES:
            raise AutonomyError(f"unknown mode {mode!r}")
        self.mode = mode
        return {"ok": True, "mode": mode, "changed_by": actor}

    def decide(self, action: dict, policy_effect: str) -> str:
        """Return the execution verdict for one gated action.

        action: {action_id, high_impact, operator_dispatched?}
        policy_effect: 'allow' | 'deny' from the PolicyEngine.
        """
        if policy_effect == "deny":
            self.decisions.append({"action_id": action.get("action_id"), "verdict": "refuse", "mode": self.mode})
            return "refuse"
        if self.mode == "manual":
            if action.get("operator_dispatched"):
                verdict = "execute"
            else:
                self.pending[action["action_id"]] = action
                verdict = "await_approval"
        elif self.mode == "hitl":
            if action.get("high_impact") and not action.get("operator_dispatched"):
                self.pending[action["action_id"]] = action
                verdict = "await_approval"
            else:
                verdict = "execute"
        else:  # autonomous
            verdict = "execute"
        self.decisions.append({"action_id": action.get("action_id"), "verdict": verdict, "mode": self.mode})
        return verdict

    def approve(self, action_id: str, actor: str) -> dict:
        """Operator approves a queued action; it becomes dispatchable."""
        if not actor.startswith("operator"):
            raise AutonomyError("approvals are operator-only")
        action = self.pending.pop(action_id, None)
        if action is None:
            raise AutonomyError(f"no pending action {action_id!r}")
        return {"ok": True, "action_id": action_id, "verdict": "execute"}

    def deny(self, action_id: str, actor: str) -> dict:
        if not actor.startswith("operator"):
            raise AutonomyError("denials are operator-only")
        action = self.pending.pop(action_id, None)
        if action is None:
            raise AutonomyError(f"no pending action {action_id!r}")
        return {"ok": True, "action_id": action_id, "verdict": "refuse"}

    def status(self) -> dict:
        return {
            "mode": self.mode,
            "pending": sorted(self.pending),
            "decisions": len(self.decisions),
        }
