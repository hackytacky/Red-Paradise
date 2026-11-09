"""g9 Budget & Scope Controller — token budget, request rate, CIDR
scope, kill switch (the ops-framework requirement).

One controller per engagement. Every model call and every dispatched
request passes through it. The kill switch halts everything and
requires explicit operator reset.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field


class BudgetError(RuntimeError):
    pass


@dataclass
class BudgetController:
    engagement_id: str
    token_budget: int
    request_rate_per_min: int
    cidr_scopes: list[str]
    model: str = ""
    tokens_used: int = 0
    requests: list[float] = field(default_factory=list)
    killed: bool = False
    kill_reason: str = ""

    def _alive(self) -> None:
        if self.killed:
            raise BudgetError(f"engagement killed: {self.kill_reason} — operator reset required")

    def charge_tokens(self, n: int) -> dict:
        self._alive()
        if self.tokens_used + n > self.token_budget:
            self.kill(f"token budget exhausted ({self.tokens_used}/{self.token_budget})")
            raise BudgetError("token budget exhausted — engagement killed; operator reset required")
        self.tokens_used += n
        return {"ok": True, "used": self.tokens_used, "remaining": self.token_budget - self.tokens_used}

    def check_rate(self, at: float | None = None) -> dict:
        self._alive()
        now = at if at is not None else time.time()
        window = [t for t in self.requests if now - t < 60]
        if len(window) >= self.request_rate_per_min:
            return {"ok": False, "reason": f"rate limit: {len(window)} requests in the last 60s (cap {self.request_rate_per_min})"}
        self.requests = [*window, now]
        return {"ok": True}

    def check_target(self, target: str) -> dict:
        self._alive()
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            # hostname: must be explicitly enrolled in scope
            if target in self.cidr_scopes:
                return {"ok": True}
            return {"ok": False, "reason": f"hostname {target!r} not enrolled in scope"}
        for scope in self.cidr_scopes:
            try:
                if addr in ipaddress.ip_network(scope, strict=False):
                    return {"ok": True}
            except ValueError:
                continue
        return {"ok": False, "reason": f"address {target} outside CIDR scopes {self.cidr_scopes}"}

    def kill(self, reason: str) -> None:
        self.killed = True
        self.kill_reason = reason

    def operator_reset(self) -> None:
        """Only an operator resets a killed engagement — agents cannot."""
        self.killed = False
        self.kill_reason = ""
        self.tokens_used = 0
        self.requests = []
