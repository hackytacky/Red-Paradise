"""End-to-end tool invocation chain — the composition the whole
control plane exists for:

  MCP typed-contract validation
    → policy evaluation (deny-by-default)
    → budget/scope controller (tokens, rate, CIDR)
    → adapter dispatch (allowlists, spec-built argv)
    → hardened container command
    → optional real execution

Every stage blocks with a precise reason; nothing reaches the
container because an earlier stage passed.
"""

from __future__ import annotations

from ..mcp.contract import ContractError, validate_call
from ..ops.budget_controller import BudgetController, BudgetError
from ..policy.engine import PolicyEngine
from .container_runtime import ContainerCommand, execute

from ..tools.nmap_adapter import dispatch as dispatch_nmap
from ..tools.web_scanners import dispatch_httpx, dispatch_ffuf, dispatch_nuclei
from ..tools.recon_tools import dispatch_subfinder, dispatch_masscan, dispatch_testssl
from ..tools.osint_secret_tools import dispatch_theharvester, dispatch_gitleaks, dispatch_dig

ADAPTERS: dict = {
    "nmap-scoped": dispatch_nmap,
    "httpx": dispatch_httpx,
    "ffuf": dispatch_ffuf,
    "nuclei": dispatch_nuclei,
    "subfinder": dispatch_subfinder,
    "masscan": dispatch_masscan,
    "testssl": dispatch_testssl,
    "theharvester": dispatch_theharvester,
    "gitleaks": dispatch_gitleaks,
    "dig": dispatch_dig,
}


def register_adapter(tool_id: str, dispatch_fn) -> None:
    ADAPTERS[tool_id] = dispatch_fn


def invoke_tool(
    *,
    engine: PolicyEngine,
    budget: BudgetController,
    spec: dict,
    call: dict,
    execute_now: bool = False,
) -> dict:
    audit: list[dict] = []

    def blocked(stage: str, reason: str) -> dict:
        return {"ok": False, "blocked_at": stage, "reason": reason, "audit": audit}

    # 1. MCP typed contract — no raw shell strings, typed fields only
    try:
        r = validate_call(spec["tool_id"], call)
    except ContractError as e:
        return blocked("mcp-contract", str(e))
    audit.append({"stage": "mcp-contract", "ok": True, "family": r["family"]})

    # 2. Policy decision point
    decision = engine.evaluate({
        "engagement_id": spec["engagement_id"],
        "principal_id": spec["principal_id"],
        "tool_id": spec["tool_id"],
        "targets": spec["target_set"],
        "sandbox_class": spec.get("sandbox_profile"),
        "required_sandbox_class": "restricted-analysis",
    })
    if decision.effect == "deny":
        return blocked("policy", "; ".join(decision.reasons))
    audit.append({"stage": "policy", "ok": True})

    # 3. Budget & scope controller
    try:
        for target in spec["target_set"]:
            check = budget.check_target(target)
            if not check["ok"]:
                return blocked("scope", check["reason"])
        rate = budget.check_rate()
        if not rate["ok"]:
            return blocked("rate", rate["reason"])
        budget.charge_tokens(call.get("_token_estimate", 500))
    except BudgetError as e:
        return blocked("budget", str(e))
    audit.append({"stage": "budget-scope", "ok": True})

    # 4. Adapter dispatch (allowlists, spec-built argv)
    dispatch = ADAPTERS.get(spec["tool_id"])
    if dispatch is None:
        return blocked("adapter", f"no adapter implemented for {spec['tool_id']}")
    try:
        cmd: ContainerCommand = dispatch(spec)
    except Exception as e:  # adapter arg errors are precise by design
        return blocked("adapter", str(e))
    audit.append({"stage": "adapter", "ok": True})

    result: dict = {
        "ok": True,
        "command": cmd.shell(),
        "audit": audit,
        "executed": False,
    }

    # 5. Optional real execution — requires a Docker daemon; fails honestly
    if execute_now:
        run = execute(cmd)
        result["executed"] = True
        result["run"] = run
        result["ok"] = run["ok"]
        if not run["ok"]:
            result["reason"] = run["reason"] or run["stderr"][:200]
    return result
