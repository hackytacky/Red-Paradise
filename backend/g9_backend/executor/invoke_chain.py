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
from ..tools.gowitness_amass_dnsrecon import dispatch_gowitness, dispatch_amass, dispatch_dnsrecon
from ..tools.feed_adapters import dispatch_shodan, dispatch_censys, dispatch_abusech, dispatch_otx, dispatch_intelx
from ..tools.wave4_adapters import (
    dispatch_owasp_zap, dispatch_caido, dispatch_grype_syft, dispatch_trivy,
    dispatch_ldapsearch, dispatch_windapsearch, dispatch_bloodhound,
    dispatch_sharphound, dispatch_azurehound, dispatch_pyrit,
)
from ..tools.wave3_adapters import (
    dispatch_sherlock, dispatch_maigret, dispatch_holehe, dispatch_ghunt, dispatch_trufflehog,
    dispatch_gobuster, dispatch_feroxbuster, dispatch_sublist3r, dispatch_whatweb,
    dispatch_exiftool, dispatch_hachoir, dispatch_dnstwist, dispatch_hakrawler,
    dispatch_promptfoo, dispatch_garak,
)

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
    "gowitness": dispatch_gowitness,
    "amass": dispatch_amass,
    "dnsrecon": dispatch_dnsrecon,
    "shodan": dispatch_shodan,
    "censys": dispatch_censys,
    "abusech": dispatch_abusech,
    "otx": dispatch_otx,
    "intelx": dispatch_intelx,
    "sherlock": dispatch_sherlock, "maigret": dispatch_maigret,
    "holehe": dispatch_holehe, "ghunt": dispatch_ghunt, "trufflehog": dispatch_trufflehog,
    "gobuster": dispatch_gobuster, "feroxbuster": dispatch_feroxbuster,
    "sublist3r": dispatch_sublist3r, "wappalyzer-whatweb": dispatch_whatweb,
    "exiftool": dispatch_exiftool, "hachoir": dispatch_hachoir,
    "dnstwist": dispatch_dnstwist, "hakrawler": dispatch_hakrawler,
    "promptfoo": dispatch_promptfoo, "garak": dispatch_garak,
    "owasp-zap": dispatch_owasp_zap, "caido": dispatch_caido,
    "grype-syft": dispatch_grype_syft, "trivy": dispatch_trivy,
    "ldapsearch": dispatch_ldapsearch, "windapsearch": dispatch_windapsearch,
    "bloodhound": dispatch_bloodhound, "sharphound": dispatch_sharphound,
    "azurehound": dispatch_azurehound, "pyrit": dispatch_pyrit,
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
    collector=None,
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
        result["run"] = {"ok": run["ok"], "exit_code": run["exit_code"], "reason": run["reason"]}
        result["ok"] = run["ok"]
        if not run["ok"]:
            result["reason"] = run["reason"] or run["stderr"][:200]
        # result collector: raw output becomes provenance-tagged evidence;
        # parsed findings enter as candidates only
        if collector is not None:
            rec = collector.ingest_tool_result(
                tool_id=spec["tool_id"], command=cmd.shell(),
                stdout=run.get("stdout", ""), stderr=run.get("stderr", ""),
                targets=spec["target_set"], exit_code=run.get("exit_code"),
            )
            result["evidence"] = rec
    return result
