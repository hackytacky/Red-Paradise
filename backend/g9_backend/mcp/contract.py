"""g9 MCP Tool-Family Contract — typed interfaces per tool family.

The single highest-leverage decision (operator requirement): wrap
each tool family in a typed MCP interface instead of letting the LLM
compose shell strings. This module defines the family descriptors
and enforces that:

- every admitted tool maps to exactly one family with a typed
  input schema
- agent calls carry structured fields only — raw shell strings are
  rejected at the contract boundary
- the adapter layer (allowlists, spec-built argv) is the only place
  command lines are ever constructed
"""

from __future__ import annotations

from ..tools.registry_data import all_entries

TOOL_FAMILIES: dict[str, dict] = {
    "network-recon": {"schema": {"targets": "list[str]", "ports": "str?", "flags": "list[str]? (allowlisted)"}, "adapters": ["nmap-scoped", "masscan"]},
    "passive-recon": {"schema": {"domains": "list[str]", "sources": "list[str]?"}, "adapters": ["subfinder", "sublist3r", "amass"]},
    "web-probe": {"schema": {"targets": "list[str]", "flags": "list[str]? (allowlisted)"}, "adapters": ["httpx", "wappalyzer-whatweb"]},
    "content-discovery": {"schema": {"target": "str", "wordlist": "str (admission-qualified asset)", "flags": "list[str]?"}, "adapters": ["ffuf", "gobuster", "feroxbuster"]},
    "template-scan": {"schema": {"targets": "list[str]", "severity": "str?", "tags": "list[str]?"}, "adapters": ["nuclei"]},
    "tls-audit": {"schema": {"target": "str"}, "adapters": ["testssl"]},
    "osint-username": {"schema": {"usernames": "list[str]", "platforms": "list[str]?"}, "adapters": ["sherlock", "maigret"]},
    "osint-email": {"schema": {"emails": "list[str]"}, "adapters": ["holehe", "ghunt"]},
    "identity-recon": {"schema": {"collector": "str", "targets": "list[str]"}, "adapters": ["bloodhound", "sharphound", "azurehound"]},
    "directory-query": {"schema": {"server": "str", "filter": "str (read-only)"}, "adapters": ["ldapsearch", "windapsearch"]},
    "sbom-scan": {"schema": {"image_or_dir": "str"}, "adapters": ["grype-syft", "trivy"]},
    "dast": {"schema": {"target": "str", "profile": "str"}, "adapters": ["owasp-zap", "burp-suite-pro", "caido"]},
    "osint-harvest": {"schema": {"domain": "str", "sources": "list[str]"}, "adapters": ["theharvester"]},
    "dns-query": {"schema": {"domains": "list[str]", "record": "str?"}, "adapters": ["dig"]},
    "secret-scanning": {"schema": {"repos": "list[str]", "orgs": "list[str]?"}, "adapters": ["gitleaks", "trufflehog"]},
    "ai-red-team": {"schema": {"target_id": "str", "corpus": "str", "control_version": "str"}, "adapters": ["promptfoo", "garak", "pyrit"]},
}


class ContractError(ValueError):
    pass


def family_for_tool(tool_id: str) -> str | None:
    for family, desc in TOOL_FAMILIES.items():
        if tool_id in desc["adapters"]:
            return family
    return None


def validate_call(tool_id: str, call: dict) -> dict:
    """Validate an agent's tool call against the family contract.
    Raw shell strings are rejected here — the boundary the LLM
    never crosses."""
    family = family_for_tool(tool_id)
    if family is None:
        raise ContractError(f"tool {tool_id!r} has no typed family contract — not callable by agents")
    if "command" in call or "shell" in call or "argv" in call:
        raise ContractError("raw shell strings are rejected at the contract boundary — agents pass typed fields only")
    schema = TOOL_FAMILIES[family]["schema"]
    for required in [k for k, v in schema.items() if "?" not in v]:
        if required not in call:
            raise ContractError(f"{family}: missing required field {required!r}")
    return {"ok": True, "family": family, "tool": tool_id}


def coverage_report() -> dict:
    """Which registry tools have family contracts (typed MCP) and
    which are pending contracts."""
    contracted: set[str] = set()
    for desc in TOOL_FAMILIES.values():
        contracted.update(desc["adapters"])
    registry_ids = {e[0] for e in all_entries()}
    return {
        "families": len(TOOL_FAMILIES),
        "contracted_tools": sorted(contracted & registry_ids),
        "pending_contracts": sorted(registry_ids - contracted),
    }
