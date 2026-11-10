"""g9-specialists (Stage 05): the nine specialist pipelines.

Each specialist declares its phase sequence over the admitted
arsenal. Two execution kinds:

  native    — lab-native adapters: REALLY executes here (lab plane)
  container — builds the hardened docker command through the
              invoke chain; executes on the G9 host with real tools

The doctrine is unchanged: every phase runs through policy → budget →
adapter → evidence → candidates only → verification. A specialist is
a mission shape, never a privilege.
"""

from __future__ import annotations

from ..core.action_spec import make_action_spec
from ..executor.invoke_chain import ADAPTERS
from ..lab.mission import LabMission

SPECIALISTS = {
    "recon": [
        ("portscan-scoped", "native"), ("http-probe", "native"),
        ("subfinder", "container"), ("sublist3r", "container"),
        ("dnstwist", "container"), ("hakrawler", "container"),
    ],
    "web-api": [
        ("http-probe", "native"), ("header-audit", "native"),
        ("content-discovery", "native"), ("ffuf", "container"),
        ("nuclei", "container"), ("wappalyzer-whatweb", "container"),
    ],
    "infra": [
        ("portscan-scoped", "native"), ("masscan", "container"),
        ("testssl", "container"), ("dig", "container"),
    ],
    "identity": [
        ("sherlock", "container"), ("maigret", "container"),
        ("holehe", "container"), ("ghunt", "container"),
    ],
    "reverse-engineering": [
        ("exiftool", "container"), ("hachoir", "container"),
    ],
    "vuln-research": [
        ("nuclei", "container"), ("nmap-scoped", "native"),
        ("http-probe", "native"),
    ],
    "emulation": [
        ("header-audit", "native"), ("http-probe", "native"),
    ],
    "defensive-validation": [
        ("header-audit", "native"), ("tls-audit", "native"),
        ("content-discovery", "native"),
    ],
    "ai-security": [
        ("promptfoo", "container"), ("garak", "container"),
    ],
}


class SpecialistError(ValueError):
    pass


def pipeline(name: str) -> list[dict]:
    if name not in SPECIALISTS:
        raise SpecialistError(f"unknown specialist {name!r} — have: {', '.join(SPECIALISTS)}")
    return [{"phase": i, "tool": t, "kind": k} for i, (t, k) in enumerate(SPECIALISTS[name])]


def run_specialist(name: str, *, mission: LabMission | None = None) -> dict:
    """Execute a specialist pipeline. Native phases REALLY run against
    the lab target; container phases build the hardened command (the
    host executes them with real tools). Everything through the gates."""
    steps = pipeline(name)
    own_mission = mission is None
    m = mission or LabMission()
    try:
        results = []
        native_tools = {"portscan-scoped", "http-probe", "header-audit",
                        "content-discovery", "tls-audit"}
        for step in steps:
            if step["kind"] == "native" and step["tool"] in native_tools:
                target = m.debug_target if step["tool"] == "portscan-scoped" else m.http_target
                r = m._invoke(step["tool"], target)
                results.append({"tool": step["tool"], "kind": "native", **r})
                continue
            # container phases: build the hardened command, no execution
            spec = make_action_spec({
                "action_id": f"ACT-SP-{name}-{step['phase']}", "engagement_id": m.engagement_id,
                "principal_id": "agent:chimera-lab", "agent_id": "chimera-lab",
                "tool_id": step["tool"], "tool_version": "1",
                "normalized_arguments": {},
                "target_set": [m.http_target], "working_directory": "/workspace/run",
                "environment_profile": "lab-plane", "sandbox_profile": "restricted-analysis",
                "network_policy_id": "netpol", "resource_budget": {"cpu": 1, "mem_gb": 1},
                "policy_revision": "ceder@v1",
            })
            dispatch = ADAPTERS.get(step["tool"])
            if dispatch is None:
                results.append({"tool": step["tool"], "kind": "container",
                                "ok": False, "reason": "no adapter implemented yet — honest boundary"})
                continue
            try:
                cmd = dispatch(spec)
                results.append({"tool": step["tool"], "kind": "container",
                                "ok": True, "command": cmd.shell(), "executed": False,
                                "note": "hardened command built — executes on the G9 host"})
            except Exception as e:
                results.append({"tool": step["tool"], "kind": "container", "ok": False, "reason": str(e)})
        report = m.verify_and_report([{"phase": name, "results": results}])
        report["specialist"] = name
        report["steps"] = [{"tool": r["tool"], "kind": r["kind"], "ok": r.get("ok", False)} for r in results]
        return report
    finally:
        if own_mission:
            m.close()


def catalog() -> dict:
    return {
        "specialists": {
            name: [{"tool": t, "kind": k} for t, k in phases]
            for name, phases in SPECIALISTS.items()
        },
        "doctrine": "every phase through policy → budget → adapter → evidence → candidates → verification",
    }
