"""g9-core: canonical action specification with SHA-256 digest-bound
approval. Mirrors src/lib/actionSpec.js with a production-grade digest.

The digest covers authorization-relevant content only: the approval
reference and the digest itself are excluded — the approval reference IS
the binding (audit finding T-5, never repeated here).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

ACTION_SPEC_FIELDS = [
    "action_id", "engagement_id", "principal_id", "agent_id",
    "tool_id", "tool_version", "normalized_arguments", "target_set",
    "working_directory", "environment_profile", "sandbox_profile",
    "network_policy_id", "resource_budget", "approval_id",
    "policy_revision", "spec_digest",
]

AUTH_RELEVANT_FIELDS = [
    "engagement_id", "principal_id", "agent_id", "tool_id",
    "tool_version", "normalized_arguments", "target_set",
    "working_directory", "environment_profile", "sandbox_profile",
    "network_policy_id", "resource_budget", "policy_revision",
]


def _canonicalize(value: Any) -> str:
    def sort(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: sort(v[k]) for k in sorted(v)}
        if isinstance(v, list):
            return [sort(x) for x in v]
        return v
    return json.dumps(sort(value), sort_keys=False, separators=(",", ":"))


def digest(spec: dict[str, Any]) -> str:
    content = {k: v for k, v in spec.items() if k not in ("spec_digest", "approval_id")}
    return hashlib.sha256(_canonicalize(content).encode()).hexdigest()


class ActionSpecError(ValueError):
    pass


@dataclass
class Approval:
    approval_id: str
    approved_by: str
    bound_digest: str
    bound_canon: str
    action_id: str
    at: str


def make_action_spec(data: dict[str, Any]) -> dict[str, Any]:
    for f in ACTION_SPEC_FIELDS:
        if f in ("spec_digest", "approval_id"):
            continue
        if data.get(f) is None:
            raise ActionSpecError(f"required field {f} is missing")
    if not isinstance(data.get("target_set"), list) or not data["target_set"]:
        raise ActionSpecError("target_set must be a non-empty list")
    if not isinstance(data.get("normalized_arguments"), dict):
        raise ActionSpecError("normalized_arguments must be an object")
    spec = dict(data)
    spec["approval_id"] = data.get("approval_id")
    spec["spec_digest"] = digest(spec)
    return spec


def bind_approval(spec: dict[str, Any], approval_id: str, approved_by: str) -> Approval:
    if not approval_id:
        raise ActionSpecError("approval_id is required")
    snapshot = {k: v for k, v in spec.items() if k != "spec_digest"}
    return Approval(
        approval_id=approval_id,
        approved_by=approved_by,
        bound_digest=spec["spec_digest"],
        bound_canon=_canonicalize(snapshot),
        action_id=spec["action_id"],
        at="",
    )


def validate_against_approval(spec: dict[str, Any], approval: Approval | None) -> tuple[bool, list[str], str]:
    if approval is None:
        return False, [], "no approval bound"
    current = digest(spec)
    if current != approval.bound_digest:
        bound = json.loads(approval.bound_canon) if approval.bound_canon else {}
        changed = [f for f in AUTH_RELEVANT_FIELDS if _canonicalize(spec.get(f)) != _canonicalize(bound.get(f))]
        reason = f"approval invalidated: action specification changed ({', '.join(changed)}) — re-approval required" if changed else "approval invalidated: action specification changed — re-approval required"
        return False, changed, reason
    return True, [], ""


def assert_targets_in_scope(spec: dict[str, Any], requested: list[str]) -> tuple[bool, str]:
    authorized = set(spec["target_set"])
    out = [t for t in requested if t not in authorized]
    if out:
        return False, f"out-of-scope targets requested: {', '.join(out)}"
    return True, ""
