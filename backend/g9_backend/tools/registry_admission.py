"""Arsenal admission gate — enforces the per-entry governance flags
before a registry candidate can be qualified and granted.

The operator's approval puts every entry into admission-REVIEW; the
flags below are the additional recorded proofs required to reach
qualified. Nothing is admitted by approval alone.
"""

from __future__ import annotations

from .registry_data import (
    C, K, S, LEGAL_GATE, LICENSE_REQUIRED, SEPARATE_AUTH, LAB_ONLY, UNVERIFIED,
    all_entries, by_id,
)

REQUIRED_PROOFS = {
    SEPARATE_AUTH: "separate_roe_addendum",
    LICENSE_REQUIRED: "valid_license_on_record",
    LEGAL_GATE: "legal_review_on_record",
    LAB_ONLY: "lab_enclave_attested",
}


class AdmissionError(ValueError):
    pass


def validate_registry() -> list[dict]:
    """Structural validation of every registry entry."""
    seen: set[str] = set()
    entries = []
    for (rid, name, category, sandbox, access, flags, note) in all_entries():
        if rid in seen:
            raise AdmissionError(f"duplicate registry id {rid}")
        seen.add(rid)
        if sandbox not in (C, K, S):
            raise AdmissionError(f"{rid}: unknown sandbox class {sandbox!r}")
        if not category:
            raise AdmissionError(f"{rid}: missing category")
        entries.append({
            "id": rid, "name": name, "category": category, "sandbox": sandbox,
            "access": access, "flags": flags, "note": note,
        })
    return entries


def required_proofs(rid: str) -> list[str]:
    entry = by_id(rid)
    if entry is None:
        raise AdmissionError(f"unknown registry id {rid}")
    return [REQUIRED_PROOFS[f] for f in entry[5] if f in REQUIRED_PROOFS]


def admit(rid: str, proofs: dict) -> dict:
    """Qualify a registry entry. Every flagged proof must be present
    and truthy; UNVERIFIED entries can never be admitted this way —
    they require an explicit manual-review override record."""
    entry = by_id(rid)
    if entry is None:
        raise AdmissionError(f"unknown registry id {rid}")
    flags = entry[5]
    if UNVERIFIED in flags and not proofs.get("manual_review_override"):
        return {
            "ok": False,
            "reason": f"{rid} is UNVERIFIED — not admitted without a recorded manual safety review; excluded from automated pipelines",
        }
    missing = [REQUIRED_PROOFS[f] for f in flags if f in REQUIRED_PROOFS and not proofs.get(REQUIRED_PROOFS[f])]
    if missing:
        return {"ok": False, "reason": f"{rid}: missing required proofs: {', '.join(missing)}"}
    return {"ok": True, "result": "qualified", "id": rid, "sandbox": entry[3], "category": entry[2]}


def summary() -> dict:
    entries = validate_registry()
    counts: dict[str, int] = {}
    flag_counts: dict[str, int] = {}
    for e in entries:
        counts[e["sandbox"]] = counts.get(e["sandbox"], 0) + 1
        for f in e["flags"]:
            flag_counts[f] = flag_counts.get(f, 0) + 1
    return {
        "total": len(entries),
        "by_sandbox": counts,
        "by_flag": flag_counts,
        "never_admitted_automatically": [e["id"] for e in entries if UNVERIFIED in e["flags"]],
    }
