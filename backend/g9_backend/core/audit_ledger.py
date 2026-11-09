"""g9-core: hash-chained (SHA-256) tamper-evident audit ledger.
Mirrors src/lib/auditLedger.js."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict


def _digest(rec: dict) -> str:
    return hashlib.sha256(json.dumps(rec, sort_keys=False, separators=(",", ":")).encode()).hexdigest()


@dataclass
class AuditRecord:
    seq: int
    engagement_id: str
    actor: str
    action: str
    subject: str | None
    detail: str
    at: str
    prev: str | None
    digest: str = ""


class AuditLedger:
    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id
        self.records: list[AuditRecord] = []

    def append(self, actor: str, action: str, subject: str | None = None, detail: str = "", at: str = "") -> AuditRecord:
        if not actor or not action:
            raise ValueError("actor and action are required")
        prev = self.records[-1].digest if self.records else None
        rec = AuditRecord(
            seq=len(self.records), engagement_id=self.engagement_id,
            actor=actor, action=action, subject=subject, detail=detail,
            at=at, prev=prev, digest="",
        )
        d = asdict(rec)
        d.pop("digest")
        rec.digest = _digest(d)
        self.records.append(rec)
        return rec

    def verify_chain(self) -> tuple[bool, int | None, str]:
        prev = None
        for rec in self.records:
            if rec.prev != prev:
                return False, rec.seq, f"sequence break at record {rec.seq}: prev-digest mismatch (insertion or deletion)"
            d = asdict(rec)
            d.pop("digest")
            if _digest(d) != rec.digest:
                return False, rec.seq, f"content tampering detected at record {rec.seq}"
            prev = rec.digest
        return True, len(self.records), ""

    def query(self, actor: str | None = None, action: str | None = None) -> tuple[bool, str, list[AuditRecord]]:
        ok, _, reason = self.verify_chain()
        if not ok:
            return False, reason, []
        return True, "", [
            r for r in self.records
            if (actor is None or r.actor == actor) and (action is None or r.action == action)
        ]
