"""g9-storage (Stage 04): durable persistence behind the existing
contracts.

The audit ledger and the evidence graph keep their in-memory
contracts unchanged; a store is injected optionally and every
mutation writes through. With no store the behavior is exactly the
scaffold you already have — nothing about persistence is allowed to
change a decision boundary.

Fail-closed rules (test-proven):

  - a ledger whose PERSISTED chain fails verification refuses to
    load — tamper-evidence survives the restart, it does not reset
    with a fresh process
  - a ledger only ever loads its OWN engagement's records; cross-
    engagement bleed is refused
  - the store carries decision metadata only — no secrets, no
    credential material (the identity vault seals secrets outside
    any store by design)

SQLite is the reference implementation (stdlib, zero host
dependencies, good enough for single-engagement work). The store
interface (`LedgerStore`, `EvidenceStore`) is the seam for the
PostgreSQL / Neo4j host deployments from the Stage 04 plan: the
graph store maps naturally to Neo4j (nodes/edges are already
property-graph shaped), the ledger to an append-only Postgres
table. Those adapters run on the G9 host; this module is the
contract they must satisfy.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..core.audit_ledger import AuditRecord, AuditLedger
from ..evidence.graph import EvidenceGraph


class LedgerStore:
    """Persistence seam for the audit ledger (Postgres target)."""

    def save(self, record: AuditRecord) -> None: ...
    def load(self, engagement_id: str) -> list[AuditRecord]: ...


class EvidenceStore:
    """Persistence seam for the evidence graph (Neo4j target)."""

    def save_node(self, node: dict) -> None: ...
    def save_edge(self, edge: dict) -> None: ...
    def load(self, scope: str) -> tuple[list[dict], list[dict]]: ...


class SqliteLedgerStore(LedgerStore):
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_records ("
            "seq INTEGER, engagement_id TEXT, actor TEXT, action TEXT,"
            "subject TEXT, detail TEXT, at TEXT, prev TEXT, digest TEXT,"
            "PRIMARY KEY (engagement_id, seq))"
        )
        self._conn.commit()

    def save(self, record: AuditRecord) -> None:
        self._conn.execute(
            "INSERT INTO audit_records VALUES (?,?,?,?,?,?,?,?,?)",
            (record.seq, record.engagement_id, record.actor, record.action,
             record.subject, record.detail, record.at, record.prev, record.digest),
        )
        self._conn.commit()

    def load(self, engagement_id: str) -> list[AuditRecord]:
        cur = self._conn.execute(
            "SELECT seq, engagement_id, actor, action, subject, detail, at, prev, digest "
            "FROM audit_records WHERE engagement_id = ? ORDER BY seq", (engagement_id,),
        )
        return [AuditRecord(*row) for row in cur.fetchall()]


class SqliteEvidenceStore(EvidenceStore):
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence_nodes (id TEXT PRIMARY KEY, scope TEXT, node TEXT)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence_edges ("
            "type TEXT, src TEXT, dst TEXT, PRIMARY KEY (type, src, dst))"
        )
        self._conn.commit()

    def save_node(self, node: dict) -> None:
        self._conn.execute(
            "INSERT INTO evidence_nodes VALUES (?,?,?)",
            (node["id"], node["scope"], json.dumps(node, sort_keys=True)),
        )
        self._conn.commit()

    def save_edge(self, edge: dict) -> None:
        self._conn.execute(
            "INSERT INTO evidence_edges VALUES (?,?,?)",
            (edge["type"], edge["from"], edge["to"]),
        )
        self._conn.commit()

    def load(self, scope: str) -> tuple[list[dict], list[dict]]:
        nodes = [
            json.loads(row[0])
            for row in self._conn.execute(
                "SELECT node FROM evidence_nodes WHERE scope = ?", (scope,),
            ).fetchall()
        ]
        edges = [
            {"type": t, "from": s, "to": d}
            for (t, s, d) in self._conn.execute("SELECT type, src, dst FROM evidence_edges").fetchall()
        ]
        return nodes, edges


class PersistenceError(RuntimeError):
    pass


def _attach_ledger(ledger: AuditLedger, store: LedgerStore) -> AuditLedger:
    """Load-and-wire a ledger against a store. The persisted chain
    must verify before the ledger will operate — a tampered store is
    a finding, not a fresh start."""
    records = store.load(ledger.engagement_id)
    for rec in records:
        if rec.engagement_id != ledger.engagement_id:
            raise PersistenceError(
                f"store returned record for engagement {rec.engagement_id!r} "
                f"under {ledger.engagement_id!r} — cross-engagement bleed refused"
            )
    ledger.records = records
    ok, seq, reason = ledger.verify_chain()
    if not ok:
        raise PersistenceError(
            f"persisted audit chain fails verification at record {seq}: {reason} — "
            "refusing to load a tampered ledger"
        )
    original_append = ledger.append

    def append(actor: str, action: str, subject: str | None = None, detail: str = "", at: str = "") -> AuditRecord:
        rec = original_append(actor, action, subject, detail, at)
        store.save(rec)
        return rec

    ledger.append = append  # type: ignore[method-assign]
    return ledger


def durable_ledger(engagement_id: str, store: LedgerStore) -> AuditLedger:
    return _attach_ledger(AuditLedger(engagement_id), store)


def durable_graph(scope: str, store: EvidenceStore) -> EvidenceGraph:
    """Load-and-wire an evidence graph against a store."""
    graph = EvidenceGraph(scope)
    nodes, edges = store.load(scope)
    for node in nodes:
        if node.get("scope") != scope:
            raise PersistenceError(
                f"store returned node scoped {node.get('scope')!r} under {scope!r} — refused"
            )
        graph.nodes[node["id"]] = node
    for edge in edges:
        if edge["from"] in graph.nodes and edge["to"] in graph.nodes:
            graph.edges.append(edge)
    original_add_node = graph.add_node
    original_add_edge = graph.add_edge

    def add_node(node: dict) -> dict:
        rec = original_add_node(node)
        store.save_node(rec)
        return rec

    def add_edge(etype: str, from_id: str, to_id: str) -> dict:
        rec = original_add_edge(etype, from_id, to_id)
        store.save_edge(rec)
        return rec

    graph.add_node = add_node  # type: ignore[method-assign]
    graph.add_edge = add_edge  # type: ignore[method-assign]
    return graph
