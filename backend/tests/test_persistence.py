import json
import sqlite3

import pytest

from g9_backend.core.audit_ledger import AuditLedger
from g9_backend.evidence import EvidenceGraph, ResultCollector
from g9_backend.storage import (
    PersistenceError,
    SqliteEvidenceStore,
    SqliteLedgerStore,
    durable_graph,
    durable_ledger,
)


class TestLedgerPersistence:
    def test_write_through_and_reload(self, tmp_path):
        db = tmp_path / "g9.db"
        ledger = durable_ledger("ENG-1", SqliteLedgerStore(db))
        ledger.append("operator", "engagement.open", detail="RoE signed")
        ledger.append("agent:panoptes", "tool.invoke", subject="nmap-scoped")

        # "restart": a fresh ledger over the same store
        reloaded = durable_ledger("ENG-1", SqliteLedgerStore(db))
        assert len(reloaded.records) == 2
        assert reloaded.records[0].action == "engagement.open"
        ok, n, _ = reloaded.verify_chain()
        assert ok and n == 2

        # the chain CONTINUES across restarts — seq and prev persist
        rec = reloaded.append("operator", "engagement.note")
        assert rec.seq == 2 and rec.prev == reloaded.records[1].digest

    def test_in_memory_ledger_unchanged(self):
        ledger = AuditLedger("ENG-1")
        ledger.append("operator", "x")
        assert len(ledger.records) == 1
        ok, n, _ = ledger.verify_chain()
        assert ok and n == 1

    def test_tampered_store_refuses_to_load(self, tmp_path):
        db = tmp_path / "g9.db"
        store = SqliteLedgerStore(db)
        ledger = durable_ledger("ENG-1", store)
        ledger.append("operator", "engagement.open")

        # tamper with the persisted detail out-of-band
        conn = sqlite3.connect(db)
        conn.execute("UPDATE audit_records SET detail='falsified' WHERE seq=0")
        conn.commit()
        conn.close()

        with pytest.raises(PersistenceError, match="refusing to load a tampered ledger"):
            durable_ledger("ENG-1", SqliteLedgerStore(db))

    def test_deleted_record_refuses_to_load(self, tmp_path):
        db = tmp_path / "g9.db"
        store = SqliteLedgerStore(db)
        ledger = durable_ledger("ENG-1", store)
        for i in range(3):
            ledger.append("operator", f"event.{i}")

        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM audit_records WHERE seq=1")
        conn.commit()
        conn.close()

        with pytest.raises(PersistenceError, match="tampered ledger"):
            durable_ledger("ENG-1", SqliteLedgerStore(db))

    def test_engagements_are_isolated(self, tmp_path):
        db = tmp_path / "g9.db"
        store = SqliteLedgerStore(db)
        a = durable_ledger("ENG-A", store)
        b = durable_ledger("ENG-B", store)
        a.append("operator", "a.only")
        b.append("operator", "b.only")
        assert [r.action for r in durable_ledger("ENG-A", SqliteLedgerStore(db)).records] == ["a.only"]
        assert [r.action for r in durable_ledger("ENG-B", SqliteLedgerStore(db)).records] == ["b.only"]


class TestGraphPersistence:
    def test_graph_round_trip(self, tmp_path):
        db = tmp_path / "graph.db"
        store = SqliteEvidenceStore(db)
        g = durable_graph("REDLAB", store)
        g.add_node({"id": "F1", "klass": "finding", "label": "f1", "scope": "REDLAB",
                    "validation_status": "confirmed"})
        g.add_node({"id": "F2", "klass": "finding", "label": "f2", "scope": "REDLAB",
                    "validation_status": "reproduced"})
        g.add_edge("chains-to", "F1", "F2")

        reloaded = durable_graph("REDLAB", SqliteEvidenceStore(db))
        assert set(reloaded.nodes) == {"F1", "F2"}
        assert reloaded.edges == [{"type": "chains-to", "from": "F1", "to": "F2"}]
        # verified-link reasoning survives the restart
        assert reloaded.shortest_attack_path("F1", "F2") == ["F1", "F2"]
        # unverified candidates still never satisfy a path
        g.add_node({"id": "F3", "klass": "finding", "label": "f3", "scope": "REDLAB",
                    "validation_status": "candidate"})
        g.add_edge("chains-to", "F2", "F3")
        again = durable_graph("REDLAB", SqliteEvidenceStore(db))
        assert again.shortest_attack_path("F1", "F3") is None

    def test_scope_bleed_refused(self, tmp_path):
        db = tmp_path / "graph.db"
        store = SqliteEvidenceStore(db)
        g = durable_graph("REDLAB", store)
        g.add_node({"id": "F1", "klass": "finding", "label": "f1", "scope": "REDLAB"})

        # forge a node whose scope COLUMN claims REDLAB but whose JSON
        # payload is foreign — the loader must trust the payload, not the index
        conn = sqlite3.connect(db)
        conn.execute(
            "INSERT INTO evidence_nodes VALUES (?,?,?)",
            ("EVIL", "REDLAB", json.dumps({"id": "EVIL", "scope": "OTHER-SCOPE"})),
        )
        conn.commit()
        conn.close()
        with pytest.raises(PersistenceError, match="refused"):
            durable_graph("REDLAB", SqliteEvidenceStore(db))

    def test_collector_over_durable_graph(self, tmp_path):
        db = tmp_path / "graph.db"
        store = SqliteEvidenceStore(db)
        g = durable_graph("REDLAB", store)
        collector = ResultCollector(g)
        collector.ingest_tool_result(
            tool_id="nuclei", command="nuclei -target x",
            stdout='{"template-id": "cve-x", "host": "lab-api.g9.local"}',
            targets=["lab-api.g9.local"], exit_code=0,
        )
        reloaded = durable_graph("REDLAB", SqliteEvidenceStore(db))
        finding = [n for n in reloaded.nodes.values() if n["klass"] == "finding"]
        assert len(finding) == 1
        # candidates stay candidates across the restart — persistence
        # is never a promotion path to confirmed
        assert finding[0]["validation_status"] == "candidate"
