# Persistence (Stage 04) — Durable Storage Behind the Existing Contracts

The audit ledger and the evidence graph keep their in-memory contracts
**unchanged**. A store is injected optionally and every mutation writes
through; with no store, behavior is exactly the scaffold that already
exists. Persistence is never allowed to change a decision boundary.

```
AuditLedger(engagement_id)  ──optional──▶  LedgerStore    (Postgres target)
EvidenceGraph(scope)        ──optional──▶  EvidenceStore  (Neo4j target)
```

## Reference implementation

`backend/g9_backend/storage/` ships SQLite (stdlib, WAL, single file per
engagement) as the reference store:

- `durable_ledger(engagement_id, store)` / `durable_graph(scope, store)`
  load-verify-wire: records load on construction, every `append` /
  `add_node` / `add_edge` writes through
- the ledger chain **continues across restarts** — seq numbers and
  prev-digests persist; a restart never resets tamper-evidence

## Fail-closed rules (test-proven in `tests/test_persistence.py`)

1. **A tampered store refuses to load.** If the persisted chain fails
   verification (out-of-band edit, deleted record), `durable_ledger`
   raises instead of starting fresh — tamper-evidence survives the
   restart; a tampered ledger is a finding, not a new beginning.
2. **Cross-engagement bleed refused.** A store row that surfaces under
   the wrong engagement, or an evidence node whose payload scope
   doesn't match the requested scope, is refused on load.
3. **Persistence is never a promotion path.** A candidate finding
   reloaded from the store is still a candidate — verified-link attack
   path reasoning behaves identically after a restart.
4. **No secrets in any store.** Stores carry decision metadata only;
   credential material is sealed in the identity vault, outside any
   store, by design.

## PostgreSQL / Neo4j deployment (host-side)

The `LedgerStore` / `EvidenceStore` interfaces are the seam. On the G9
host:

- **Postgres**: the ledger maps to an append-only table
  (`PRIMARY KEY (engagement_id, seq)`); `INSERT`-only permissions, no
  `UPDATE`/`DELETE` grants, so the only way to "edit history" is a
  detectable schema-level violation
- **Neo4j**: the graph is already property-graph shaped
  (`nodes` with `klass`/`validation_status`, typed `edges` with
  class-constrained endpoints); `chains-to` traversals become Cypher
  walks over confirmed/reproduced findings only

Both adapters satisfy the same contract the SQLite store proves in CI;
nothing in the control plane changes when they swap in.

## Honest boundary

SQLite is running in tests and is suitable for single-engagement
operation. Postgres/Neo4j adapters are not implemented in this
scaffold — the contract they must satisfy is implemented and tested;
the adapters are host-side Stage 04 work.
