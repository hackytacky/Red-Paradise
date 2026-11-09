/* ============================================================
   G9 Audit Ledger — tamper-evident activity records
   (g9-audit module contract: "tamper-evident activity records;
   detectable record modification")

   Append-only, hash-chained: every record carries the digest of
   the previous record and a digest of itself. Any mutation,
   deletion, or insertion breaks the chain at an exact record —
   a compromised agent cannot rewrite history undetected.
   ============================================================ */

export function digestRecord(rec) {
  const canonical = JSON.stringify(rec);
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  for (let i = 0; i < canonical.length; i++) {
    const c = canonical.charCodeAt(i);
    h1 = (h1 ^ c) >>> 0; h1 = (h1 * 0x01000193) >>> 0;
    h2 = (h2 ^ ((c << 3) & 0xff)) >>> 0; h2 = (h2 * 0x85ebca6b) >>> 0;
  }
  return (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0")).repeat(2);
}

export function makeAuditLedger({ engagementId }) {
  return { engagementId, records: [] };
}

export function append(ledger, { actor, action, subject, detail = "", at = null }) {
  if (!actor || !action) throw new Error("AuditLedger: actor and action are required");
  const prev = ledger.records.length > 0 ? ledger.records[ledger.records.length - 1].digest : null;
  const rec = {
    seq: ledger.records.length,
    engagementId: ledger.engagementId,
    actor, action, subject: subject ?? null, detail,
    at: at ?? new Date().toISOString(),
    prev,
  };
  rec.digest = digestRecord(rec);
  ledger.records.push(rec);
  return rec;
}

/* Verify the whole chain. Returns ok plus the exact broken record. */
export function verifyChain(ledger) {
  let prev = null;
  for (const rec of ledger.records) {
    const { digest, ...rest } = rec;
    if (rec.prev !== prev) {
      return { ok: false, brokenAt: rec.seq, reason: `sequence break at record ${rec.seq}: prev-digest mismatch (insertion or deletion)` };
    }
    if (digestRecord(rest) !== digest) {
      return { ok: false, brokenAt: rec.seq, reason: `content tampering detected at record ${rec.seq}` };
    }
    prev = digest;
  }
  return { ok: true, length: ledger.records.length };
}

/* Query with integrity assertion: refuses to serve history from a
   ledger whose chain does not verify. */
export function query(ledger, { actor = null, action = null } = {}) {
  const integrity = verifyChain(ledger);
  if (!integrity.ok) {
    return { ok: false, reason: integrity.reason, records: [] };
  }
  return {
    ok: true,
    records: ledger.records.filter(
      (r) => (actor === null || r.actor === actor) && (action === null || r.action === action)
    ),
  };
}
