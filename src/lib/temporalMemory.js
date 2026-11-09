/* ============================================================
   G9 Temporal Memory (docs/architecture/g9-spectre-v3.md §8)

   Security facts change over time: endpoints disappear, credentials
   rotate, vulnerabilities get patched, attack paths become invalid.

   Acceptance requirement: expired or superseded facts must not
   silently reappear as current security findings. Temporal memory
   improves recall but must never become an authorization source.
   ============================================================ */

export function makeTemporalStore() {
  return { facts: new Map() };
}

/*
  record: {
    id, statement, kind (asset|observation|finding|attack-path|credential),
    firstObserved, validFrom, validUntil (nullable), lastVerified,
    evidenceRefs, confidence, validationStatus, engagementScope
  }
*/
export function record(store, fact) {
  for (const f of ["id", "statement", "kind", "engagementScope"]) {
    if (!fact[f]) throw new Error(`TemporalMemory: fact requires ${f}`);
  }
  if (store.facts.has(fact.id)) throw new Error(`TemporalMemory: duplicate fact id ${fact.id}`);
  const now = new Date().toISOString();
  store.facts.set(fact.id, {
    firstObserved: fact.firstObserved ?? now,
    validFrom: fact.validFrom ?? now,
    validUntil: fact.validUntil ?? null,
    lastVerified: fact.lastVerified ?? now,
    evidenceRefs: fact.evidenceRefs ?? [],
    confidence: fact.confidence ?? null,
    validationStatus: fact.validationStatus ?? "unvalidated",
    supersededBy: null,
    ...fact,
  });
  return store.facts.get(fact.id);
}

export function supersede(store, { oldId, newId, at = null }) {
  const old = store.facts.get(oldId);
  if (!old) throw new Error(`TemporalMemory: no fact ${oldId}`);
  old.supersededBy = newId;
  old.validUntil = at ?? new Date().toISOString();
  return old;
}

export function verify(store, { id, at = null }) {
  const f = store.facts.get(id);
  if (!f) throw new Error(`TemporalMemory: no fact ${id}`);
  f.lastVerified = at ?? new Date().toISOString();
  return f;
}

/* Is this fact current right now (or at a given instant)?
   A fact is current only if:
   - its validity window covers the instant, AND
   - it has not been superseded, AND
   - it has not expired (validUntil passed). */
export function isCurrent(fact, at = null) {
  const now = at ?? new Date().toISOString();
  if (fact.supersededBy) return false;
  if (fact.validFrom > now) return false;
  if (fact.validUntil && fact.validUntil <= now) return false;
  return true;
}

/* Query current facts only. Expired/superseded facts are never
   returned as current findings — the acceptance requirement. */
export function queryCurrent(store, { kind = null, engagementScope = null } = {}, at = null) {
  return [...store.facts.values()].filter(
    (f) => isCurrent(f, at) &&
      (kind === null || f.kind === kind) &&
      (engagementScope === null || f.engagementScope === engagementScope)
  );
}

/* Explicitly retrieve history (for investigation context) —
   clearly labeled as historical, never as current. */
export function queryHistory(store, { kind = null } = {}) {
  return [...store.facts.values()]
    .filter((f) => kind === null || f.kind === kind)
    .map((f) => ({ ...f, historical: !isCurrent(f) }));
}

/* Authorization guard: temporal memory is NOT an authorization
   source. Any attempt to use it as one is rejected. */
export function authorize(_store, _request) {
  return { ok: false, reason: "temporal memory is not an authorization source — use the policy decision point" };
}
