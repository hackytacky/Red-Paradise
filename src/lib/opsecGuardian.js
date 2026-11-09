/* ============================================================
   G9 OPSEC Guardian — stealth, privacy, anonymity, no-traces
   (HYPNOS agent engine; authorized engagements only)

   Doctrine (elite-standards + redteam-pentest methodology):
   - Stealth vs. speed is a decision, not a habit: loud validates
     detection (silence is a finding); stealth simulates a real
     adversary. Decided per phase, documented per chain link.
   - Assume the target is monitored: execute so the blue team could
     have caught the engagement.
   - Operator privacy/anonymity: no personal identifiers in any
     tool argument, artifact, or log; local models on red tier.
   - No traces after testing: EVERY artifact is recorded at
     creation in the artifact ledger; engagement close is BLOCKED
     until the cleanup manifest verifies every artifact removed,
     handed over, or explicitly retained per RoE.
   ============================================================ */

export const NOISE_CLASSES = {
  silent: { detectability: 0, desc: "passive/no packets on target" },
  low: { detectability: 1, desc: "scoped, slow, rate-limited activity inside normal traffic patterns" },
  medium: { detectability: 2, desc: "active scanning — should be visible to a competent blue team" },
  loud: { detectability: 3, desc: "high-volume/exploit-grade noise — detection expected; silence is a finding" },
};

/* Pre-action stealth assessment. Every chain step and pre-execution
   action passes through this BEFORE dispatch. */
export function assessStealth({ actionId, noiseClass, opsecPlan, phase, declaredNoise = null, containsPII = null, evidenceEncrypted = null }) {
  const cls = NOISE_CLASSES[noiseClass];
  if (!cls) return { ok: false, reason: `unknown noise class ${JSON.stringify(noiseClass)}` };

  const violations = [];

  /* The declared intent must match the plan: no silent drift to loud. */
  if (declaredNoise && NOISE_CLASSES[declaredNoise] && NOISE_CLASSES[declaredNoise].detectability > cls.detectability) {
    violations.push(`declared noise ${declaredNoise} exceeds plan class ${noiseClass} — re-plan or re-declare`);
  }
  if (opsecPlan && !opsecPlan.phases?.[phase]) {
    violations.push(`phase ${JSON.stringify(phase)} has no OPSEC plan entry — Phase 0 OPSEC plan incomplete`);
  }
  if (opsecPlan?.phases?.[phase] && opsecPlan.phases[phase].maxNoise && cls.detectability > opsecPlan.phases[phase].maxNoise) {
    violations.push(`noise class ${noiseClass} exceeds phase ${phase} max (${opsecPlan.phases[phase].maxNoise})`);
  }
  if (containsPII) {
    violations.push("operator/personal identifiers detected in action — anonymity violation");
  }
  if (evidenceEncrypted === false) {
    violations.push("evidence store not encrypted at rest — RoE evidence-handling violation");
  }

  return {
    ok: violations.length === 0,
    verdict: violations.length === 0 ? "proceed" : "hold",
    actionId, noiseClass, detectability: cls.detectability,
    violations,
    note: cls.detectability >= 2
      ? "active noise: the blue team should see this — if they do not, that is a headline finding"
      : "low/noise activity within plan",
  };
}

/* Anonymity: scan tool arguments and metadata for operator-identifying
   material. The operator's identity never enters target-facing
   traffic, artifacts, or logs. */
const PII_PATTERNS = [
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,           // email
  /\b(?:\+?\d[\d\s().-]{7,}\d)\b/,                                  // phone
  /\b(hackytacky|operator|admin|yourname|username)\b/i,            // personal handles (configurable list)
  /\b[A-Z][a-z]+ [A-Z][a-z]+\b/,                                   // full names (conservative)
];

export function scanForIdentifiers(payload) {
  const blob = typeof payload === "string" ? payload : JSON.stringify(payload ?? {});
  const hits = [];
  PII_PATTERNS.forEach((re, i) => {
    const m = blob.match(re);
    if (m) hits.push({ pattern: i, sample: m[0].slice(0, 24) });
  });
  return { clean: hits.length === 0, hits };
}

/* ---------------- No-traces artifact ledger ---------------- */

export function makeArtifactLedger({ engagementId, evidenceStore }) {
  if (!evidenceStore?.encrypted) throw new Error("OPSEC: evidence store must be encrypted at rest (RoE)");
  return { engagementId, evidenceStore, artifacts: new Map(), closed: false };
}

/* Record EVERY artifact at creation time — contemporaneous, not
   reconstructed. If it is not in the ledger, it should not exist. */
export function recordArtifact(ledger, { id, kind, location, detectability = "target-visible", data = null }) {
  if (ledger.closed) throw new Error("OPSEC: engagement closed — no new artifacts");
  if (ledger.artifacts.has(id)) throw new Error(`OPSEC: duplicate artifact ${id}`);
  ledger.artifacts.set(id, {
    id, kind, location, detectability, data,
    createdAt: new Date().toISOString(),
    state: "present", // present | removed | handed-over | retained-per-roe
    removedAt: null,
  });
  return ledger.artifacts.get(id);
}

export function markRemoved(ledger, { id, state = "removed", verifiedBy }) {
  const a = ledger.artifacts.get(id);
  if (!a) throw new Error(`OPSEC: unknown artifact ${id}`);
  if (!["removed", "handed-over", "retained-per-roe"].includes(state)) {
    throw new Error(`OPSEC: invalid cleanup state ${state}`);
  }
  if (state === "retained-per-roe" && !verifiedBy) {
    throw new Error("OPSEC: retention requires an explicit RoE citation and reviewer");
  }
  a.state = state;
  a.removedAt = new Date().toISOString();
  a.verifiedBy = verifiedBy ?? "cleanup-crew";
  return a;
}

/* Cleanup manifest + close gate: engagement close is BLOCKED while
   any artifact remains present. No traces after testing. */
export function cleanupManifest(ledger) {
  const all = [...ledger.artifacts.values()];
  const present = all.filter((a) => a.state === "present");
  return {
    engagementId: ledger.engagementId,
    total: all.length,
    cleaned: all.length - present.length,
    remaining: present.map((a) => ({ id: a.id, kind: a.kind, location: a.location, detectability: a.detectability })),
    evidenceDisposition: ledger.evidenceStore.disposition ?? "destroy-or-handover-per-contract",
    canClose: present.length === 0,
  };
}

export function closeEngagement(ledger) {
  const manifest = cleanupManifest(ledger);
  if (!manifest.canClose) {
    return {
      ok: false,
      reason: `no-traces gate: ${manifest.remaining.length} artifact(s) still present — ${manifest.remaining.map((a) => a.id).join(", ")}`,
      manifest,
    };
  }
  ledger.closed = true;
  return { ok: true, manifest };
}
