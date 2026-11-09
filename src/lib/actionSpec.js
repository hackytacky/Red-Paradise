/* ============================================================
   G9 Trusted Execution — Canonical Action Specification
   (g9-approval / g9-executor contract, docs/architecture/
   g9-spectre-v3.md §10)

   Rules:
   - An agent-generated command is never executed solely because
     it conforms to the expected JSON schema.
   - The specification is canonicalized and approval is bound to
     its digest.
   - Any change to authorization-relevant fields invalidates the
     approval.
   ============================================================ */

export const ACTION_SPEC_FIELDS = [
  "action_id", "engagement_id", "principal_id", "agent_id",
  "tool_id", "tool_version", "normalized_arguments", "target_set",
  "working_directory", "environment_profile", "sandbox_profile",
  "network_policy_id", "resource_budget", "approval_id",
  "policy_revision", "spec_digest",
];

/* Authorization-relevant fields: changing any of these after
   approval MUST invalidate the approval. */
export const AUTH_RELEVANT_FIELDS = [
  "engagement_id", "principal_id", "agent_id", "tool_id",
  "tool_version", "normalized_arguments", "target_set",
  "working_directory", "environment_profile", "sandbox_profile",
  "network_policy_id", "resource_budget", "policy_revision",
];

/* Deterministic canonicalization: lexicographic key order, no
   whitespace. Production uses SHA-256; this portable digest is a
   stand-in with identical collision-avoidance intent for the demo
   control plane. */
export function canonicalize(spec) {
  const sortValue = (v) => {
    if (Array.isArray(v)) return v.map(sortValue);
    if (v && typeof v === "object") {
      return Object.keys(v).sort().reduce((acc, k) => { acc[k] = sortValue(v[k]); return acc; }, {});
    }
    return v;
  };
  return JSON.stringify(sortValue(spec));
}

export function digest(spec) {
  const canonical = canonicalize(spec);
  /* FNV-1a 64-bit-style double pass, hex-encoded */
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < canonical.length; i++) {
    const c = canonical.charCodeAt(i);
    h1 = (h1 ^ c) >>> 0; h1 = (h1 * 0x01000193) >>> 0;
    h2 = (h2 ^ ((c << 3) & 0xff)) >>> 0; h2 = (h2 * 0x85ebca6b) >>> 0;
  }
  return (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0")).repeat(2);
}

export function makeActionSpec(input) {
  for (const f of ACTION_SPEC_FIELDS) {
    if (f === "spec_digest" || f === "approval_id") continue;
    if (input[f] === undefined || input[f] === null) {
      throw new Error(`ActionSpec: required field ${f} is missing`);
    }
  }
  if (!Array.isArray(input.target_set) || input.target_set.length === 0) {
    throw new Error("ActionSpec: target_set must be a non-empty array of authorized targets");
  }
  if (!input.normalized_arguments || typeof input.normalized_arguments !== "object") {
    throw new Error("ActionSpec: normalized_arguments must be an object");
  }
  const spec = { ...input, approval_id: input.approval_id ?? null };
  spec.spec_digest = digest(spec);
  return spec;
}

/* Bind an approval to the exact spec digest. */
export function bindApproval(spec, { approvalId, approvedBy, at = null }) {
  if (!approvalId) throw new Error("bindApproval: approvalId is required");
  return {
    approvalId,
    approvedBy,
    at: at ?? new Date().toISOString(),
    boundDigest: spec.spec_digest,
    actionId: spec.action_id,
  };
}

/* Pre-execution validation: the spec's current digest must equal
   the digest the approval was bound to. Any authorization-relevant
   change invalidates the approval. */
export function validateAgainstApproval(spec, approval) {
  if (!approval) return { ok: false, reason: "no approval bound" };
  const current = digest({ ...spec, approval_id: approval.approvalId });
  if (current !== approval.boundDigest) {
    const changed = AUTH_RELEVANT_FIELDS.filter(
      (f) => canonicalize(spec[f]) !== canonicalize(JSON.parse(approval.boundCanon ?? "{}")[f] ?? spec[f])
    );
    return {
      ok: false,
      reason: `approval invalidated: action specification changed${changed.length ? ` (${changed.join(", ")})` : ""} — re-approval required`,
    };
  }
  return { ok: true };
}

/* Scope check: every concrete target in the arguments must fall
   inside the authorized target_set. The model's claim about scope
   is never consulted. */
export function assertTargetsInScope(spec, { resolveTargets }) {
  const requested = resolveTargets(spec.normalized_arguments);
  const authorized = new Set(spec.target_set);
  const out = requested.filter((t) => !authorized.has(t));
  if (out.length > 0) {
    return { ok: false, reason: `out-of-scope targets requested: ${out.join(", ")}`, out };
  }
  return { ok: true };
}
