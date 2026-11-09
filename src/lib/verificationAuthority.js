/* ============================================================
   G9 Verification Authority — explicit finding-state machine.

   States:
     hypothesis → candidate → reproduced → confirmed →
     remediated → regression-verified

   Hard rules (docs/architecture/custom-capabilities.md):
   - The primary testing agent's own success statement is NEVER
     sufficient proof: transitions out of `candidate` require
     independent evidence (verifier-issued), not agent claims.
   - Models cannot promote their own findings to confirmed status:
     only a caller with the `verifier` role can advance states that
     increase claim strength.
   - Every transition is attributable and auditable (append-only log).
   ============================================================ */

export const FINDING_STATES = ["hypothesis", "candidate", "reproduced", "confirmed", "remediated", "regression-verified"];

export const TRANSITIONS = {
  hypothesis: { target: "candidate", requires: ["agent-submission"], role: "agent" },
  candidate: { target: "reproduced", requires: ["reproduction-artifact", "independent-verification"], role: "verifier" },
  reproduced: { target: "confirmed", requires: ["adjudication", "independent-evidence"], role: "verifier" },
  confirmed: { target: "remediated", requires: ["remediation-evidence"], role: "verifier" },
  remediated: { target: "regression-verified", requires: ["regression-test-passed"], role: "verifier" },
};

export const ROLES = ["agent", "verifier"];

export function makeFinding({ id, title, scope, vector, target, evidence = [], remediation = null, verification = null }) {
  if (!id || !title || !scope) throw new Error("VerificationAuthority: finding requires id, title, scope");
  return {
    id, title, scope, vector: vector ?? null, target: target ?? null,
    state: "hypothesis",
    evidence: [...evidence],
    remediation, verification,
    auditLog: [{ at: new Date().toISOString(), role: "agent", from: null, to: "hypothesis", note: "finding registered" }],
  };
}

export function advance(finding, { role, evidence = [], note = "" }) {
  const t = TRANSITIONS[finding.state];
  if (!t) {
    return { ok: false, reason: `finding ${finding.id} is terminal (${finding.state})`, finding };
  }
  if (t.role === "verifier" && role !== "verifier") {
    return {
      ok: false,
      reason: `models cannot promote their own findings: transition ${finding.state} → ${t.target} requires the verifier role`,
      finding,
    };
  }
  const have = new Set(evidence);
  const missing = t.requires.filter((r) => !have.has(r));
  if (missing.length > 0) {
    return {
      ok: false,
      reason: `missing evidence requirements: ${missing.join(", ")} (required: ${t.requires.join(", ")})`,
      finding,
    };
  }
  const from = finding.state;
  finding.state = t.target;
  finding.evidence.push(...evidence.map((kind) => ({ kind, at: new Date().toISOString() })));
  finding.auditLog.push({ at: new Date().toISOString(), role, from, to: t.target, note });
  return { ok: true, finding };
}

/* Deterministic post-condition check result is the only acceptable
   `independent-verification` artifact; an agent's own success
   statement maps to `agent-claim` and is rejected for promotion. */
export function submitReproduction(finding, { role, reproductionArtifact, postConditionPassed, note = "" }) {
  if (postConditionPassed !== true) {
    return { ok: false, reason: "post-condition check did not pass — no promotion", finding };
  }
  return advance(finding, {
    role: role === "verifier" ? "verifier" : "agent",
    evidence: ["reproduction-artifact", "independent-verification"],
    note: note || `deterministic post-condition passed: ${reproductionArtifact}`,
  });
}
