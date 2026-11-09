/* ============================================================
   G9 Trusted Execution — Approval / Execution State Machine
   (g9-tasks / g9-executor contract, docs/architecture/
   g9-spectre-v3.md §10)

   CREATED → SCHEMA_VALIDATED → POLICY_EVALUATED → AWAITING_APPROVAL
     → APPROVED → PRE_EXECUTION_VALIDATION → DISPATCHED → RUNNING
     → COMPLETED → EVIDENCE_PRESERVED

   Terminal/detour states: DENIED, REJECTED, INVALIDATED,
   CANCELLED, FAILED, OUTCOME_UNKNOWN.

   Hard rules:
   - OUTCOME_UNKNOWN is essential: a worker may crash after
     performing an external action but before the broker records
     its result. Such actions are NEVER automatically replayed;
     reconciliation of execution evidence is required first.
   - A dispatch requires an approval still bound to the exact
     action digest (pre-execution validation).
   ============================================================ */

export const EXEC_STATES = [
  "CREATED", "SCHEMA_VALIDATED", "POLICY_EVALUATED", "AWAITING_APPROVAL",
  "APPROVED", "PRE_EXECUTION_VALIDATION", "DISPATCHED", "RUNNING",
  "COMPLETED", "EVIDENCE_PRESERVED",
  "DENIED", "REJECTED", "INVALIDATED", "CANCELLED", "FAILED", "OUTCOME_UNKNOWN",
];

export const EXEC_TRANSITIONS = {
  CREATED: { schema_valid: "SCHEMA_VALIDATED" },
  SCHEMA_VALIDATED: { policy_evaluated: "POLICY_EVALUATED" },
  POLICY_EVALUATED: { denied: "DENIED", approval_required: "AWAITING_APPROVAL" },
  AWAITING_APPROVAL: { approved: "APPROVED", rejected: "REJECTED" },
  APPROVED: { pre_execution_validation: "PRE_EXECUTION_VALIDATION" },
  PRE_EXECUTION_VALIDATION: { invalidated: "INVALIDATED", dispatched: "DISPATCHED" },
  DISPATCHED: { running: "RUNNING" },
  RUNNING: { completed: "COMPLETED", cancelled: "CANCELLED", failed: "FAILED", outcome_unknown: "OUTCOME_UNKNOWN" },
  COMPLETED: { evidence_preserved: "EVIDENCE_PRESERVED" },
};

/* States that permit re-dispatch without reconciliation */
export const RETRYABLE_WITHOUT_RECONCILIATION = new Set(["FAILED", "CANCELLED"]);

export function makeExecution({ actionId, specDigest, toolId }) {
  if (!actionId || !specDigest) throw new Error("Execution: actionId and specDigest are required");
  return {
    actionId, specDigest, toolId: toolId ?? null,
    state: "CREATED",
    attempts: 0,
    reconciled: false,
    auditLog: [{ at: new Date().toISOString(), event: "created", to: "CREATED", note: "" }],
  };
}

export function transition(exec, event, { note = "", approval = null, reconciliationEvidence = null } = {}) {
  const allowed = EXEC_TRANSITIONS[exec.state];
  if (!allowed || !(event in allowed)) {
    return { ok: false, reason: `event ${JSON.stringify(event)} is not valid from state ${exec.state}`, exec };
  }
  let target = allowed[event];

  /* Pre-execution validation: dispatch requires an approval still
     bound to the exact action digest. */
  if (event === "dispatched") {
    if (!approval || approval.boundDigest !== exec.specDigest) {
      target = "INVALIDATED";
      exec.auditLog.push({ at: new Date().toISOString(), event: "invalidated", to: target, note: "approval digest mismatch or missing — dispatch refused" });
      exec.state = target;
      return { ok: false, reason: "pre-execution validation failed: approval not bound to this action digest", exec };
    }
  }

  /* OUTCOME_UNKNOWN: an external side effect may have occurred.
     Never auto-replay; require reconciliation evidence before any
     retry is permitted. */
  if (event === "outcome_unknown") {
    exec.reconciled = false;
    exec.auditLog.push({
      at: new Date().toISOString(), event, to: target,
      note: "worker lost after possible external side effect — replay blocked pending reconciliation",
    });
    exec.state = target;
    return { ok: true, exec };
  }

  if (event === "failed" || event === "cancelled") {
    exec.attempts += 1;
  }

  exec.auditLog.push({ at: new Date().toISOString(), event, to: target, note });
  exec.state = target;
  return { ok: true, exec };
}

/* Reconciliation gate: only after OUTCOME_UNKNOWN has been
   reconciled with execution evidence may a retry be requested.
   Reconciliation records what side effects actually occurred. */
export function reconcile(exec, { evidence, sideEffectsOccurred = null }) {
  if (exec.state !== "OUTCOME_UNKNOWN") {
    return { ok: false, reason: `reconciliation is only valid from OUTCOME_UNKNOWN (state: ${exec.state})`, exec };
  }
  if (!evidence || typeof evidence !== "object") {
    return { ok: false, reason: "reconciliation requires execution evidence", exec };
  }
  exec.reconciled = true;
  exec.reconciliation = { evidence, sideEffectsOccurred, at: new Date().toISOString() };
  exec.auditLog.push({ at: new Date().toISOString(), event: "reconciled", to: exec.state, note: "execution evidence recorded; retry permitted" });
  return { ok: true, exec };
}

/* Retry policy: FAILED/CANCELLED may retry directly; OUTCOME_UNKNOWN
   may retry ONLY after reconciliation. */
export function canRetry(exec) {
  if (RETRYABLE_WITHOUT_RECONCILIATION.has(exec.state)) return { ok: true };
  if (exec.state === "OUTCOME_UNKNOWN") {
    return exec.reconciled
      ? { ok: true }
      : { ok: false, reason: "OUTCOME_UNKNOWN cannot be replayed until execution evidence is reconciled — automatic replay is prohibited" };
  }
  return { ok: false, reason: `state ${exec.state} is not retryable` };
}

export function resetForRetry(exec) {
  const r = canRetry(exec);
  if (!r.ok) return r;
  exec.state = "PRE_EXECUTION_VALIDATION";
  exec.attempts += 1;
  exec.auditLog.push({ at: new Date().toISOString(), event: "retry", to: exec.state, note: "re-entering pre-execution validation" });
  return { ok: true, exec };
}
