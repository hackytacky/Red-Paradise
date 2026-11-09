/* ============================================================
   G9 Research Loop — Mantis-style vulnerability research
   (the zero-day pipeline competitors lack: hypothesis → critique →
   reproduce → patch-diff, with escalation instead of invention)

   States: research → critique → hypothesis → reproduce → patch-diff
     → reported    (detours: escalated, abandoned)

   Hard rules:
   - Uncertain conclusions ESCALATE to specialists; the analyst never
     invents an answer.
   - A hypothesis only advances to reproduce with a PoC plan and
     preconditions recorded.
   - Patch-diff must show the fault stops AND functional tests still
     pass (CyberGym-E2E staged checks).
   - Zero-day discipline: no CVE claims for novel findings —
     evidence, gadget chains, PoV, disclosure notes only.
   ============================================================ */

export const RESEARCH_STATES = ["research", "critique", "hypothesis", "reproduce", "patch-diff", "reported"];
export const DETOURS = ["escalated", "abandoned"];

export function makeResearchTask({ id, title, target, technology, analyst }) {
  if (!id || !title || !target || !technology) {
    throw new Error("ResearchLoop: task requires id, title, target, technology");
  }
  return {
    id, title, target, technology, analyst,
    state: "research",
    notes: [], hypotheses: [], pocPlan: null,
    patchDiff: null, zeroDay: false, cveClaim: null,
    auditLog: [{ at: new Date().toISOString(), event: "created", to: "research" }],
  };
}

export function note(task, { source, content, confidence }) {
  if (confidence !== null && (typeof confidence !== "number" || confidence < 0 || confidence > 1)) {
    throw new Error("ResearchLoop: confidence must be null or in [0,1]");
  }
  task.notes.push({ source, content, confidence, at: new Date().toISOString() });
  return task;
}

/* Escalation instead of invention: low-confidence conclusions at the
   critique stage MUST escalate to a specialist — they never become
   hypotheses on their own. */
export function critique(task, { verdict, confidence, escalateTo = null }) {
  if (task.state !== "research" && task.state !== "critique") {
    return { ok: false, reason: `critique is not valid from ${task.state}` };
  }
  task.state = "critique";
  if (verdict === "no-plausible-path") {
    task.state = "abandoned";
    task.auditLog.push({ at: new Date().toISOString(), event: "critique", to: "abandoned", note: "no plausible weakness path" });
    return { ok: true, task };
  }
  if (confidence !== null && confidence < 0.5) {
    if (!escalateTo) {
      return { ok: false, reason: "low-confidence critique must escalate to a specialist — never invent an answer" };
    }
    task.state = "escalated";
    task.escalatedTo = escalateTo;
    task.auditLog.push({ at: new Date().toISOString(), event: "critique", to: "escalated", note: `escalated to ${escalateTo} (confidence ${confidence})` });
    return { ok: true, task };
  }
  task.auditLog.push({ at: new Date().toISOString(), event: "critique", to: "critique", note: `verdict: ${verdict}` });
  return { ok: true, task };
}

export function proposeHypothesis(task, { statement, precondition, pocPlan, zeroDay = false }) {
  if (task.state !== "critique") {
    return { ok: false, reason: `hypotheses are only proposed from critique (state: ${task.state})` };
  }
  if (!statement || !pocPlan) {
    return { ok: false, reason: "hypothesis requires a statement and a PoC plan — no 'probably vulnerable'" };
  }
  task.hypotheses.push({ statement, precondition: precondition ?? null, pocPlan });
  task.state = "hypothesis";
  task.zeroDay = zeroDay;
  task.pocPlan = pocPlan;
  task.auditLog.push({ at: new Date().toISOString(), event: "hypothesis", to: "hypothesis", note: statement });
  return { ok: true, task };
}

/* Reproduction requires a deterministic proof-of-vulnerability —
   the analyst's claim is never sufficient (same rule as the
   Verification Authority). */
export function reproduce(task, { povPassed, povArtifact }) {
  if (task.state !== "hypothesis") {
    return { ok: false, reason: `reproduction is only valid from hypothesis (state: ${task.state})` };
  }
  if (povPassed !== true || !povArtifact) {
    return { ok: false, reason: "reproduction requires a deterministic PoV artifact — agent claims are not proof" };
  }
  task.state = "reproduce";
  task.povArtifact = povArtifact;
  task.auditLog.push({ at: new Date().toISOString(), event: "reproduce", to: "reproduce", note: povArtifact });
  return { ok: true, task };
}

/* Patch-diff: the fault must stop AND functional tests must pass. */
export function patchDiff(task, { faultStops, functionalTestsPass, patchRef }) {
  if (task.state !== "reproduce") {
    return { ok: false, reason: `patch-diff is only valid from reproduce (state: ${task.state})` };
  }
  if (faultStops !== true) return { ok: false, reason: "patch-diff requires the fault to stop under the patch" };
  if (functionalTestsPass !== true) return { ok: false, reason: "patch-diff requires functional tests to still pass" };
  task.state = "patch-diff";
  task.patchDiff = patchRef;
  task.auditLog.push({ at: new Date().toISOString(), event: "patch-diff", to: "patch-diff", note: patchRef });
  return { ok: true, task };
}

/* Zero-day discipline: novel findings carry no CVE claims. */
export function report(task) {
  if (task.state !== "patch-diff") {
    return { ok: false, reason: `report is only valid from patch-diff (state: ${task.state})` };
  }
  if (task.zeroDay && task.cveClaim) {
    return { ok: false, reason: "zero-day discipline: novel findings carry no CVE claims — evidence, gadget chain, PoV, disclosure notes only" };
  }
  task.state = "reported";
  task.auditLog.push({ at: new Date().toISOString(), event: "report", to: "reported" });
  return { ok: true, task };
}
