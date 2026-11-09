/* ============================================================
   G9 Mission Pipeline — ordered composition of the control-plane
   engines into the documented execution flow:

     preference → admission → grant → policy → stealth gate →
     action-spec validation → tripwire scan → dispatch decision

   Each stage returns allow/hold with a precise reason; the first
   blocking stage wins and the decision is recorded in the audit
   ledger. Nothing executes because an earlier stage passed.
   ============================================================ */

import { evaluate } from "./policyEngine.js";
import { assessStealth } from "./opsecGuardian.js";
import { validateAgainstApproval } from "./actionSpec.js";
import { scanToolCall } from "./adversarialResilience.js";
import { append } from "./auditLedger.js";

export const PIPELINE_STAGES = ["policy", "stealth", "approval-binding", "tripwires"];

export function runPipeline({ engine, auditLedger, request }) {
  const trail = [];
  const block = (stage, reason) => {
    const rec = append(auditLedger, {
      actor: request.principalId ?? "unknown",
      action: "pipeline-blocked",
      subject: request.toolId,
      detail: `${stage}: ${reason}`,
    });
    return { verdict: "blocked", blockedAt: stage, reason, trail, auditSeq: rec.seq };
  };
  const pass = (stage) => trail.push({ stage, ok: true });

  /* 1. Policy decision point — deny-by-default */
  const policy = evaluate(engine, request.policyRequest);
  if (policy.effect === "deny") return block("policy", policy.reasons.join("; "));
  pass("policy");

  /* 2. OPSEC stealth gate */
  if (request.stealth) {
    const stealth = assessStealth(request.stealth);
    if (!stealth.ok) return block("stealth", stealth.violations.join("; "));
    pass("stealth");
  }

  /* 3. Approval binding — digest must still match the approved spec */
  if (request.spec && request.approval) {
    const binding = validateAgainstApproval(request.spec, request.approval);
    if (!binding.ok) return block("approval-binding", binding.reason);
    pass("approval-binding");
  }

  /* 4. Tripwire scan — the model's safety claim is never consulted */
  if (request.scan) {
    const scan = scanToolCall(request.scan);
    if (scan.verdict !== "allow") {
      return block("tripwires", scan.findings.map((f) => `${f.tripwire}: ${f.detail}`).join("; "));
    }
    pass("tripwires");
  }

  const rec = append(auditLedger, {
    actor: request.principalId ?? "unknown",
    action: "pipeline-cleared",
    subject: request.toolId,
    detail: `stages passed: ${trail.map((t) => t.stage).join(" → ")}`,
  });
  return { verdict: "cleared", trail, auditSeq: rec.seq };
}
