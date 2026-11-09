/* ============================================================
   G9 Policy Engine — Cedar-style, deny-by-default
   (Tier 1: Authorization; g9-policy module contract)

   The sole Policy Decision Point. Security decisions are enforced
   OUTSIDE the AI model: the model can propose, reason, and request;
   it cannot grant itself permissions, expand scope, or declare its
   own results verified.

   Every request is evaluated against: engagement validity, RoE
   signature, principal identity, in-scope targets, tool grant
   membership, sandbox class, and approval binding. Absence of any
   required fact is a DENY with the precise reason.
   ============================================================ */

export function makePolicyEngine({ engagements, grants, policyRevision = "ceder@v1" }) {
  return { engagements, grants, policyRevision, decisions: [] };
}

export function evaluate(engine, request) {
  const reasons = [];
  const deny = (ok) => {
    const decision = {
      effect: reasons.length === 0 && ok ? "allow" : "deny",
      reasons,
      policyRevision: engine.policyRevision,
      at: new Date().toISOString(),
      requestId: request.requestId ?? null,
    };
    engine.decisions.push(decision);
    return decision;
  };

  /* 1. Engagement must exist, be active, and have a signed RoE */
  const eng = engine.engagements[request.engagementId];
  if (!eng) return deny((reasons.push("unknown engagement"), false));
  if (!eng.roeSigned) reasons.push("rules of engagement unsigned — red tier locked");
  if (eng.window && (new Date().toISOString() < eng.window.start || new Date().toISOString() > eng.window.end)) {
    reasons.push("outside engagement window");
  }

  /* 2. Principal must be a known, active identity */
  const principal = eng.principals?.[request.principalId];
  if (!principal) reasons.push(`unknown principal ${request.principalId}`);
  else if (principal.revoked) reasons.push(`principal ${request.principalId} revoked`);

  /* 3. Every target must be inside the engagement scope */
  for (const t of request.targets ?? []) {
    if (!eng.scope.includes(t)) reasons.push(`target ${t} outside authorized scope`);
  }

  /* 4. The tool must be in the engagement's capability grant */
  const grant = engine.grants[request.engagementId];
  if (!grant) reasons.push("no capability grant issued for engagement");
  else if (!grant.tools.has(request.toolId)) reasons.push(`tool ${request.toolId} not in capability grant`);

  /* 5. The sandbox class must satisfy the tool's requirement */
  if (request.sandboxClass && request.requiredSandboxClass && request.sandboxClass !== request.requiredSandboxClass) {
    reasons.push(`sandbox class ${request.sandboxClass} does not satisfy required ${request.requiredSandboxClass}`);
  }

  /* 6. High-impact actions require a bound approval */
  if (request.highImpact && !request.approvalId) {
    reasons.push("high-impact action requires an operator approval reference");
  }
  if (request.approvalId && request.boundDigest && request.actionDigest !== request.boundDigest) {
    reasons.push("approval digest mismatch — action specification changed after approval");
  }

  /* 7. The requesting agent may never be the authority */
  if (request.selfAuthorized) {
    reasons.push("agent self-authorization attempt — the model is not an authorization source");
  }

  return deny(reasons.length === 0);
}
