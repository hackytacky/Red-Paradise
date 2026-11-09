import { describe, it, expect } from "vitest";
import { makeFinding, advance, submitReproduction, FINDING_STATES } from "../verificationAuthority.js";

const base = { id: "F-0100", title: "test finding", scope: "10.10.0.0/24", vector: "web", target: "lab-api.g9.local" };

describe("VerificationAuthority", () => {
  it("registers findings as hypotheses with an audit log", () => {
    const f = makeFinding(base);
    expect(f.state).toBe("hypothesis");
    expect(f.auditLog.length).toBe(1);
  });

  it("lets an agent submit a hypothesis to candidate", () => {
    const f = makeFinding(base);
    const r = advance(f, { role: "agent", evidence: ["agent-submission"] });
    expect(r.ok).toBe(true);
    expect(f.state).toBe("candidate");
  });

  it("rejects missing evidence requirements", () => {
    const f = makeFinding(base);
    advance(f, { role: "agent", evidence: ["agent-submission"] });
    const r = advance(f, { role: "verifier", evidence: ["reproduction-artifact"] });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/independent-verification/);
    expect(f.state).toBe("candidate");
  });

  it("never lets a model promote its own finding", () => {
    const f = makeFinding(base);
    advance(f, { role: "agent", evidence: ["agent-submission"] });
    const r = advance(f, {
      role: "agent",
      evidence: ["reproduction-artifact", "independent-verification"],
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/verifier role/);
    expect(f.state).toBe("candidate");
  });

  it("promotes only with verifier role and full evidence", () => {
    const f = makeFinding(base);
    advance(f, { role: "agent", evidence: ["agent-submission"] });
    const r = submitReproduction(f, { role: "verifier", reproductionArtifact: "pov-response.svc", postConditionPassed: true });
    expect(r.ok).toBe(true);
    expect(f.state).toBe("reproduced");
    const r2 = advance(f, { role: "verifier", evidence: ["adjudication", "independent-evidence"] });
    expect(r2.ok).toBe(true);
    expect(f.state).toBe("confirmed");
  });

  it("refuses promotion when the deterministic post-condition fails", () => {
    const f = makeFinding(base);
    advance(f, { role: "agent", evidence: ["agent-submission"] });
    const r = submitReproduction(f, { role: "verifier", reproductionArtifact: "pov", postConditionPassed: false });
    expect(r.ok).toBe(false);
    expect(f.state).toBe("candidate");
  });

  it("walks the full ladder to regression-verified with auditability", () => {
    const f = makeFinding(base);
    advance(f, { role: "agent", evidence: ["agent-submission"] });
    submitReproduction(f, { role: "verifier", reproductionArtifact: "pov", postConditionPassed: true });
    advance(f, { role: "verifier", evidence: ["adjudication", "independent-evidence"] });
    advance(f, { role: "verifier", evidence: ["remediation-evidence"] });
    advance(f, { role: "verifier", evidence: ["regression-test-passed"] });
    expect(f.state).toBe("regression-verified");
    expect(f.auditLog.map((l) => l.to)).toEqual(FINDING_STATES);
    // terminal state
    const r = advance(f, { role: "verifier", evidence: ["anything"] });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/terminal/);
  });
});
