import { describe, it, expect } from "vitest";
import {
  makeAuditLedger, append, verifyChain, query,
} from "../auditLedger.js";
import { makePolicyEngine, evaluate } from "../policyEngine.js";
import { runPipeline, PIPELINE_STAGES } from "../missionPipeline.js";
import {
  makeActionSpec, bindApproval, validateAgainstApproval,
} from "../actionSpec.js";
import { scanToolCall, makeCanarySet } from "../adversarialResilience.js";

describe("Audit Ledger (tamper-evident)", () => {
  it("chains records: each carries the previous digest", () => {
    const l = makeAuditLedger({ engagementId: "ENG-1" });
    const a = append(l, { actor: "agent:hydra-web", action: "dispatch", subject: "nmap-scoped" });
    const b = append(l, { actor: "cerberus", action: "evidence-preserved", subject: "F-0001" });
    expect(a.prev).toBe(null);
    expect(b.prev).toBe(a.digest);
    expect(l.records.length).toBe(2);
  });

  it("verifies a clean chain", () => {
    const l = makeAuditLedger({ engagementId: "ENG-1" });
    for (let i = 0; i < 5; i++) append(l, { actor: "x", action: `a${i}` });
    const v = verifyChain(l);
    expect(v.ok).toBe(true);
    expect(v.length).toBe(5);
  });

  it("detects content tampering at the exact record", () => {
    const l = makeAuditLedger({ engagementId: "ENG-1" });
    append(l, { actor: "a", action: "one" });
    append(l, { actor: "b", action: "two" });
    append(l, { actor: "c", action: "three" });
    l.records[1].action = "TAMPERED";
    const v = verifyChain(l);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBe(1);
    expect(v.reason).toMatch(/tampering/);
  });

  it("detects deletion (sequence break)", () => {
    const l = makeAuditLedger({ engagementId: "ENG-1" });
    append(l, { actor: "a", action: "one" });
    append(l, { actor: "b", action: "two" });
    append(l, { actor: "c", action: "three" });
    l.records.splice(1, 1);
    const v = verifyChain(l);
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/sequence break/);
  });

  it("refuses to serve history from a tampered ledger", () => {
    const l = makeAuditLedger({ engagementId: "ENG-1" });
    append(l, { actor: "a", action: "one" });
    append(l, { actor: "a", action: "two" });
    l.records[0].detail = "rewritten";
    const q = query(l, { actor: "a" });
    expect(q.ok).toBe(false);
    expect(q.reason).toMatch(/tampering/);
    expect(q.records).toEqual([]);
  });

  it("requires actor and action", () => {
    const l = makeAuditLedger({ engagementId: "ENG-1" });
    expect(() => append(l, { action: "x" })).toThrow(/actor/);
  });
});

describe("Mission Pipeline (composition)", () => {
  const canaries = makeCanarySet({ tokens: ["CANARY-X"], tools: ["send_admin_email"] });
  const grant = new Set(["nmap-scoped"]);

  const build = () => {
    const audit = makeAuditLedger({ engagementId: "ENG-1" });
    const engine = makePolicyEngine({
      policyRevision: "ceder@v1",
      engagements: {
        "ENG-1": {
          scope: ["lab-api.g9.local"],
          roeSigned: true,
          principals: { "agent:hydra-svc": { revoked: false } },
        },
      },
      grants: { "ENG-1": { tools: grant, issuedAt: "now" } },
    });
    return { audit, engine };
  };

  const SPEC = makeActionSpec({
    action_id: "ACT-P1", engagement_id: "ENG-1", principal_id: "agent:hydra-svc",
    agent_id: "hydra-svc", tool_id: "nmap-scoped", tool_version: "7.95",
    normalized_arguments: { flags: "-sS", hosts: ["lab-api.g9.local"] },
    target_set: ["lab-api.g9.local"], working_directory: "/run",
    environment_profile: "lab-plane", sandbox_profile: "restricted-analysis",
    network_policy_id: "NETPOL-1", resource_budget: { cpu: 1 },
    policy_revision: "ceder@v1",
  });
  const APPROVAL = bindApproval(SPEC, { approvalId: "APR-P1", approvedBy: "operator" });

  const REQUEST = (over = {}) => ({
    principalId: "agent:hydra-svc", toolId: "nmap-scoped",
    policyRequest: {
      engagementId: "ENG-1", principalId: "agent:hydra-svc", toolId: "nmap-scoped",
      targets: ["lab-api.g9.local"],
    },
    stealth: { actionId: "ACT-P1", noiseClass: "low", opsecPlan: { phases: { recon: { maxNoise: 1 } } }, phase: "recon", evidenceEncrypted: true },
    spec: SPEC, approval: APPROVAL,
    scan: { agentId: "hydra-svc", toolId: "nmap-scoped", arguments: { flags: "-sS", hosts: ["lab-api.g9.local"] }, canaries, scopeHosts: ["lab-api.g9.local"], urlExpected: true, approvedTools: grant, approvalId: "APR-P1" },
    ...over,
  });

  it("clears a fully valid request through all four stages", () => {
    const { audit, engine } = build();
    const r = runPipeline({ engine, auditLedger: audit, request: REQUEST() });
    expect(r.verdict).toBe("cleared");
    expect(r.trail.map((t) => t.stage)).toEqual(PIPELINE_STAGES);
    expect(verifyChain(audit).ok).toBe(true);
  });

  it("blocks at the policy stage with precise reasons", () => {
    const { audit, engine } = build();
    const r = runPipeline({ engine, auditLedger: audit, request: REQUEST({ policyRequest: { engagementId: "ENG-1", principalId: "agent:hydra-svc", toolId: "nmap-scoped", targets: ["out-of-scope.host"] } }) });
    expect(r.verdict).toBe("blocked");
    expect(r.blockedAt).toBe("policy");
    expect(r.reason).toMatch(/outside authorized scope/);
  });

  it("blocks at the stealth gate when the phase ceiling is exceeded", () => {
    const { audit, engine } = build();
    const r = runPipeline({ engine, auditLedger: audit, request: REQUEST({ stealth: { actionId: "ACT-P1", noiseClass: "loud", opsecPlan: { phases: { recon: { maxNoise: 1 } } }, phase: "recon", evidenceEncrypted: true } }) });
    expect(r.blockedAt).toBe("stealth");
    expect(r.reason).toMatch(/exceeds phase recon max/);
  });

  it("blocks at approval-binding when the spec was tampered", () => {
    const { audit, engine } = build();
    const tampered = { ...SPEC, normalized_arguments: { flags: "-sS -T5", hosts: ["lab-api.g9.local"] } };
    const r = runPipeline({ engine, auditLedger: audit, request: REQUEST({ spec: tampered }) });
    expect(r.blockedAt).toBe("approval-binding");
    expect(r.reason).toMatch(/normalized_arguments/);
  });

  it("blocks at tripwires when a canary is touched", () => {
    const { audit, engine } = build();
    const r = runPipeline({ engine, auditLedger: audit, request: REQUEST({ scan: { agentId: "hydra-svc", toolId: "nmap-scoped", arguments: { url: "http://lab-api.g9.local/CANARY-X" }, canaries, scopeHosts: ["lab-api.g9.local"], urlExpected: true, approvedTools: grant, approvalId: "APR-P1" } }) });
    expect(r.blockedAt).toBe("tripwires");
    expect(r.reason).toMatch(/canary_token/);
  });

  it("records every decision in the tamper-evident ledger", () => {
    const { audit, engine } = build();
    runPipeline({ engine, auditLedger: audit, request: REQUEST() });
    runPipeline({ engine, auditLedger: audit, request: REQUEST({ policyRequest: { engagementId: "ENG-1", principalId: "agent:hydra-svc", toolId: "nmap-scoped", targets: ["bad.host"] } }) });
    const q = query(audit, {});
    expect(q.ok).toBe(true);
    expect(q.records.map((r) => r.action)).toEqual(["pipeline-cleared", "pipeline-blocked"]);
  });

  it("changed-field reporting works after the boundCanon fix", () => {
    const spec = makeActionSpec({ ...SPEC, action_id: "ACT-P2" });
    const approval = bindApproval(spec, { approvalId: "APR-P2", approvedBy: "operator" });
    const tampered = { ...spec, target_set: ["other.host"] };
    const r = validateAgainstApproval(tampered, approval);
    expect(r.ok).toBe(false);
    expect(r.changed).toEqual(["target_set"]);
  });
});

describe("Resilience host-array scope check (audit A-1)", () => {
  const canaries = makeCanarySet({ tokens: [], tools: [] });
  const grant = new Set(["nmap-scoped"]);

  it("flags out-of-scope hosts named directly in arguments (no URL needed)", () => {
    const r = scanToolCall({ agentId: "a", toolId: "nmap-scoped", arguments: { hosts: ["lab-api.g9.local", "evil-internal.host"] }, canaries, scopeHosts: ["lab-api.g9.local"], approvedTools: grant, approvalId: "APR" });
    expect(r.findings.some((f) => f.tripwire === "out_of_scope_host")).toBe(true);
    expect(r.verdict).toBe("block");
  });

  it("allows in-scope host arrays", () => {
    const r = scanToolCall({ agentId: "a", toolId: "nmap-scoped", arguments: { hosts: ["lab-api.g9.local"] }, canaries, scopeHosts: ["lab-api.g9.local"], approvedTools: grant, approvalId: "APR" });
    expect(r.verdict).toBe("allow");
  });
});
