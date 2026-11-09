import { describe, it, expect } from "vitest";
import {
  makeActionSpec, digest, canonicalize, bindApproval, validateAgainstApproval, assertTargetsInScope,
} from "../actionSpec.js";
import {
  makeExecution, transition, reconcile, canRetry, resetForRetry, EXEC_STATES,
} from "../approvalStateMachine.js";

const SPEC_INPUT = {
  action_id: "ACT-0001",
  engagement_id: "ENG-REDLAB-7",
  principal_id: "operator:hackytacky",
  agent_id: "hydra-web",
  tool_id: "nmap-scoped",
  tool_version: "7.95",
  normalized_arguments: { flags: "-sS -sV", ports: "1-1000", hosts: ["lab-api.g9.local"] },
  target_set: ["lab-api.g9.local", "lab-portal.g9.local"],
  working_directory: "/workspace/run",
  environment_profile: "lab-plane",
  sandbox_profile: "restricted-analysis",
  network_policy_id: "NETPOL-REDLAB",
  resource_budget: { cpu: 2, mem_gb: 4, minutes: 10 },
  policy_revision: "ceder@v3",
};

describe("ActionSpec", () => {
  it("creates a canonical spec with a digest", () => {
    const spec = makeActionSpec(SPEC_INPUT);
    expect(spec.spec_digest).toMatch(/^[0-9a-f]{32}$/);
  });

  it("rejects missing required fields and empty target sets", () => {
    expect(() => makeActionSpec({ ...SPEC_INPUT, tool_id: undefined })).toThrow(/tool_id/);
    expect(() => makeActionSpec({ ...SPEC_INPUT, target_set: [] })).toThrow(/target_set/);
  });

  it("digest is canonical: key order and whitespace do not matter", () => {
    const a = makeActionSpec(SPEC_INPUT);
    const reordered = {
      resource_budget: SPEC_INPUT.resource_budget, policy_revision: SPEC_INPUT.policy_revision,
      network_policy_id: SPEC_INPUT.network_policy_id, sandbox_profile: SPEC_INPUT.sandbox_profile,
      environment_profile: SPEC_INPUT.environment_profile, working_directory: SPEC_INPUT.working_directory,
      target_set: SPEC_INPUT.target_set, normalized_arguments: SPEC_INPUT.normalized_arguments,
      tool_version: SPEC_INPUT.tool_version, tool_id: SPEC_INPUT.tool_id,
      agent_id: SPEC_INPUT.agent_id, principal_id: SPEC_INPUT.principal_id,
      engagement_id: SPEC_INPUT.engagement_id, action_id: SPEC_INPUT.action_id,
      approval_id: null,
    };
    expect(digest(reordered)).toBe(a.spec_digest);
  });

  it("invalidates approval when any authorization-relevant field changes", () => {
    const spec = makeActionSpec(SPEC_INPUT);
    const approval = bindApproval(spec, { approvalId: "APR-1", approvedBy: "operator" });
    const tampered = { ...spec, normalized_arguments: { ...spec.normalized_arguments, ports: "1-65535" } };
    const r = validateAgainstApproval(tampered, approval);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/invalidated/);
  });

  it("rejects dispatch when no approval is bound", () => {
    const spec = makeActionSpec(SPEC_INPUT);
    expect(validateAgainstApproval(spec, null).ok).toBe(false);
  });

  it("enforces scope on resolved targets — the model's claim is never consulted", () => {
    const spec = makeActionSpec(SPEC_INPUT);
    const inScope = assertTargetsInScope(spec, { resolveTargets: (args) => args.hosts });
    expect(inScope.ok).toBe(true);
    const out = assertTargetsInScope(spec, { resolveTargets: () => ["lab-api.g9.local", "out-of-scope.host"] });
    expect(out.ok).toBe(false);
    expect(out.reason).toMatch(/out-of-scope/);
  });
});

describe("Approval / execution state machine", () => {
  const approvalFor = (spec) => bindApproval(spec, { approvalId: "APR-1", approvedBy: "operator" });

  const walkTo = (exec, spec, event) => {
    const approval = approvalFor(spec);
    const steps = ["schema_valid", "policy_evaluated", "approval_required", "approved", "pre_execution_validation", "dispatched", "running"];
    for (const s of steps) {
      const r = transition(exec, s, { approval });
      if (!r.ok) throw new Error(`walk failed at ${s}: ${r.reason}`);
    }
    return exec;
  };

  it("walks the happy path to EVIDENCE_PRESERVED", () => {
    const spec = makeActionSpec({ ...SPEC_INPUT, action_id: "ACT-HAPPY" });
    const exec = makeExecution({ actionId: spec.action_id, specDigest: spec.spec_digest, toolId: spec.tool_id });
    walkTo(exec, spec);
    transition(exec, "completed", { note: "tool exited 0" });
    const r = transition(exec, "evidence_preserved", { note: "artifacts hashed and stored" });
    expect(r.ok).toBe(true);
    expect(exec.state).toBe("EVIDENCE_PRESERVED");
    expect(EXEC_STATES).toContain(exec.state);
  });

  it("refuses invalid events from each state", () => {
    const spec = makeActionSpec({ ...SPEC_INPUT, action_id: "ACT-BAD" });
    const exec = makeExecution({ actionId: spec.action_id, specDigest: spec.spec_digest });
    expect(transition(exec, "running").ok).toBe(false);
    expect(exec.state).toBe("CREATED");
  });

  it("blocks dispatch when the approval digest does not match (tamper → INVALIDATED)", () => {
    const spec = makeActionSpec({ ...SPEC_INPUT, action_id: "ACT-TAMPER" });
    const exec = makeExecution({ actionId: spec.action_id, specDigest: spec.spec_digest });
    transition(exec, "schema_valid");
    transition(exec, "policy_evaluated");
    transition(exec, "approval_required");
    transition(exec, "approved");
    transition(exec, "pre_execution_validation");
    const wrongApproval = { approvalId: "APR-OTHER", boundDigest: "deadbeef".repeat(4), actionId: spec.action_id };
    const r = transition(exec, "dispatched", { approval: wrongApproval });
    expect(r.ok).toBe(false);
    expect(exec.state).toBe("INVALIDATED");
  });

  it("OUTCOME_UNKNOWN blocks replay until reconciliation", () => {
    const spec = makeActionSpec({ ...SPEC_INPUT, action_id: "ACT-UNK" });
    const exec = makeExecution({ actionId: spec.action_id, specDigest: spec.spec_digest });
    walkTo(exec, spec);
    transition(exec, "outcome_unknown", { note: "worker crash after possible side effect" });
    expect(exec.state).toBe("OUTCOME_UNKNOWN");
    expect(canRetry(exec).ok).toBe(false);
    expect(canRetry(exec).reason).toMatch(/reconcil/);
    expect(resetForRetry(exec).ok).toBe(false);
    const rec = reconcile(exec, { evidence: { pcap: "sha256:…", exit: "signal-9" }, sideEffectsOccurred: "unknown" });
    expect(rec.ok).toBe(true);
    expect(canRetry(exec).ok).toBe(true);
    const retry = resetForRetry(exec);
    expect(retry.ok).toBe(true);
    expect(exec.state).toBe("PRE_EXECUTION_VALIDATION");
  });

  it("reconciliation is only valid from OUTCOME_UNKNOWN", () => {
    const spec = makeActionSpec({ ...SPEC_INPUT, action_id: "ACT-REC" });
    const exec = makeExecution({ actionId: spec.action_id, specDigest: spec.spec_digest });
    const r = reconcile(exec, { evidence: {} });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/OUTCOME_UNKNOWN/);
  });

  it("FAILED may retry without reconciliation", () => {
    const spec = makeActionSpec({ ...SPEC_INPUT, action_id: "ACT-FAIL" });
    const exec = makeExecution({ actionId: spec.action_id, specDigest: spec.spec_digest });
    walkTo(exec, spec);
    transition(exec, "failed", { note: "tool error before any external action" });
    expect(canRetry(exec).ok).toBe(true);
    expect(resetForRetry(exec).ok).toBe(true);
  });
});
