import { describe, it, expect } from "vitest";
import {
  makeRegistry, registerTool, admissionReview, qualifiedTools, issueGrant, recommendForTask, TOOL_STATES,
} from "../toolRegistry.js";
import { makePolicyEngine, evaluate } from "../policyEngine.js";

const NMAP = {
  id: "nmap-scoped", name: "nmap (scoped profile)", source: "https://github.com/nmap/nmap",
  license: "GPL-2.0", protocols: ["tcp", "udp"], capabilityClass: "network-recon",
  sandboxClass: "restricted-analysis",
};
const BLOODHOUND = {
  id: "bloodhound-ce", name: "BloodHound Community Edition", source: "https://github.com/SpecterOps/BloodHound",
  license: "Apache-2.0", protocols: ["http"], capabilityClass: "identity-analysis",
  sandboxClass: "restricted-analysis",
};
const CUSTOM = {
  id: "custom-fuzzer", name: "any-tool-from-github", source: "https://github.com/example/fuzzer",
  license: "AGPL-3.0", protocols: ["tcp", "dns"], capabilityClass: "fuzzing",
  sandboxClass: "hostile-research-vm",
};

function qualifiedRegistry() {
  const r = makeRegistry();
  registerTool(r, NMAP);
  registerTool(r, BLOODHOUND);
  registerTool(r, CUSTOM);
  admissionReview(r, { toolId: "nmap-scoped", decision: "qualified", revision: "7.95", reviewedBy: "operator" });
  admissionReview(r, { toolId: "bloodhound-ce", decision: "qualified", revision: "v5.1.0", reviewedBy: "operator" });
  return r;
}

describe("Universal Tool Registry", () => {
  it("registers any tool from anywhere with its protocol and sandbox surface", () => {
    const r = makeRegistry();
    const t = registerTool(r, CUSTOM);
    expect(t.state).toBe("unqualified");
    expect(TOOL_STATES).toContain("unqualified");
  });

  it("validates required fields, protocols, and sandbox classes", () => {
    const r = makeRegistry();
    registerTool(r, NMAP);
    expect(() => registerTool(r, { ...NMAP, license: undefined })).toThrow(/license/);
    expect(() => registerTool(r, { ...NMAP, protocols: [] })).toThrow(/protocols/);
    expect(() => registerTool(r, { ...NMAP, sandboxClass: "bare-metal" })).toThrow(/sandbox class/);
    expect(() => registerTool(r, { ...NMAP, id: "nmap-scoped" })).toThrow(/duplicate/);
  });

  it("qualification requires a pinned revision and is recorded", () => {
    const r = qualifiedRegistry();
    const q = qualifiedTools(r);
    expect(q.map((t) => t.id).sort()).toEqual(["bloodhound-ce", "nmap-scoped"]);
    expect(r.admissions.length).toBe(2);
    expect(() => admissionReview(r, { toolId: "nmap-scoped", decision: "qualified", revision: "x", reviewedBy: "o" })).toThrow(/already qualified/);
    expect(() => admissionReview(r, { toolId: "custom-fuzzer", decision: "qualified", reviewedBy: "o" })).toThrow(/pinned revision/);
  });

  it("rejection is explicit and recorded", () => {
    const r = makeRegistry();
    registerTool(r, CUSTOM);
    admissionReview(r, { toolId: "custom-fuzzer", decision: "rejected", reviewedBy: "operator", note: "AGPL + unvetted source" });
    expect(r.tools.get("custom-fuzzer").state).toBe("rejected");
    expect(qualifiedTools(r).length).toBe(0);
  });

  it("grants only issue over qualified tools", () => {
    const r = qualifiedRegistry();
    const g = issueGrant(r, { engagementId: "ENG-1", toolIds: ["nmap-scoped"] });
    expect(g.tools.has("nmap-scoped")).toBe(true);
    expect(() => issueGrant(r, { engagementId: "ENG-1", toolIds: ["custom-fuzzer"] })).toThrow(/not qualified/);
  });

  it("recommends the most useful qualified tool and surfaces unqualified candidates for admission", () => {
    const r = qualifiedRegistry();
    const rec = recommendForTask(r, { protocols: ["tcp", "udp"], capabilityClass: "network-recon" });
    expect(rec.qualified.map((t) => t.id)).toEqual(["nmap-scoped"]);
    const fuzz = recommendForTask(r, { protocols: ["tcp", "dns"], capabilityClass: "fuzzing" });
    expect(fuzz.qualified).toEqual([]);
    expect(fuzz.needsAdmission.map((t) => t.id)).toEqual(["custom-fuzzer"]);
  });
});

describe("Policy Engine (deny-by-default)", () => {
  const build = (over = {}) => {
    const r = qualifiedRegistry();
    const grants = { "ENG-1": issueGrant(r, { engagementId: "ENG-1", toolIds: ["nmap-scoped", "bloodhound-ce"] }) };
    const engagements = {
      "ENG-1": {
        scope: ["lab-api.g9.local", "lab-dc-01.g9.local"],
        roeSigned: true,
        principals: { "agent:hydra-svc": { revoked: false }, "agent:hydra-ident": { revoked: false } },
        ...over.engagement,
      },
    };
    return { engine: makePolicyEngine({ engagements, grants }), grants };
  };
  const REQ = {
    requestId: "REQ-1", engagementId: "ENG-1", principalId: "agent:hydra-svc",
    toolId: "nmap-scoped", targets: ["lab-api.g9.local"],
    sandboxClass: "restricted-analysis", requiredSandboxClass: "restricted-analysis",
  };

  it("allows a fully valid request", () => {
    const { engine } = build();
    const d = evaluate(engine, REQ);
    expect(d.effect).toBe("allow");
    expect(d.policyRevision).toBe("ceder@v1");
  });

  it("denies when the RoE is unsigned (red tier locked)", () => {
    const { engine } = build({ engagement: { roeSigned: false } });
    const d = evaluate(engine, REQ);
    expect(d.effect).toBe("deny");
    expect(d.reasons.join(" ")).toMatch(/unsigned/);
  });

  it("denies out-of-scope targets with the precise reason", () => {
    const { engine } = build();
    const d = evaluate(engine, { ...REQ, targets: ["lab-api.g9.local", "corp-prod.example.com"] });
    expect(d.effect).toBe("deny");
    expect(d.reasons.join(" ")).toMatch(/corp-prod\.example\.com/);
  });

  it("denies ungranted tools even if they exist in the registry", () => {
    const { engine } = build();
    const d = evaluate(engine, { ...REQ, toolId: "custom-fuzzer" });
    expect(d.effect).toBe("deny");
    expect(d.reasons.join(" ")).toMatch(/not in capability grant/);
  });

  it("denies unknown/revoked principals", () => {
    const { engine } = build();
    expect(evaluate(engine, { ...REQ, principalId: "agent:unknown" }).effect).toBe("deny");
    const rev = build({ engagement: { principals: { "agent:hydra-svc": { revoked: true } } } });
    expect(evaluate(rev.engine, REQ).effect).toBe("deny");
  });

  it("denies insufficient sandbox class for hostile-research tools", () => {
    const { engine } = build();
    const d = evaluate(engine, { ...REQ, sandboxClass: "restricted-analysis", requiredSandboxClass: "hostile-research-vm" });
    expect(d.effect).toBe("deny");
    expect(d.reasons.join(" ")).toMatch(/sandbox class/);
  });

  it("denies high-impact actions without an approval, and digest mismatches", () => {
    const { engine } = build();
    const d = evaluate(engine, { ...REQ, highImpact: true });
    expect(d.effect).toBe("deny");
    expect(d.reasons.join(" ")).toMatch(/approval/);
    const d2 = evaluate(engine, { ...REQ, approvalId: "APR-1", actionDigest: "aaa", boundDigest: "bbb" });
    expect(d2.effect).toBe("deny");
    expect(d2.reasons.join(" ")).toMatch(/digest mismatch/);
  });

  it("denies agent self-authorization — the model is not an authorization source", () => {
    const { engine } = build();
    const d = evaluate(engine, { ...REQ, selfAuthorized: true });
    expect(d.effect).toBe("deny");
    expect(d.reasons.join(" ")).toMatch(/self-authorization/);
  });

  it("records every decision for audit", () => {
    const { engine } = build();
    evaluate(engine, REQ);
    evaluate(engine, { ...REQ, targets: ["bad.host"] });
    expect(engine.decisions.length).toBe(2);
    expect(engine.decisions[1].effect).toBe("deny");
  });
});
