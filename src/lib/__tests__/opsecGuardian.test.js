import { describe, it, expect } from "vitest";
import {
  assessStealth, scanForIdentifiers, makeArtifactLedger, recordArtifact,
  markRemoved, cleanupManifest, closeEngagement, NOISE_CLASSES,
} from "../opsecGuardian.js";

const PLAN = {
  phases: {
    "recon": { maxNoise: 1 },
    "exploitation": { maxNoise: 3 },
    "post-exploit": { maxNoise: 2 },
  },
};

describe("Stealth assessment (pre-action gate)", () => {
  it("allows in-plan stealthy actions", () => {
    const r = assessStealth({ actionId: "A1", noiseClass: "low", opsecPlan: PLAN, phase: "recon", evidenceEncrypted: true });
    expect(r.ok).toBe(true);
    expect(r.verdict).toBe("proceed");
  });

  it("holds actions that exceed the phase noise ceiling", () => {
    const r = assessStealth({ actionId: "A2", noiseClass: "loud", opsecPlan: PLAN, phase: "recon", evidenceEncrypted: true });
    expect(r.ok).toBe(false);
    expect(r.violations.join(" ")).toMatch(/exceeds phase recon max/);
  });

  it("holds actions for unplanned phases (Phase 0 OPSEC plan incomplete)", () => {
    const r = assessStealth({ actionId: "A3", noiseClass: "low", opsecPlan: PLAN, phase: "cleanup", evidenceEncrypted: true });
    expect(r.ok).toBe(false);
    expect(r.violations.join(" ")).toMatch(/no OPSEC plan entry/);
  });

  it("rejects silent drift to louder declared intent", () => {
    const r = assessStealth({ actionId: "A4", noiseClass: "low", declaredNoise: "loud", opsecPlan: PLAN, phase: "recon", evidenceEncrypted: true });
    expect(r.ok).toBe(false);
    expect(r.violations.join(" ")).toMatch(/exceeds plan class/);
  });

  it("flags anonymity and evidence-encryption violations", () => {
    const pii = assessStealth({ actionId: "A5", noiseClass: "low", opsecPlan: PLAN, phase: "recon", containsPII: true, evidenceEncrypted: true });
    expect(pii.violations.join(" ")).toMatch(/anonymity violation/);
    const enc = assessStealth({ actionId: "A6", noiseClass: "low", opsecPlan: PLAN, phase: "recon", evidenceEncrypted: false });
    expect(enc.violations.join(" ")).toMatch(/encrypted at rest/);
  });

  it("notes that loud noise should be detected — silence is a finding", () => {
    const r = assessStealth({ actionId: "A7", noiseClass: "loud", opsecPlan: PLAN, phase: "exploitation", evidenceEncrypted: true });
    expect(r.ok).toBe(true);
    expect(r.note).toMatch(/headline finding/);
    expect(NOISE_CLASSES.loud.detectability).toBe(3);
  });

  it("rejects unknown noise classes", () => {
    expect(assessStealth({ actionId: "A8", noiseClass: "invisible" }).ok).toBe(false);
  });
});

describe("Anonymity scanning", () => {
  it("passes clean payloads", () => {
    const r = scanForIdentifiers({ flags: "-sS -sV", hosts: ["lab-api.g9.local"] });
    expect(r.clean).toBe(true);
  });

  it("detects emails, phones, and personal handles", () => {
    expect(scanForIdentifiers({ contact: "me@example.com" }).clean).toBe(false);
    expect(scanForIdentifiers({ call: "+1 555 123 4567" }).clean).toBe(false);
    expect(scanForIdentifiers({ note: "run as hackytacky" }).clean).toBe(false);
    expect(scanForIdentifiers({ who: "John Smith" }).clean).toBe(false);
  });
});

describe("No-traces artifact ledger", () => {
  const ledger = () => makeArtifactLedger({ engagementId: "ENG-1", evidenceStore: { encrypted: true, disposition: "handover" } });

  it("requires an encrypted evidence store (RoE)", () => {
    expect(() => makeArtifactLedger({ engagementId: "ENG-1", evidenceStore: { encrypted: false } })).toThrow(/encrypted/);
  });

  it("records every artifact at creation and blocks duplicates", () => {
    const l = ledger();
    recordArtifact(l, { id: "ART-1", kind: "session-cookie", location: "lab-api:/tmp/.s", detectability: "target-visible" });
    recordArtifact(l, { id: "ART-2", kind: "persistence-marker", location: "lab-forensics:/var/.g9_marker", detectability: "target-visible" });
    expect(l.artifacts.size).toBe(2);
    expect(() => recordArtifact(l, { id: "ART-1", kind: "x", location: "y" })).toThrow(/duplicate/);
  });

  it("retention requires an explicit reviewer/RoE citation", () => {
    const l = ledger();
    recordArtifact(l, { id: "ART-1", kind: "evidence-bundle", location: "evidence-store:bundle.zip" });
    expect(() => markRemoved(l, { id: "ART-1", state: "retained-per-roe" })).toThrow(/retention requires/);
    markRemoved(l, { id: "ART-1", state: "retained-per-roe", verifiedBy: "operator (RoE §evidence)" });
    expect(l.artifacts.get("ART-1").state).toBe("retained-per-roe");
  });

  it("blocks engagement close while artifacts remain — no traces", () => {
    const l = ledger();
    recordArtifact(l, { id: "ART-1", kind: "marker", location: "host:/var/.m" });
    recordArtifact(l, { id: "ART-2", kind: "log", location: "host:/var/log/.g9" });
    const blocked = closeEngagement(l);
    expect(blocked.ok).toBe(false);
    expect(blocked.reason).toMatch(/no-traces gate/);
    expect(blocked.manifest.remaining.map((a) => a.id)).toEqual(["ART-1", "ART-2"]);
    markRemoved(l, { id: "ART-1", state: "removed" });
    markRemoved(l, { id: "ART-2", state: "removed" });
    const closed = closeEngagement(l);
    expect(closed.ok).toBe(true);
    expect(closed.manifest.cleaned).toBe(2);
    expect(l.closed).toBe(true);
  });

  it("closed ledgers accept no new artifacts", () => {
    const l = ledger();
    recordArtifact(l, { id: "ART-1", kind: "x", location: "y" });
    markRemoved(l, { id: "ART-1" });
    closeEngagement(l);
    expect(() => recordArtifact(l, { id: "ART-9", kind: "x", location: "y" })).toThrow(/closed/);
  });

  it("manifest summarizes disposition", () => {
    const l = ledger();
    recordArtifact(l, { id: "ART-1", kind: "evidence", location: "store:x" });
    const m = cleanupManifest(l);
    expect(m.total).toBe(1);
    expect(m.canClose).toBe(false);
    expect(m.evidenceDisposition).toBe("handover");
  });
});
