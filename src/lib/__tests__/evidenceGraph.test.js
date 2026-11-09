import { describe, it, expect } from "vitest";
import { EvidenceGraph, makeNode, NODE_CLASSES, VALIDATION_STATUS } from "../evidenceGraph.js";

const SCOPE = "10.10.0.0/24 · *.g9.local";

function buildGraph() {
  const g = new EvidenceGraph({ scope: SCOPE });
  g.addNode(makeNode({ id: "A1", klass: "asset", label: "lab-api.g9.local", scope: SCOPE, meta: { targetId: "lab-api" } }));
  g.addNode(makeNode({ id: "S1", klass: "service", label: "https :443", scope: SCOPE }));
  g.addNode(makeNode({ id: "T1", klass: "technology", label: "custom order API v1", scope: SCOPE }));
  g.addNode(makeNode({ id: "H1", klass: "hypothesis", label: "SQLi in /orders", scope: SCOPE, confidence: 0.6, meta: { targetId: "lab-api", titleFingerprint: "sqli-orders" } }));
  g.addNode(makeNode({ id: "T2", klass: "test", label: "union-based probe", scope: SCOPE, provenance: { tool: "httpx" } }));
  g.addNode(makeNode({ id: "O1", klass: "observation", label: "role=admin in response", scope: SCOPE }));
  g.addNode(makeNode({ id: "F1", klass: "finding", label: "F-0001 SQLi auth bypass", scope: SCOPE, validationStatus: "reproduced", provenance: { model: "g9-32b-web-ft" } }));
  g.addNode(makeNode({ id: "F2", klass: "finding", label: "F-0004 SSRF metadata creds", scope: SCOPE, validationStatus: "confirmed" }));
  g.addNode(makeNode({ id: "F3", klass: "finding", label: "F-0003 IDOR invoices", scope: SCOPE, validationStatus: "confirmed" }));
  g.addEdge({ type: "runs-on", from: "S1", to: "A1" });
  g.addEdge({ type: "uses-tech", from: "S1", to: "T1" });
  g.addEdge({ type: "hypothesizes", from: "T1", to: "H1" });
  g.addEdge({ type: "tested-by", from: "H1", to: "T2" });
  g.addEdge({ type: "observed-by", from: "T2", to: "O1" });
  g.addEdge({ type: "evidences", from: "O1", to: "F1" });
  g.addEdge({ type: "chains-to", from: "F1", to: "F2" });
  g.addEdge({ type: "chains-to", from: "F2", to: "F3" });
  return g;
}

describe("EvidenceGraph", () => {
  it("accepts a well-formed graph", () => {
    const g = buildGraph();
    expect(g.nodes.size).toBe(9);
    expect(g.edges.length).toBe(8);
  });

  it("rejects unknown node classes and invalid confidence", () => {
    expect(() => makeNode({ id: "X", klass: "bogus", label: "x", scope: SCOPE })).toThrow();
    expect(() => makeNode({ id: "X", klass: "asset", label: "x", scope: SCOPE, confidence: 1.5 })).toThrow();
  });

  it("rejects duplicate node ids and scope mismatches", () => {
    const g = buildGraph();
    expect(() => g.addNode(makeNode({ id: "F1", klass: "finding", label: "dup", scope: SCOPE }))).toThrow(/duplicate/);
    expect(() => g.addNode(makeNode({ id: "F9", klass: "finding", label: "other scope", scope: "elsewhere" }))).toThrow(/scope/);
  });

  it("enforces typed edge classes", () => {
    const g = buildGraph();
    expect(() => g.addEdge({ type: "evidences", from: "A1", to: "F1" })).toThrow(/source class/);
    expect(() => g.addEdge({ type: "chains-to", from: "F1", to: "A1" })).toThrow(/target class/);
    expect(() => g.addEdge({ type: "nonsense", from: "A1", to: "A1" })).toThrow(/unknown edge type/);
  });

  it("reasons attack paths only over verified finding links", () => {
    const g = buildGraph();
    expect(g.shortestAttackPath("F1", "F3")).toEqual(["F1", "F2", "F3"]);
    // an unverified finding is not a confirmed fact: link it into the chain
    g.addNode(makeNode({ id: "F4", klass: "finding", label: "unverified", scope: SCOPE, validationStatus: "candidate" }));
    g.addEdge({ type: "chains-to", from: "F3", to: "F4" });
    expect(g.shortestAttackPath("F1", "F4")).toBeNull();
  });

  it("prevents duplicate rediscovery via equivalence fingerprints", () => {
    const g = buildGraph();
    const dup = g.findEquivalent({ klass: "hypothesis", targetId: "lab-api", titleFingerprint: "sqli-orders" });
    expect(dup.id).toBe("H1");
    expect(g.findEquivalent({ klass: "hypothesis", targetId: "lab-api", titleFingerprint: "other" })).toBeNull();
  });

  it("attributes nodes by provenance for audit", () => {
    const g = buildGraph();
    const byModel = g.nodesByProvenance({ model: "g9-32b-web-ft" });
    expect(byModel.map((n) => n.id)).toEqual(["F1"]);
    const byTool = g.nodesByProvenance({ tool: "httpx" });
    expect(byTool.map((n) => n.id)).toEqual(["T2"]);
  });

  it("keeps hypotheses distinct from confirmed facts", () => {
    const g = buildGraph();
    const h = g.nodes.get("H1");
    const f = g.nodes.get("F2");
    expect(EvidenceGraph.isConfirmedFact(h)).toBe(false);
    expect(EvidenceGraph.isConfirmedFact(f)).toBe(true);
    expect(NODE_CLASSES).toContain("hypothesis");
    expect(VALIDATION_STATUS[0]).toBe("unvalidated");
  });
});
