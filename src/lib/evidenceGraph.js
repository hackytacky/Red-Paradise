/* ============================================================
   G9 Evidence Graph — typed evidence model with provenance,
   confidence, validation status, and attack-path reasoning.

   Node classes (strictly separated):
     asset → service → technology → hypothesis → test →
     observation → finding → attack-path

   Design rules (docs/architecture/custom-capabilities.md):
   - Hypotheses, observations and confirmed facts are distinct.
   - Every node carries source, timestamp, model/tool provenance,
     confidence, validation status, engagement scope, artifact links.
   - Graph-based attack-path reasoning over verified links only.
   ============================================================ */

export const NODE_CLASSES = ["asset", "service", "technology", "hypothesis", "test", "observation", "finding", "attack-path"];

export const VALIDATION_STATUS = ["unvalidated", "candidate", "reproduced", "confirmed", "remediated", "regression-verified"];

export const EDGE_TYPES = {
  "runs-on": ["service", "asset"],
  "uses-tech": ["service", "technology"],
  "hypothesizes": ["technology", "hypothesis"],
  "tested-by": ["hypothesis", "test"],
  "observed-by": ["test", "observation"],
  "evidences": ["observation", "finding"],
  "chains-to": ["finding", "finding"],
  "part-of": ["finding", "attack-path"],
  "relates-to": [null, null], // free-form, never used for attack-path reasoning
};

const _required = (cond, msg) => {
  if (!cond) throw new Error(`EvidenceGraph: ${msg}`);
};

export function makeNode({
  id, klass, label, scope,
  source = null, collectedAt = null,
  provenance = { model: null, tool: null },
  confidence = null, // 0..1, null for deterministic facts
  validationStatus = "unvalidated",
  artifacts = [],
  meta = {},
}) {
  _required(typeof id === "string" && id.length > 0, "node id is required");
  _required(NODE_CLASSES.includes(klass), `unknown node class ${JSON.stringify(klass)}`);
  _required(typeof scope === "string" && scope.length > 0, "engagement scope is required on every node");
  _required(VALIDATION_STATUS.includes(validationStatus), `unknown validation status ${JSON.stringify(validationStatus)}`);
  _required(confidence === null || (typeof confidence === "number" && confidence >= 0 && confidence <= 1),
    "confidence must be null or a number in [0,1]");
  return {
    id, klass, label, scope,
    source: source ?? "unknown",
    collectedAt: collectedAt ?? new Date().toISOString(),
    provenance: { model: provenance?.model ?? null, tool: provenance?.tool ?? null },
    confidence: confidence === null ? null : Math.round(confidence * 100) / 100,
    validationStatus,
    artifacts: Array.isArray(artifacts) ? [...artifacts] : [],
    meta: { ...meta },
  };
}

export class EvidenceGraph {
  constructor({ scope } = {}) {
    _required(typeof scope === "string" && scope.length > 0, "graph requires an engagement scope");
    this.scope = scope;
    this.nodes = new Map();
    this.edges = [];
  }

  addNode(node) {
    _required(node && node.id !== undefined, "addNode requires a node");
    _required(node.scope === this.scope, `node ${node.id} scope mismatch: engagement scope is authoritative`);
    _required(!this.nodes.has(node.id), `duplicate node id ${node.id} — dedupe before adding`);
    this.nodes.set(node.id, node);
    return node;
  }

  addEdge({ type, from, to }) {
    const t = EDGE_TYPES[type];
    _required(t !== undefined, `unknown edge type ${JSON.stringify(type)}`);
    const a = this.nodes.get(from);
    const b = this.nodes.get(to);
    _required(a && b, `edge ${from} -> ${to} references missing node(s)`);
    if (t[0] !== null) _required(a.klass === t[0], `edge ${type} requires source class ${t[0]}, got ${a.klass}`);
    if (t[1] !== null) _required(b.klass === t[1], `edge ${type} requires target class ${t[1]}, got ${b.klass}`);
    const edge = { type, from, to, at: new Date().toISOString() };
    this.edges.push(edge);
    return edge;
  }

  /* Confirmed facts only: a finding counts as a confirmed fact when
     its validation status is reproduced or higher. Hypotheses and
     mere observations never satisfy attack-path reasoning. */
  static isConfirmedFact(node) {
    const i = VALIDATION_STATUS.indexOf(node.validationStatus);
    return node.klass === "finding" && i >= VALIDATION_STATUS.indexOf("reproduced");
  }

  /* Attack-path reasoning: shortest path over verified finding
     links (chains-to) from a start finding to a target finding.
     Unverified links never contribute to a path. */
  shortestAttackPath(fromFindingId, toFindingId) {
    const adjacency = new Map();
    for (const e of this.edges) {
      if (e.type !== "chains-to") continue;
      const src = this.nodes.get(e.from);
      const dst = this.nodes.get(e.to);
      if (!EvidenceGraph.isConfirmedFact(src) || !EvidenceGraph.isConfirmedFact(dst)) continue;
      if (!adjacency.has(e.from)) adjacency.set(e.from, []);
      adjacency.get(e.from).push(e.to);
    }
    const queue = [[fromFindingId]];
    const seen = new Set([fromFindingId]);
    while (queue.length > 0) {
      const path = queue.shift();
      const last = path[path.length - 1];
      if (last === toFindingId) return path;
      for (const next of adjacency.get(last) ?? []) {
        if (!seen.has(next)) {
          seen.add(next);
          queue.push([...path, next]);
        }
      }
    }
    return null;
  }

  /* Duplicate-rediscovery prevention: is there already an equivalent
     hypothesis/observation/finding for this target+class+label key? */
  findEquivalent({ klass, targetId, titleFingerprint }) {
    for (const n of this.nodes.values()) {
      if (n.klass !== klass) continue;
      if (n.meta.targetId === targetId && n.meta.titleFingerprint === titleFingerprint) return n;
    }
    return null;
  }

  /* Provenance audit: every action attributable — list all nodes
     produced by a given model/tool. */
  nodesByProvenance({ model, tool }) {
    return [...this.nodes.values()].filter(
      (n) => (model !== undefined && n.provenance.model === model) ||
              (tool !== undefined && n.provenance.tool === tool)
    );
  }

  toJSON() {
    return { scope: this.scope, nodes: [...this.nodes.values()], edges: this.edges };
  }
}
