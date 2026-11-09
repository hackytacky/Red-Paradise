"""g9-evidence: the evidence graph contract (Python port of
src/lib/evidenceGraph.js). Hypotheses, observations and confirmed
facts are strictly distinct; attack-path reasoning runs over
verified links only."""

from __future__ import annotations

NODE_CLASSES = {"asset", "service", "technology", "hypothesis", "test", "observation", "finding", "attack-path"}
VALIDATION_STATUS = ["unvalidated", "candidate", "reproduced", "confirmed", "remediated", "regression-verified"]

EDGE_TYPES = {
    "runs-on": ("service", "asset"),
    "uses-tech": ("service", "technology"),
    "hypothesizes": ("technology", "hypothesis"),
    "tested-by": ("hypothesis", "test"),
    "observed-by": ("test", "observation"),
    "evidences": ("observation", "finding"),
    "chains-to": ("finding", "finding"),
    "part-of": ("finding", "attack-path"),
    "relates-to": (None, None),
}


class EvidenceGraphError(ValueError):
    pass


class EvidenceGraph:
    def __init__(self, scope: str):
        if not scope:
            raise EvidenceGraphError("engagement scope is required")
        self.scope = scope
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    def add_node(self, node: dict) -> dict:
        for f in ("id", "klass", "label"):
            if not node.get(f):
                raise EvidenceGraphError(f"node requires {f}")
        if node["id"] in self.nodes:
            raise EvidenceGraphError(f"duplicate node {node['id']}")
        if node["klass"] not in NODE_CLASSES:
            raise EvidenceGraphError(f"unknown node class {node['klass']!r}")
        if node.get("scope") != self.scope:
            raise EvidenceGraphError("node scope must match the authoritative engagement scope")
        rec = {
            "id": node["id"], "klass": node["klass"], "label": node["label"],
            "scope": node["scope"], "source": node.get("source", "unknown"),
            "collected_at": node.get("collected_at"), "provenance": node.get("provenance", {}),
            "confidence": node.get("confidence"), "validation_status": node.get("validation_status", "unvalidated"),
            "artifacts": node.get("artifacts", []), "meta": node.get("meta", {}),
        }
        self.nodes[rec["id"]] = rec
        return rec

    def add_edge(self, etype: str, from_id: str, to_id: str) -> dict:
        if etype not in EDGE_TYPES:
            raise EvidenceGraphError(f"unknown edge type {etype!r}")
        a, b = self.nodes.get(from_id), self.nodes.get(to_id)
        if not a or not b:
            raise EvidenceGraphError("edge references missing node(s)")
        want_src, want_dst = EDGE_TYPES[etype]
        if want_src and a["klass"] != want_src:
            raise EvidenceGraphError(f"edge {etype} requires source class {want_src}")
        if want_dst and b["klass"] != want_dst:
            raise EvidenceGraphError(f"edge {etype} requires target class {want_dst}")
        edge = {"type": etype, "from": from_id, "to": to_id}
        self.edges.append(edge)
        return edge

    @staticmethod
    def is_confirmed_fact(node: dict) -> bool:
        order = VALIDATION_STATUS
        return node["klass"] == "finding" and order.index(node["validation_status"]) >= order.index("reproduced")

    def shortest_attack_path(self, from_id: str, to_id: str) -> list[str] | None:
        adjacency: dict[str, list[str]] = {}
        for e in self.edges:
            if e["type"] != "chains-to":
                continue
            if not self.is_confirmed_fact(self.nodes[e["from"]]) or not self.is_confirmed_fact(self.nodes[e["to"]]):
                continue
            adjacency.setdefault(e["from"], []).append(e["to"])
        queue = [[from_id]]
        seen = {from_id}
        while queue:
            path = queue.pop(0)
            if path[-1] == to_id:
                return path
            for nxt in adjacency.get(path[-1], []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(path + [nxt])
        return None
