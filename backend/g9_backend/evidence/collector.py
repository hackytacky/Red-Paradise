"""g9-evidence: the result collector — tool output becomes evidence.

Every completed tool run is ingested as provenance-tagged
observations anchored to a ToolExecution. Parsed findings ALWAYS
enter as `candidate` — the Verification Authority confirms, never
the scanner, never the collector, never the agent.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .graph import EvidenceGraph


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _artifact_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class ResultCollector:
    def __init__(self, graph: EvidenceGraph):
        self.graph = graph
        self.ingested: list[dict] = []

    def ingest_tool_result(self, *, tool_id: str, command: str, stdout: str, stderr: str = "", targets: list[str], exit_code: int | None, at: str | None = None) -> dict:
        """Ingest one completed tool run. Creates observations for the
        raw output and candidate findings for anything the tool claims.
        Nothing is confirmed here."""
        if not tool_id or not command:
            raise ValueError("tool_id and command are required")
        ts = at or _now()
        digest = _artifact_digest(stdout)

        # observation: the raw run output, provenance-tagged
        obs_id = f"obs-{digest[:12]}"
        if obs_id in self.graph.nodes:
            observation = self.graph.nodes[obs_id]  # identical output: reuse, never duplicate
        else:
            observation = self.graph.add_node({
            "id": obs_id, "klass": "observation",
            "label": f"{tool_id} output ({len(stdout)} bytes, exit {exit_code})",
            "scope": self.graph.scope, "source": tool_id, "collected_at": ts,
                "provenance": {"tool": tool_id, "command_digest": _artifact_digest(command)},
                "artifacts": [f"sha256:{digest}"], "meta": {"targets": targets, "stderr_bytes": len(stderr)},
            })

        # candidate findings parsed from structured tool output
        candidates = self._parse_candidates(tool_id, stdout, ts)
        for cand in candidates:
            self.graph.add_edge("evidences", obs_id, cand["id"])

        record = {
            "observation": obs_id, "candidates": [c["id"] for c in candidates],
            "artifact": f"sha256:{digest}", "at": ts,
        }
        self.ingested.append(record)
        return record

    def _parse_candidates(self, tool_id: str, stdout: str, ts: str) -> list[dict]:
        """Parse structured tool output into CANDIDATE findings.
        Supported: nuclei-style JSON lines / arrays. Everything else
        stays an observation — no invented findings."""
        candidates: list[dict] = []
        lines = [l for l in stdout.splitlines() if l.strip()]
        for line in lines:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict) or "template-id" not in data:
                continue
            cand_id = f"find-cand-{hashlib.sha256((data['template-id'] + str(data.get('host'))).encode()).hexdigest()[:12]}"
            if cand_id in self.graph.nodes:
                continue
            node = self.graph.add_node({
                "id": cand_id, "klass": "finding",
                "label": f"[candidate] {data.get('template-id')}: {data.get('host', '')}",
                "scope": self.graph.scope, "source": tool_id, "collected_at": ts,
                "provenance": {"tool": tool_id, "template": data.get("template-id")},
                "validation_status": "candidate",  # NEVER confirmed here
                "meta": {"severity": data.get("info", {}).get("severity", "unknown"), "matched_at": data.get("matched-at")},
            })
            candidates.append(node)
        return candidates
