import React, { useMemo, useState } from "react";
import { Panel } from "./views1.jsx";
import { EvidenceGraph, makeNode, NODE_CLASSES, VALIDATION_STATUS } from "./lib/evidenceGraph.js";
import { makeFinding, advance, submitReproduction, FINDING_STATES } from "./lib/verificationAuthority.js";
import { FINDINGS_SEED, CHAINS } from "./data.js";

/* ================================================================
   VIEW: Evidence Graph + Verification Authority (live engines)
   ================================================================ */

const SCOPE = "10.10.0.0/24 · *.g9.local";

const KLASS_STYLE = {
  asset: { fill: "#64748b", icon: "▣" },
  service: { fill: "#0e7490", icon: "◉" },
  technology: { fill: "#7c3aed", icon: "◇" },
  hypothesis: { fill: "#d97706", icon: "?" },
  test: { fill: "#0369a1", icon: "⚡" },
  observation: { fill: "#0891b2", icon: "👁" },
  finding: { fill: "#dc2626", icon: "⚑" },
  "attack-path": { fill: "#16a34a", icon: "★" },
};

function buildGraph() {
  const g = new EvidenceGraph({ scope: SCOPE });
  const add = (n) => g.addNode(makeNode(n));
  add({ id: "A1", klass: "asset", label: "lab-api.g9.local", scope: SCOPE, meta: { targetId: "lab-api" } });
  add({ id: "A2", klass: "asset", label: "lab-portal.g9.local", scope: SCOPE, meta: { targetId: "lab-portal" } });
  add({ id: "A3", klass: "asset", label: "lab-dc-01.g9.local", scope: SCOPE, meta: { targetId: "lab-dc" } });
  add({ id: "S1", klass: "service", label: "https :443 order API", scope: SCOPE });
  add({ id: "S2", klass: "service", label: "SMB / LDAP", scope: SCOPE });
  add({ id: "T1", klass: "technology", label: "custom order API v1", scope: SCOPE });
  add({ id: "T2", klass: "technology", label: "AD forest (lab)", scope: SCOPE });
  add({ id: "H1", klass: "hypothesis", label: "SQLi in /orders", scope: SCOPE, confidence: 0.6, provenance: { model: "g9-32b-web-ft" }, meta: { targetId: "lab-api", titleFingerprint: "sqli-orders" } });
  add({ id: "H2", klass: "hypothesis", label: "Kerberoastable SPN", scope: SCOPE, confidence: 0.7, provenance: { model: "g9-32b-ident-ft" }, meta: { targetId: "lab-dc", titleFingerprint: "kerberoast-spn" } });
  add({ id: "X1", klass: "test", label: "union-based probe", scope: SCOPE, provenance: { tool: "httpx" } });
  add({ id: "X2", klass: "test", label: "GetUserSPNs + offline crack", scope: SCOPE, provenance: { tool: "graph-paths" } });
  add({ id: "O1", klass: "observation", label: "role=admin in response", scope: SCOPE, provenance: { tool: "post-condition-check" } });
  add({ id: "O2", klass: "observation", label: "DC session from delegation path", scope: SCOPE, provenance: { tool: "post-condition-check" } });
  add({ id: "F1", klass: "finding", label: "F-0001 SQLi auth bypass", scope: SCOPE, validationStatus: "reproduced", provenance: { model: "g9-32b-web-ft" } });
  add({ id: "F2", klass: "finding", label: "F-0004 SSRF metadata creds", scope: SCOPE, validationStatus: "confirmed" });
  add({ id: "F3", klass: "finding", label: "F-0003 IDOR invoices", scope: SCOPE, validationStatus: "confirmed" });
  add({ id: "F4", klass: "finding", label: "F-0006 delegation path to DC", scope: SCOPE, validationStatus: "confirmed" });
  add({ id: "P1", klass: "attack-path", label: "C-01 payment records", scope: SCOPE, validationStatus: "confirmed" });
  g.addEdge({ type: "runs-on", from: "S1", to: "A1" });
  g.addEdge({ type: "runs-on", from: "S2", to: "A3" });
  g.addEdge({ type: "uses-tech", from: "S1", to: "T1" });
  g.addEdge({ type: "uses-tech", from: "S2", to: "T2" });
  g.addEdge({ type: "hypothesizes", from: "T1", to: "H1" });
  g.addEdge({ type: "hypothesizes", from: "T2", to: "H2" });
  g.addEdge({ type: "tested-by", from: "H1", to: "X1" });
  g.addEdge({ type: "tested-by", from: "H2", to: "X2" });
  g.addEdge({ type: "observed-by", from: "X1", to: "O1" });
  g.addEdge({ type: "observed-by", from: "X2", to: "O2" });
  g.addEdge({ type: "evidences", from: "O1", to: "F1" });
  g.addEdge({ type: "evidences", from: "O2", to: "F4" });
  g.addEdge({ type: "chains-to", from: "F1", to: "F2" });
  g.addEdge({ type: "chains-to", from: "F2", to: "F3" });
  g.addEdge({ type: "part-of", from: "F3", to: "P1" });
  return g;
}

const POS = {
  A1: [40, 40], A2: [40, 130], A3: [40, 220],
  S1: [170, 40], S2: [170, 220],
  T1: [300, 40], T2: [300, 220],
  H1: [430, 40], H2: [430, 220],
  X1: [560, 40], X2: [560, 220],
  O1: [690, 40], O2: [690, 220],
  F1: [820, 40], F2: [820, 130], F3: [820, 220], F4: [430, 130],
  P1: [950, 130],
};

export function EvidenceView() {
  const graph = useMemo(() => buildGraph(), []);
  const [pathFrom, setPathFrom] = useState("F1");
  const [pathTo, setPathTo] = useState("F3");
  const [verifierFinding, setVerifierFinding] = useState(() => {
    const f = makeFinding({
      id: "F-0018", title: "Race condition on coupon redemption (demo ladder)",
      scope: SCOPE, vector: "web", target: "lab-shop.g9.local",
    });
    advance(f, { role: "agent", evidence: ["agent-submission"], note: "HYDRA-WEB submitted hypothesis with PoC plan" });
    return f;
  });
  const [lastAction, setLastAction] = useState(null);

  const path = graph.shortestAttackPath(pathFrom, pathTo);
  const findings = [...graph.nodes.values()].filter((n) => n.klass === "finding");

  const runStep = (step) => {
    const f = verifierFinding;
    let r;
    if (step === "reproduce") {
      r = submitReproduction(f, { role: "verifier", reproductionArtifact: "pov-balance-delta.txt", postConditionPassed: true, note: "CERBERUS deterministic post-condition passed" });
    } else if (step === "confirm") {
      r = advance(f, { role: "verifier", evidence: ["adjudication", "independent-evidence"], note: "THEMIS/SOCRATES independent adjudication" });
    } else if (step === "remediate") {
      r = advance(f, { role: "verifier", evidence: ["remediation-evidence"], note: "owner applied idempotency key + row lock" });
    } else if (step === "regression") {
      r = advance(f, { role: "verifier", evidence: ["regression-test-passed"], note: "concurrent replay yields exactly one redemption" });
    } else if (step === "self-promote") {
      r = advance(f, { role: "agent", evidence: ["adjudication", "independent-evidence"], note: "agent attempted to promote its own finding" });
    }
    setLastAction({ ok: r.ok, reason: r.reason, step });
    setVerifierFinding({ ...f });
  };

  const nextStep = {
    reproduced: "confirm", confirmed: "remediate", remediated: "regression",
  }[verifierFinding.state];

  return (
    <div className="space-y-4">
      <Panel title="G9 Evidence Graph — live engine (typed nodes, provenance, verified attack-path reasoning)">
        <div className="text-[11px] text-slate-500 mb-3 leading-relaxed">
          Strictly separated node classes: <span className="font-mono text-slate-400">{NODE_CLASSES.join(" → ")}</span>. Every node carries scope, timestamp, model/tool provenance, confidence and validation status (<span className="font-mono text-slate-400">{VALIDATION_STATUS.join(" · ")}</span>). Attack-path reasoning runs over <span className="text-slate-300 font-semibold">verified finding links only</span> — hypotheses and observations never satisfy a path.
        </div>
        <div className="overflow-x-auto rounded-lg bg-black/40 border border-slate-800 p-2">
          <svg viewBox="0 0 1060 280" className="w-full min-w-[900px]">
            {graph.edges.map((e, i) => {
              const [x1, y1] = POS[e.from]; const [x2, y2] = POS[e.to];
              const onPath = path && path.includes(e.from) && path.includes(e.to) && path.indexOf(e.to) === path.indexOf(e.from) + 1 && e.type === "chains-to";
              return (
                <line key={i} x1={x1 + 12} y1={y1 + 12} x2={x2 + 12} y2={y2 + 12}
                  stroke={onPath ? "#10b981" : "#334155"} strokeWidth={onPath ? 3 : 1.2}
                  strokeDasharray={e.type === "chains-to" ? "" : "4 4"} />
              );
            })}
            {[...graph.nodes.values()].map((n) => {
              const st = KLASS_STYLE[n.klass];
              const [x, y] = POS[n.id];
              const dim = n.klass === "hypothesis" || n.klass === "observation" || n.validationStatus === "candidate" || n.validationStatus === "unvalidated";
              return (
                <g key={n.id} opacity={dim ? 0.75 : 1}>
                  <rect x={x} y={y} width={110} height={44} rx={8}
                    fill={`${st.fill}22`} stroke={st.fill} strokeWidth={1.5} strokeDasharray={dim ? "5 3" : ""} />
                  <text x={x + 8} y={y + 15} fontSize={7.5} fill={st.fill} fontFamily="monospace">{st.icon} {n.klass}</text>
                  <text x={x + 8} y={y + 28} fontSize={8} fill="#cbd5e1" fontFamily="monospace">
                    {n.label.length > 22 ? n.label.slice(0, 22) + "…" : n.label}
                  </text>
                  <text x={x + 8} y={y + 39} fontSize={6.5} fill="#64748b" fontFamily="monospace">
                    {n.validationStatus !== "unvalidated" ? `✓ ${n.validationStatus}` : n.confidence !== null ? `conf ${n.confidence}` : ""}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
          <span className="text-slate-500">Attack-path query (verified links only):</span>
          <select value={pathFrom} onChange={(e) => setPathFrom(e.target.value)} className="px-2 py-1 rounded bg-slate-950 border border-slate-800 font-mono text-[11px]">
            {findings.map((f) => <option key={f.id} value={f.id}>{f.id}</option>)}
          </select>
          <span className="text-slate-600">→</span>
          <select value={pathTo} onChange={(e) => setPathTo(e.target.value)} className="px-2 py-1 rounded bg-slate-950 border border-slate-800 font-mono text-[11px]">
            {findings.map((f) => <option key={f.id} value={f.id}>{f.id}</option>)}
          </select>
          <span className={`px-2 py-0.5 rounded border font-mono ${path ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40" : "bg-red-500/15 text-red-300 border-red-500/40"}`}>
            {path ? path.join(" → ") : "no verified path"}
          </span>
        </div>
      </Panel>

      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="G9 Verification Authority — live finding ladder">
          <div className="flex flex-wrap gap-1 mb-3">
            {FINDING_STATES.map((s) => {
              const idx = FINDING_STATES.indexOf(s);
              const cur = FINDING_STATES.indexOf(verifierFinding.state);
              return (
                <span key={s} className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${idx < cur ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40" : idx === cur ? "bg-cyan-500/20 text-cyan-200 border-cyan-500/50" : "bg-slate-950 text-slate-600 border-slate-800"}`}>
                  {idx < cur ? "✓ " : ""}{s}
                </span>
              );
            })}
          </div>
          <div className="text-[12px] font-bold text-slate-100">{verifierFinding.title}</div>
          <div className="text-[11px] text-slate-500 mb-3">{verifierFinding.id} · {verifierFinding.target}</div>
          <div className="flex flex-wrap gap-2">
            {nextStep && (
              <button onClick={() => runStep(nextStep)} className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-bold">
                {nextStep === "confirm" ? "Confirm (verifier)" : nextStep === "remediate" ? "Mark remediated" : "Run regression test"}
              </button>
            )}
            {verifierFinding.state === "candidate" && (
              <button onClick={() => runStep("reproduce")} className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px] font-bold">
                Verify post-condition → reproduce
              </button>
            )}
            <button onClick={() => runStep("self-promote")} className="px-3 py-1.5 rounded bg-red-600/80 hover:bg-red-500 text-white text-[11px] font-bold">
              Try agent self-promotion (must fail)
            </button>
          </div>
          {lastAction && (
            <div className={`mt-3 rounded-lg border p-2.5 text-[11px] ${lastAction.ok ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-200" : "border-red-500/40 bg-red-500/5 text-red-200"}`}>
              {lastAction.ok ? "✓" : "✕"} <span className="font-bold">{lastAction.step}</span>: {lastAction.reason}
            </div>
          )}
          <div className="mt-3 pt-3 border-t border-slate-800">
            <div className="text-[10px] font-bold tracking-widest text-slate-600 uppercase mb-1">Audit log (append-only)</div>
            <div className="space-y-0.5 font-mono text-[10.5px]">
              {verifierFinding.auditLog.map((l, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-slate-700">{l.at.slice(11, 19)}</span>
                  <span className="text-slate-500">[{l.role}]</span>
                  <span className="text-slate-400">{l.from ?? "∅"} → {l.to}</span>
                  <span className="text-slate-500 truncate">{l.note}</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>

        <Panel title="Engine contracts (implemented in src/lib)">
          <div className="space-y-2 text-[11px]">
            {[
              ["evidenceGraph.js", "Typed node classes with class-enforced edges, scope authority (engagement scope is authoritative — mismatched nodes are rejected), duplicate-rediscovery prevention via equivalence fingerprints, provenance attribution queries, and BFS attack-path reasoning over verified finding links only."],
              ["verificationAuthority.js", "Explicit state machine: hypothesis → candidate → reproduced → confirmed → remediated → regression-verified. Verifier-role gating (agents can never promote past candidate), per-transition evidence requirements, deterministic post-condition acceptance, and an append-only attributable audit log."],
              ["__tests__/", "15 unit tests cover: typed-edge rejection, scope mismatch, duplicate ids, unverified-link exclusion from paths, equivalence dedupe, provenance attribution, missing-evidence rejection, self-promotion refusal, failed post-condition refusal, full ladder walk, and terminal-state handling."],
            ].map(([f, d]) => (
              <div key={f} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="font-mono text-cyan-300 font-bold">{f}</div>
                <div className="text-slate-400 leading-relaxed mt-0.5">{d}</div>
              </div>
            ))}
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-2.5 text-slate-400">
              <span className="font-bold text-emerald-300">npm test</span> — vitest, 15 passing. These are the real engines behind the UI panels, not mockups: the graph on the left is rendered from a live <span className="font-mono">EvidenceGraph</span> instance and the ladder is a live <span className="font-mono">makeFinding</span> instance.
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
