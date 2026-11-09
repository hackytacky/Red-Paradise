import React, { useMemo, useState } from "react";
import { Panel } from "./views1.jsx";
import {
  assessStealth, scanForIdentifiers, makeArtifactLedger, recordArtifact,
  markRemoved, cleanupManifest, closeEngagement, NOISE_CLASSES,
} from "./lib/opsecGuardian.js";

/* ================================================================
   VIEW: OPSEC — stealth gate, anonymity, no-traces close (HYPNOS)
   ================================================================ */

const PLAN = {
  phases: {
    recon: { maxNoise: 1 },
    exploitation: { maxNoise: 3 },
    "post-exploit": { maxNoise: 2 },
  },
};

export function OpsecView() {
  const [phase, setPhase] = useState("recon");
  const [noise, setNoise] = useState("low");
  const [pii, setPii] = useState(false);
  const [assess, setAssess] = useState(null);

  const [payload, setPayload] = useState('{"flags":"-sS -sV","hosts":["lab-api.g9.local"]}');
  const [identScan, setIdentScan] = useState(null);

  const ledger = useMemo(() => {
    const l = makeArtifactLedger({ engagementId: "ENG-REDLAB-7", evidenceStore: { encrypted: true, disposition: "handover-per-contract" } });
    recordArtifact(l, { id: "ART-1", kind: "session cookie (admin)", location: "lab-api: memory only", detectability: "target-invisible" });
    recordArtifact(l, { id: "ART-2", kind: "persistence marker", location: "lab-forensics:/var/.g9_marker", detectability: "target-visible" });
    recordArtifact(l, { id: "ART-3", kind: "dropped PoC binary", location: "lab-cms:/tmp/poc", detectability: "target-visible" });
    recordArtifact(l, { id: "ART-4", kind: "evidence bundle (sealed)", location: "evidence-store:bundle-7.zip", detectability: "operator-side" });
    return l;
  }, []);
  const [ledgerState, setLedgerState] = useState({ closed: false, log: [] });

  const runAssess = () => {
    setAssess(assessStealth({
      actionId: "ACT-OPSEC-DEMO", noiseClass: noise, opsecPlan: PLAN,
      phase, declaredNoise: noise, containsPII: pii, evidenceEncrypted: true,
    }));
  };

  const runIdent = () => {
    let parsed = payload;
    try { parsed = JSON.parse(payload); } catch { parsed = payload; }
    setIdentScan(scanForIdentifiers(parsed));
  };

  const clean = (id) => {
    try {
      markRemoved(ledger, { id, state: id === "ART-4" ? "retained-per-roe" : "removed", verifiedBy: id === "ART-4" ? "operator (RoE §evidence-handling)" : undefined });
      setLedgerState((s) => ({ ...s, log: [...s.log, `✓ ${id} → ${id === "ART-4" ? "retained-per-roe" : "removed"}`] }));
    } catch (e) {
      setLedgerState((s) => ({ ...s, log: [...s.log, `✕ ${id}: ${e.message}`] }));
    }
  };

  const tryClose = () => {
    const r = closeEngagement(ledger);
    setLedgerState((s) => ({
      ...s,
      closed: r.ok ? true : s.closed,
      log: [...s.log, r.ok ? "✓ engagement closed — no traces remain" : `✕ close refused: ${r.reason}`],
    }));
  };

  const manifest = cleanupManifest(ledger);

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-violet-500/40 bg-violet-500/10 p-4">
        <div className="text-[13px] font-black text-violet-200">HYPNOS — OPSEC GUARDIAN · stealth · privacy · anonymity · no traces</div>
        <div className="text-[11px] text-violet-200/80 mt-1 leading-relaxed">
          Every chain step and pre-execution action passes the stealth gate before dispatch, and the engagement close gate refuses to close while any artifact remains. Doctrine: stealth vs. speed is a decision per phase; loud validates detection (silence is a finding); operator identifiers never reach target-facing traffic; evidence is encrypted at rest and destroyed or handed over per contract.
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="Pre-action stealth gate (live engine)">
          <div className="grid grid-cols-2 gap-2 text-[10.5px]">
            <label>
              <span className="text-slate-500">Phase (OPSEC plan: recon≤1 · exploitation≤3 · post-exploit≤2)</span>
              <select value={phase} onChange={(e) => setPhase(e.target.value)} className="mt-0.5 w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-800 font-mono">
                <option>recon</option><option>exploitation</option><option>post-exploit</option><option>cleanup</option>
              </select>
            </label>
            <label>
              <span className="text-slate-500">Noise class</span>
              <select value={noise} onChange={(e) => setNoise(e.target.value)} className="mt-0.5 w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-800 font-mono">
                {Object.entries(NOISE_CLASSES).map(([k, v]) => <option key={k} value={k}>{k} (d{v.detectability})</option>)}
              </select>
            </label>
            <label className="col-span-2 flex items-center gap-2 text-slate-400">
              <input type="checkbox" checked={pii} onChange={(e) => setPii(e.target.checked)} className="accent-red-500" />
              contains operator identifiers (anonymity violation)
            </label>
          </div>
          <button onClick={runAssess} className="mt-2 px-3 py-1.5 rounded bg-violet-600 hover:bg-violet-500 text-white text-[11px] font-bold">Assess action</button>
          {assess && (
            <div className={`mt-3 rounded-lg border p-2.5 text-[11px] ${assess.ok ? "border-emerald-500/40 bg-emerald-500/5" : "border-red-500/40 bg-red-500/5"}`}>
              <div className={`font-black uppercase ${assess.ok ? "text-emerald-300" : "text-red-300"}`}>{assess.verdict} · noise {assess.noiseClass} (d{assess.detectability})</div>
              <div className="text-slate-400 mt-0.5">{assess.note}</div>
              {assess.violations.map((v, i) => <div key={i} className="text-red-300/90 mt-0.5">⛔ {v}</div>)}
            </div>
          )}
          <div className="mt-2 text-[10px] text-slate-500 leading-relaxed">Try: loud noise in recon phase (held — exceeds ceiling), any action in the unplanned "cleanup" phase (held — Phase 0 plan incomplete), or the identifier checkbox (held — anonymity violation).</div>
        </Panel>

        <Panel title="Operator anonymity scan (live engine)">
          <label className="text-[10px] font-bold tracking-widest text-slate-500 uppercase">Tool-call payload (JSON)</label>
          <textarea value={payload} onChange={(e) => setPayload(e.target.value)} rows={4} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono focus:border-violet-500/50 outline-none" />
          <div className="flex flex-wrap gap-1 mt-2">
            {[
              ['{"contact":"me@example.com"}'],
              ['{"run_as":"hackytacky"}'],
              ['{"who":"John Smith"}'],
            ].map(([p]) => (
              <button key={p} onClick={() => setPayload(p)} className="px-2 py-1 rounded text-[10px] font-bold border bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200">{p.slice(0, 28)}</button>
            ))}
          </div>
          <button onClick={runIdent} className="mt-2 px-3 py-1.5 rounded bg-violet-600 hover:bg-violet-500 text-white text-[11px] font-bold">Scan for identifiers</button>
          {identScan && (
            <div className={`mt-3 rounded-lg border p-2.5 text-[11px] ${identScan.clean ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-300" : "border-red-500/40 bg-red-500/5 text-red-300"}`}>
              {identScan.clean ? "✓ clean — no operator-identifying material in the payload" : `✕ ${identScan.hits.length} identifier pattern(s) detected — strip before dispatch`}
            </div>
          )}
          <div className="mt-2 text-[10px] text-slate-500">Red tier runs local models only: no external LLM call ever carries engagement context.</div>
        </Panel>
      </div>

      <Panel title="No-traces cleanup ledger — engagement close gate (live engine)">
        <div className="text-[11px] text-slate-500 mb-3">
          Every artifact recorded at creation. Close is blocked while anything is <span className="font-mono text-amber-300">present</span>. Retention requires an explicit RoE citation. Manifest: <span className="text-slate-300 font-bold">{manifest.cleaned}/{manifest.total} cleaned</span> · evidence disposition: <span className="font-mono text-slate-400">{manifest.evidenceDisposition}</span>
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2">
          {[...ledger.artifacts.values()].map((a) => (
            <div key={a.id} className={`rounded-lg border p-2.5 ${a.state === "present" ? "border-amber-500/40 bg-amber-500/5" : "border-emerald-500/30 bg-emerald-500/5"}`}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-[10px] text-slate-500">{a.id}</span>
                <span className={`ml-auto px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${a.state === "present" ? "bg-amber-500/15 text-amber-300 border-amber-500/40" : "bg-emerald-500/15 text-emerald-300 border-emerald-500/40"}`}>{a.state}</span>
              </div>
              <div className="text-[11px] text-slate-200 mt-0.5">{a.kind}</div>
              <div className="text-[10px] text-slate-500 font-mono">{a.location}</div>
              {a.state === "present" && (
                <button onClick={() => clean(a.id)} className="mt-1.5 px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[9px] font-bold">
                  {a.id === "ART-4" ? "retain per RoE" : "verify removal"}
                </button>
              )}
            </div>
          ))}
        </div>
        <button onClick={tryClose} className="mt-3 px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-[11px] font-bold">
          {manifest.canClose ? "Close engagement (will pass)" : "Try close (must refuse while artifacts remain)"}
        </button>
        <div className="mt-2 pt-2 border-t border-slate-800 space-y-0.5 font-mono text-[10.5px]">
          {ledgerState.log.length === 0 && <div className="text-slate-700">no cleanup actions yet</div>}
          {ledgerState.log.map((l, i) => (
            <div key={i} className={l.startsWith("✕") ? "text-red-300/90" : "text-emerald-300/80"}>{l}</div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
