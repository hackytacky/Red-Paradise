import React, { useEffect, useState } from "react";
import { Panel } from "./views1.jsx";
import { g9api } from "./lib/api.js";

/* ================================================================
   LIVE RUN — the real end-to-end mission against the loopback lab
   target. One click: POST /lab/run executes the full active chain
   (policy → budget/scope → lab-native adapters → real execution →
   evidence → candidates → deterministic verification) and the
   report renders here. No simulation: every number below comes
   from the backend's tamper-evident ledger and evidence graph.
   ================================================================ */

const SEV_COLOR = {
  high: "text-red-300 border-red-500/40 bg-red-500/10",
  medium: "text-amber-300 border-amber-500/40 bg-amber-500/10",
  info: "text-slate-300 border-slate-500/40 bg-slate-500/10",
  unknown: "text-slate-300 border-slate-500/40 bg-slate-500/10",
};

export function LiveRunView() {
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [apiUp, setApiUp] = useState(null);

  useEffect(() => {
    g9api.labArsenal().then((r) => setApiUp(!!r.ok));
  }, []);

  async function run() {
    setRunning(true);
    setError("");
    try {
      const r = await g9api.runLabMission();
      if (r.ok) setReport(r);
      else setError(r.reason || "run blocked");
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  }

  const findings = report?.findings_reproduced || [];
  const phases = report?.phases || [];

  return (
    <div className="space-y-4">
      <Panel title="⯑ Live Run — full active mission (real execution, loopback lab target)">
        <div className="text-[11px] text-slate-400 mb-3">
          Backend: <span className="font-mono text-slate-300">{g9api.base}</span>{" "}
          {apiUp === null && <span className="text-slate-600">checking…</span>}
          {apiUp === true && <span className="text-emerald-400 font-bold">online</span>}
          {apiUp === false && <span className="text-red-400 font-bold">offline — start it: cd backend && uv run uvicorn g9_backend.api:app --port 8700</span>}
          <div className="mt-1 text-slate-500">
            The lab target binds 127.0.0.1 with an ephemeral port. The run executes:
            policy (deny-by-default) → budget/scope → lab-native adapters → real probes →
            evidence collector → CANDIDATE findings only → deterministic Verification
            Authority (independent re-probe; a candidate that does not reproduce stays a
            candidate). Ledger is hash-chained and verified in the report.
          </div>
        </div>
        <button
          onClick={run}
          disabled={running}
          className={`px-4 py-2 rounded-lg text-[12px] font-bold ${running ? "bg-slate-700 text-slate-400" : "bg-red-600 hover:bg-red-500 text-white"}`}
        >
          {running ? "RUNNING — full active chain…" : "▶ RUN FULL ACTIVE MISSION"}
        </button>
        {error && <div className="mt-3 px-3 py-2 rounded bg-red-500/10 border border-red-500/40 text-red-300 text-[11px] font-mono">{error}</div>}
      </Panel>

      {report && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            {[
              ["candidates", report.candidates, "text-slate-200"],
              ["reproduced", report.reproduced, "text-emerald-300"],
              ["evidence nodes", report.nodes, "text-cyan-300"],
              ["ledger records", report.ledger_records, "text-violet-300"],
              ["tokens spent", report.tokens_used, "text-amber-300"],
              ["ledger verified", report.ledger_verified ? "YES" : "NO", report.ledger_verified ? "text-emerald-300" : "text-red-300"],
            ].map(([label, value, cls]) => (
              <div key={label} className="rounded-lg bg-slate-900/70 border border-slate-800 px-3 py-2">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">{label}</div>
                <div className={`text-lg font-black ${cls}`}>{String(value)}</div>
              </div>
            ))}
          </div>

          <Panel title="⯑ Reproduced findings (Verification Authority — never the scanner's word)">
            <div className="space-y-1.5">
              {findings.map((f) => (
                <div key={f.id} className="flex items-center gap-3 px-3 py-2 rounded border text-[11px] font-mono">
                  <span className={`px-2 py-0.5 rounded border font-black uppercase ${SEV_COLOR[f.severity] || SEV_COLOR.unknown}`}>{f.severity}</span>
                  <span className="text-slate-200 font-bold">{f.template}</span>
                  <span className="text-slate-500 truncate">{f.host}</span>
                  <span className="ml-auto text-emerald-300 text-[10px] font-bold">REPRODUCED ✓</span>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="⯑ Phase ledger — every invocation through the gates">
            <div className="font-mono text-[10.5px] space-y-1">
              {phases.map((p) => (
                <div key={p.phase} className="text-slate-400">
                  <span className="text-slate-200 font-bold">{p.phase}</span>
                  {p.invocations.map((inv, i) => (
                    <div key={i} className={inv.ok ? "text-emerald-300/80" : "text-red-300/90"}>
                      {"  "}· {inv.tool} → {inv.target} {inv.ok ? "CLEARED" : `BLOCKED at ${inv.blocked_at}: ${inv.reason || (inv.reasons || []).join("; ")}`}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
