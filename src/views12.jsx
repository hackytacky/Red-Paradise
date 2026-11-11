import React, { useEffect, useRef, useState } from "react";
import { Panel } from "./views1.jsx";
import { g9api } from "./lib/api.js";

/* ================================================================
   MISSION CONSOLE — watch the autonomous run LIVE: every decision,
   gate, execution, and verification step as it happens.
   Polls GET /lab/events once per second while a mission runs.
   ================================================================ */

const KIND_STYLE = {
  thinking: { icon: "◆", cls: "text-cyan-300", label: "DECISION" },
  gate: { icon: "⛨", cls: "text-amber-300", label: "GATE" },
  execution: { icon: "▶", cls: "text-red-300", label: "EXECUTE" },
  finding: { icon: "★", cls: "text-emerald-300", label: "FINDING" },
  phase: { icon: "❯", cls: "text-slate-400", label: "PHASE" },
  ledger: { icon: "⛓", cls: "text-violet-300", label: "LEDGER" },
};

export function MissionConsoleView() {
  const [mode, setMode] = useState("autonomous");
  const [planner, setPlanner] = useState("rulebook");
  const [running, setRunning] = useState(false);
  const [events, setEvents] = useState([]);
  const [done, setDone] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const cursor = useRef(0);
  const boxRef = useRef(null);

  useEffect(() => {
    if (!running) return;
    const iv = setInterval(async () => {
      const r = await g9api.labEvents(cursor.current);
      if (!r.ok) return;
      if (r.events.length) {
        setEvents((e) => [...e, ...r.events]);
        cursor.current = r.next;
        if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
      }
      if (r.done) {
        setRunning(false);
        setDone(true);
        if (r.error) setError(r.error);
        if (r.report) setReport(r.report);
      }
    }, 1000);
    return () => clearInterval(iv);
  }, [running]);

  const [confirming, setConfirming] = useState(false);

  async function start() {
    setEvents([]); setDone(false); setReport(null); setError("");
    cursor.current = 0;
    const r = await g9api.quickstart(mode, planner);
    if (r.ok && r.launch && r.launch.ok) setRunning(true);
    else setError((r.launch && r.launch.reason) || r.reason || "failed to start");
  }

  const counts = events.reduce((a, e) => { a[e.kind] = (a[e.kind] || 0) + 1; return a; }, {});

  return (
    <div className="space-y-4">
      <Panel title="⯈ Mission Console — live decision / gate / execution / verification stream">
        <div className="flex flex-wrap items-center gap-3 mb-3">
          <div className="flex items-center gap-1 text-[11px]">
            <span className="text-slate-500 font-bold uppercase tracking-wider">mode</span>
            {["autonomous", "hitl", "manual"].map((m) => (
              <button key={m} onClick={() => setMode(m)} disabled={running}
                className={`px-2.5 py-1 rounded text-[11px] font-bold border ${mode === m ? "bg-cyan-600/20 text-cyan-200 border-cyan-500/50" : "text-slate-400 border-slate-700 hover:bg-slate-800"}`}>
                {m === "hitl" ? "human-in-the-loop" : m}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1 text-[11px]">
            <span className="text-slate-500 font-bold uppercase tracking-wider">brain</span>
            {[["rulebook", "rulebook (deterministic)"], ["llm", "local LLM (G9_LLM_ENDPOINT)"]].map(([p, label]) => (
              <button key={p} onClick={() => setPlanner(p)} disabled={running}
                className={`px-2.5 py-1 rounded text-[11px] font-bold border ${planner === p ? "bg-fuchsia-600/20 text-fuchsia-200 border-fuchsia-500/50" : "text-slate-400 border-slate-700 hover:bg-slate-800"}`}>
                {label}
              </button>
            ))}
          </div>
          <button onClick={() => setConfirming(true)} disabled={running}
            className={`px-4 py-2 rounded-lg text-[12px] font-bold ${running ? "bg-slate-700 text-slate-400" : "bg-red-600 hover:bg-red-500 text-white"}`}>
            {running ? "● MISSION RUNNING — streaming below…" : "⚡ QUICK START TEST"}
          </button>
          {confirming && !running && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
              <div className="max-w-md w-full mx-4 rounded-xl border border-red-500/40 bg-slate-950 p-5 space-y-3">
                <div className="text-[14px] font-black text-red-300">QUICK START — full autonomous lab test?</div>
                <div className="text-[11px] text-slate-400 leading-relaxed">
                  One click creates the lab engagement and runs the whole mission:
                  loopback lab target · lab RoE pre-signed · all lab tools granted ·
                  mode <span className="text-cyan-300 font-bold">{mode}</span> · brain{" "}
                  <span className="text-fuchsia-300 font-bold">{planner === "llm" ? "local LLM" : "rulebook"}</span>.
                  Every action still passes policy → budget → verification, and the
                  hash-chained ledger records everything.
                </div>
                <div className="flex gap-2 justify-end pt-1">
                  <button onClick={() => setConfirming(false)} className="px-4 py-2 rounded-lg text-[12px] font-bold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">NO</button>
                  <button onClick={() => { setConfirming(false); start(); }} className="px-4 py-2 rounded-lg text-[12px] font-bold bg-red-600 hover:bg-red-500 text-white">YES — RUN IT</button>
                </div>
              </div>
            </div>
          )}
          <span className={`text-[11px] font-bold ${running ? "text-emerald-400 animate-pulse" : done ? "text-slate-400" : "text-slate-600"}`}>
            {running ? "LIVE" : done ? "COMPLETE" : "idle"}
          </span>
          {Object.entries(counts).map(([k, n]) => (
            <span key={k} className={`text-[10px] font-mono ${KIND_STYLE[k]?.cls || "text-slate-500"}`}>
              {KIND_STYLE[k]?.label || k}: {n}
            </span>
          ))}
        </div>
        {error && <div className="mb-2 px-3 py-2 rounded bg-red-500/10 border border-red-500/40 text-red-300 text-[11px] font-mono">{error}</div>}

        <div ref={boxRef} className="h-[420px] overflow-y-auto rounded-lg bg-black/70 border border-slate-800 p-3 space-y-1 font-mono text-[11px]">
          {events.length === 0 && !running && (
            <div className="text-slate-700">press START — every policy verdict, autonomy decision, real execution, and verification re-probe streams here in real time</div>
          )}
          {events.map((e, i) => {
            const st = KIND_STYLE[e.kind] || KIND_STYLE.phase;
            return (
              <div key={i} className="flex items-start gap-2">
                <span className="text-slate-700 shrink-0">{new Date(e.t * 1000).toLocaleTimeString()}</span>
                <span className={`shrink-0 font-black ${st.cls}`}>{st.icon} {st.label}</span>
                <span className={st.cls}>{e.msg}</span>
              </div>
            );
          })}
        </div>
      </Panel>

      {report && (
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
      )}
    </div>
  );
}
