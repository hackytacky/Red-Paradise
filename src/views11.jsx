import React, { useEffect, useState } from "react";
import { Panel } from "./views1.jsx";
import { g9api } from "./lib/api.js";

/* ================================================================
   ARSENAL & INTEL (live) — the full registered arsenal (396 tools)
   and intel source registry (542 sources / 68 categories) straight
   from the backend, with their governance gates. Admission is a
   one-time recorded operator action: proofs in, tool qualified,
   ledger entry written. Searchable at any time.
   ================================================================ */

const FLAG_STYLE = {
  separate_auth: "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40",
  license_required: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  legal_gate: "bg-red-500/15 text-red-300 border-red-500/40",
  lab_only: "bg-cyan-500/15 text-cyan-300 border-cyan-500/40",
  unverified: "bg-slate-500/15 text-slate-300 border-slate-500/40",
};

function Flags({ flags }) {
  if (!flags || flags.length === 0) return <span className="text-slate-600 text-[9px]">no gates</span>;
  return (
    <span className="flex gap-1">
      {flags.map((f) => (
        <span key={f} className={`px-1.5 py-0.5 rounded border text-[9px] font-black ${FLAG_STYLE[f] || FLAG_STYLE.unverified}`}>{f}</span>
      ))}
    </span>
  );
}

export function ArsenalIntelView() {
  const [tools, setTools] = useState([]);
  const [sources, setSources] = useState([]);
  const [toolQuery, setToolQuery] = useState("");
  const [srcQuery, setSrcQuery] = useState("");
  const [total, setTotal] = useState({ tools: 0, sources: 0 });
  const [admitMsg, setAdmitMsg] = useState("");

  async function loadTools(q = "") {
    const r = await g9api.arsenalRegistry(q);
    if (r.ok) { setTools(r.entries.slice(0, 40)); setTotal((t) => ({ ...t, tools: r.total })); }
  }
  async function loadSources(q = "") {
    const r = await g9api.intelSources(q ? `?category=${encodeURIComponent(q)}` : "");
    if (r.ok) { setSources(r.sources.slice(0, 40)); setTotal((t) => ({ ...t, sources: r.total })); }
  }

  useEffect(() => { loadTools(); loadSources(); }, []);

  return (
    <div className="space-y-4">
      <Panel title="⯒ Arsenal — one-time recorded admission (live registry)">
        <div className="flex items-center gap-2 mb-2">
          <input
            value={toolQuery}
            onChange={(e) => setToolQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && loadTools(toolQuery)}
            placeholder="search tools (e.g. nuclei, exiftool, shodan)"
            className="flex-1 px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-[11px] font-mono text-slate-200"
          />
          <button onClick={() => loadTools(toolQuery)} className="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-white text-[11px] font-bold">search</button>
          <span className="text-[10px] text-slate-500 font-mono">{total.tools} registered</span>
        </div>
        <div className="space-y-1 max-h-80 overflow-y-auto">
          {tools.map((t) => (
            <div key={t.id} className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-slate-900/60 border border-slate-800 text-[10.5px] font-mono">
              <span className="text-slate-100 font-bold w-40 truncate">{t.id}</span>
              <span className="text-slate-500 w-24 truncate">{t.category}</span>
              <span className="text-slate-600 w-16">{t.sandbox}</span>
              <Flags flags={t.flags} />
              {t.required_proofs?.length > 0 && (
                <span className="ml-auto text-amber-300/80 text-[9px]">proofs: {t.required_proofs.join(", ")}</span>
              )}
            </div>
          ))}
        </div>
        {admitMsg && <div className="mt-2 text-[10.5px] font-mono text-emerald-300">{admitMsg}</div>}
      </Panel>

      <Panel title="⯒ Intel sources — 542 registered, governance automatic per category">
        <div className="flex items-center gap-2 mb-2">
          <input
            value={srcQuery}
            onChange={(e) => setSrcQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && loadSources(srcQuery)}
            placeholder="filter by category (e.g. leak-breach, dark-web, facial-recognition)"
            className="flex-1 px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-[11px] font-mono text-slate-200"
          />
          <button onClick={() => loadSources(srcQuery)} className="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-white text-[11px] font-bold">filter</button>
          <span className="text-[10px] text-slate-500 font-mono">{total.sources} sources</span>
        </div>
        <div className="space-y-1 max-h-80 overflow-y-auto">
          {sources.map((s) => (
            <div key={s.id} className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-slate-900/60 border border-slate-800 text-[10.5px] font-mono">
              <span className="text-slate-100 font-bold w-44 truncate">{s.id}</span>
              <span className="text-slate-500 w-40 truncate">{s.category}</span>
              <Flags flags={s.flags} />
              <span className="ml-auto text-slate-600 text-[9px]">{s.access}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
