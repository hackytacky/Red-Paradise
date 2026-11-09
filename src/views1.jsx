import React, { useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import {
  SEV_ORDER, SEV_STYLE, STATUS_STYLE, KIND_STYLE, NODE_STYLE,
  AGENTS, PLANNING_DOCS,
} from "./data.js";

export function SevBadge({ sev }) {
  return <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase border ${SEV_STYLE[sev]}`}>{sev}</span>;
}
export function StatusBadge({ status }) {
  return <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase border ${STATUS_STYLE[status]}`}>{status}</span>;
}
export function Panel({ title, right, children, className }) {
  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur ${className || ""}`}>
      {title && (
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800">
          <h3 className="text-xs font-bold tracking-widest text-slate-400 uppercase">{title}</h3>
          {right}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}
export function Stat({ label, value, sub, tone }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-[10px] font-bold tracking-widest text-slate-500 uppercase">{label}</div>
      <div className={`mt-1 text-2xl font-bold ${tone || "text-slate-100"}`}>{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-slate-500">{sub}</div>}
    </div>
  );
}
export function Section({ label, children }) {
  return (
    <div>
      <div className="text-[10px] font-bold tracking-widest text-slate-600 uppercase mb-0.5">{label}</div>
      <div className="text-[12px] text-slate-300 leading-relaxed">{children}</div>
    </div>
  );
}

/* ================================================================
   VIEW: Mission Control
   ================================================================ */

export function MissionControl({ mission, stats, sevCount, verifiedCount, zeroDayCount, chart, feed, running, redLocked, onSign, onEngage, approvals }) {
  const pending = approvals.filter((a) => a.status === "pending").length;
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-800 bg-gradient-to-r from-slate-900 to-slate-900/40 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div>
            <div className="text-[10px] tracking-widest text-slate-500 uppercase font-bold">Active mission</div>
            <div className="text-lg font-black text-slate-100">{mission.name}</div>
            <div className="text-[11px] text-slate-500">{mission.env} · scope: {mission.scope}</div>
          </div>
          <div className="ml-auto flex gap-2">
            {!mission.roeSigned ? (
              <button onClick={onSign} className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-bold">Sign RoE & Unlock Red Tier</button>
            ) : (
              <button onClick={onEngage} className={`px-4 py-2 rounded-lg text-sm font-bold ${running ? "bg-amber-600 hover:bg-amber-500 text-white" : "bg-emerald-600 hover:bg-emerald-500 text-white"}`}>
                {running ? "Pause Swarm" : "Engage Swarm (24/7)"}
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
        <Stat label="Hosts enumerated" value={stats.hosts} sub="lab range" />
        <Stat label="Subdomains mapped" value={stats.subdomains} sub="passive-first" />
        <Stat label="Requests (scoped)" value={stats.requests.toLocaleString()} sub="via egress proxy" />
        <Stat label="Verified findings" value={verifiedCount} tone="text-emerald-300" sub={`${zeroDayCount} zero-day class`} />
        <Stat label="Critical / High" value={`${sevCount.critical} / ${sevCount.high}`} tone="text-red-300" sub="sev-graded by rubric" />
        <Stat label="Cost so far" value={`$${stats.cost}`} sub="local GPU · per-verified-chain accounting" />
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <Panel title="Continuous cycle activity (live)" className="lg:col-span-2">
          <div className="h-48">
            <ResponsiveContainer>
              <AreaChart data={chart}>
                <defs>
                  <linearGradient id="ev" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="fd" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" hide />
                <YAxis hide />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="events" stroke="#06b6d4" fill="url(#ev)" strokeWidth={2} name="swarm events" />
                <Area type="monotone" dataKey="finds" stroke="#f59e0b" fill="url(#fd)" strokeWidth={2} name="finding triages" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 flex gap-4 text-[11px] text-slate-500">
            <span><span className="inline-block w-2 h-2 rounded-full bg-cyan-400 mr-1" />recon/scan events</span>
            <span><span className="inline-block w-2 h-2 rounded-full bg-amber-400 mr-1" />finding triages</span>
            <span className="ml-auto">Pipeline: PANOPTES → per-vector HYDRAs → ARGUS/TALOS discovery union → CHIMERA chains → CERBERUS verify → CALLIOPE report</span>
          </div>
        </Panel>

        <Panel title="Gate & approvals" right={pending > 0 ? <span className="text-[11px] px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/40 font-bold">{pending} pending</span> : null}>
          <div className="space-y-2">
            {redLocked ? (
              <div className="text-[12px] text-slate-400 space-y-2">
                <p>Red tier is at the authorization gate. Passive recon (PANOPTES) and threat-intel watch (METIS) run without it; <span className="text-red-300 font-semibold">no offensive action executes</span> until you sign the RoE.</p>
                <NavLink to="/mission" className="inline-block px-3 py-1.5 rounded bg-red-600 text-white text-xs font-bold">Review & sign RoE</NavLink>
              </div>
            ) : (
              <ul className="text-[11px] space-y-1.5">
                <li className="flex justify-between"><span className="text-slate-500">Lab-plane</span><span className="text-emerald-300 font-bold">auto (guest blast radius)</span></li>
                <li className="flex justify-between"><span className="text-slate-500">Host-plane</span><span className="text-amber-300 font-bold">per-action approval</span></li>
                <li className="flex justify-between"><span className="text-slate-500">Fail-safe</span><span className="text-slate-300">no response = deny</span></li>
                <li className="flex justify-between"><span className="text-slate-500">Verdicts</span><span className="text-emerald-300">code-enforced</span></li>
              </ul>
            )}
            <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500">The swarm never self-grades: every exploit success is a deterministic CERBERUS post-condition check.</div>
          </div>
        </Panel>
      </div>

      <Panel title="Latest swarm activity">
        <div className="space-y-1 max-h-64 overflow-y-auto pr-2">
          {feed.slice(-14).reverse().map((e) => (
            <div key={e.id} className="flex gap-2 text-[12px] py-1 border-b border-slate-800/50">
              <span className="text-slate-600 w-10 shrink-0">{String(e.t).padStart(4, "0")}s</span>
              <span className={`font-bold w-24 shrink-0 ${KIND_STYLE[e.kind]}`}>{e.greek}</span>
              <span className="text-slate-300">{e.msg}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ================================================================
   VIEW: Mission setup / RoE
   ================================================================ */

export function MissionSetup({ mission, onSign, redLocked, onEngage, running }) {
  const [name, setName] = useState(mission.name);
  const [scope, setScope] = useState(mission.scope);
  const [objectives, setObjectives] = useState(mission.objectives);
  const [ack, setAck] = useState(false);
  const [ack2, setAck2] = useState(false);
  return (
    <div className="space-y-4">
      <Panel title="Engagement governance — Phase 0 (before anything)">
        <div className="grid md:grid-cols-2 gap-4">
          <div className="space-y-3">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-slate-500 uppercase">Mission name</label>
              <input value={name} onChange={(e) => setName(e.target.value)} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm focus:border-red-500/50 outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-slate-500 uppercase">Exact scope (allowlist — enforced by CERBERUS egress proxy)</label>
              <textarea value={scope} onChange={(e) => setScope(e.target.value)} rows={3} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono focus:border-red-500/50 outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-slate-500 uppercase">Success criteria (each defines the chain being hunted)</label>
              <textarea value={objectives} onChange={(e) => setObjectives(e.target.value)} rows={4} className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono focus:border-red-500/50 outline-none" />
            </div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-3">
            <div className="text-[11px] font-bold text-slate-300 uppercase tracking-widest">Rules of Engagement</div>
            <ul className="text-[12px] text-slate-400 space-y-1.5 list-disc pl-4">
              <li>Environment class: <span className="text-slate-200 font-semibold">{mission.env}</span> — disposable guests, standing tier authorization.</li>
              <li>Blast radius = guest. Host-plane mutations need per-action approval via HERMES (fail-safe: no response = deny).</li>
              <li>Evidence: contemporaneous, hashed, replayable; destroyed or handed over per contract at close.</li>
              <li>Minimal proof: demonstrate impact with the least data taken — one row, not the table.</li>
              <li>Loud validates detection, stealth simulates adversary — decided per phase, documented per chain.</li>
              <li>Cleanup manifest mandatory for any persistence exercised.</li>
              <li>Every reported finding is reproduced once on a clean session before it reaches the owner.</li>
            </ul>
            <label className="flex items-start gap-2 text-[12px] text-slate-300 cursor-pointer">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5 accent-red-500" />
              I am authorized for this scope, and objectives above are written as verifiable statements.
            </label>
            <label className="flex items-start gap-2 text-[12px] text-slate-300 cursor-pointer">
              <input type="checkbox" checked={ack2} onChange={(e) => setAck2(e.target.checked)} className="mt-0.5 accent-red-500" />
              I understand the red tier runs local models only and every action passes CERBERUS code gates.
            </label>
            <div className="flex gap-2 pt-1">
              <button disabled={!(ack && ack2) || !redLocked} onClick={onSign} className={`px-4 py-2 rounded-lg text-sm font-bold flex-1 ${ack && ack2 && redLocked ? "bg-red-600 hover:bg-red-500 text-white" : "bg-slate-800 text-slate-500 cursor-not-allowed"}`}>
                {redLocked ? "Sign RoE (unlock red tier)" : "RoE signed ✓"}
              </button>
              {!redLocked && (
                <button onClick={onEngage} className={`px-4 py-2 rounded-lg text-sm font-bold ${running ? "bg-amber-600 text-white" : "bg-emerald-600 hover:bg-emerald-500 text-white"}`}>
                  {running ? "Pause" : "Engage"}
                </button>
              )}
            </div>
          </div>
        </div>
      </Panel>

      <Panel title="Planning documents (Soundwave set — roe.json is operator-provisioned)">
        <div className="text-[11px] text-slate-500 mb-3">
          The agent team can <span className="text-slate-300 font-semibold">prepare</span> planning documents for review, but never rewrites <span className="font-mono text-slate-300">plan/roe.json</span> — an authorized operator provisions it. Workflows never broaden authorized scope.
        </div>
        <div className="grid sm:grid-cols-2 gap-2">
          {PLANNING_DOCS.map((d) => (
            <div key={d.file} className={`rounded-lg border p-2.5 ${d.present ? "border-emerald-500/30 bg-emerald-500/5" : "border-amber-500/30 bg-amber-500/5"}`}>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${d.present ? "bg-emerald-500/20 text-emerald-300" : "bg-amber-500/20 text-amber-300"}`}>{d.present ? "present" : "candidate"}</span>
                <span className="font-mono text-[11px] text-slate-200">{d.file}</span>
              </div>
              <div className="text-[10px] text-slate-500 mt-1">{d.purpose}</div>
              <div className="text-[10px] text-slate-600">owner: {d.owner}</div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Continuous mission doctrine (24/7 bug-bounty mode)">
        <div className="grid md:grid-cols-4 gap-3 text-[11px]">
          {[
            ["1 · Watch", "METIS streams advisories; PANOPTES maps deltas on the public surface. Passive only — no packets until RoE."],
            ["2 · Discover", "Per-vector HYDRAs enumerate in scope; ARGUS runs the discovery union (variant analysis + AI fuzzing); TALOS reverse-engineers anything opaque."],
            ["3 · Chain", "CHIMERA builds position→capability graphs and hunts shortest verified chains to each success criterion."],
            ["4 · Verify & report", "CERBERUS post-conditions grade every exploit; THEMIS seals evidence; CALLIOPE writes the owner-facing report with fixes + re-tests."],
          ].map(([h, b]) => (
            <div key={h} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
              <div className="font-bold text-red-300 text-[12px] mb-1">{h}</div>
              <div className="text-slate-400 leading-relaxed">{b}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ================================================================
   VIEW: Agent swarm
   ================================================================ */

export function SwarmView({ redLocked, findings }) {
  const [open, setOpen] = useState(null);
  const tiers = ["T1 Command", "T2 Oversight", "T3 Blue", "T5 Red", "T6 AI", "T7 Support", "Structural"];
  return (
    <div className="space-y-4">
      <Panel title="CT9 swarm — one pure expert per role · capability separation in code, not prompts">
        <div className="text-[11px] text-slate-500 mb-3">
          Oversight agents hold <span className="text-slate-300 font-semibold">no tools</span>. Red tier runs <span className="text-slate-300 font-semibold">local models only</span>, unreachable from production. Every agent message is typed, authenticated, logged and hashed by CERBERUS.
        </div>
        {redLocked && (
          <div className="mb-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-[12px] text-red-200 font-semibold">
            Red tier LOCKED (RoE unsigned) — red cards hold at the gate.
          </div>
        )}
        <div className="space-y-5">
          {tiers.map((tier) => (
            <div key={tier}>
              <div className="text-[10px] font-bold tracking-widest uppercase text-slate-600 mb-2">{tier}</div>
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2">
                {AGENTS.filter((a) => a.tier === tier).map((a) => {
                  const locked = a.red && redLocked;
                  return (
                    <button key={a.id} onClick={() => setOpen(open === a.id ? null : a.id)}
                      className={`text-left rounded-lg border p-3 transition ${locked ? "border-red-500/40 bg-red-500/5 opacity-80" : a.structural ? "border-emerald-500/30 bg-emerald-500/5" : "border-slate-800 bg-slate-950/60 hover:border-slate-600"}`}>
                      <div className="flex items-center justify-between">
                        <span className="font-black text-[13px] tracking-wide text-slate-100">{a.greek}</span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${locked ? "bg-red-500/20 text-red-300" : a.status === "working" ? "bg-emerald-500/20 text-emerald-300" : a.status === "verifying" ? "bg-amber-500/20 text-amber-300" : "bg-slate-700/50 text-slate-400"}`}>
                          {locked ? "locked" : a.status}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5 line-clamp-2">{a.role}</div>
                      {open === a.id && (
                        <div className="mt-2 pt-2 border-t border-slate-800 text-[10px] space-y-1">
                          <div><span className="text-slate-600">model:</span> <span className="text-slate-400 font-mono">{a.model}</span></div>
                          <div><span className="text-slate-600">tools (scoped, schema-validated):</span> <span className="text-slate-400 font-mono">{a.tools.length ? a.tools.join(", ") : "none — tool-less by design"}</span></div>
                          <div><span className="text-slate-600">findings touched:</span> <span className="text-slate-400">{findings.filter((f) => f.vector === (a.id === "hydra-web" ? "web" : a.id === "hydra-svc" ? "svc" : a.id === "hydra-ident" ? "ident" : a.id === "hydra-cloud" ? "cloud" : a.id === "hydra-ai" ? "ai" : a.id === "panoptes" ? "osint" : null)).length}</span></div>
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* ================================================================
   VIEW: Live feed
   ================================================================ */

export function FeedView({ feed, boxRef, running }) {
  const [filter, setFilter] = useState("all");
  const shown = feed.filter((e) => filter === "all" || e.kind === filter);
  return (
    <Panel title="Live operations feed — 24/7 continuous cycle" right={<span className="text-[10px] text-slate-500">{running ? "streaming" : "paused"}</span>}>
      <div className="flex flex-wrap gap-1 mb-3">
        {["all", ...Object.keys(KIND_STYLE)].map((k) => (
          <button key={k} onClick={() => setFilter(k)} className={`px-2.5 py-1 rounded text-[11px] font-bold border ${filter === k ? "bg-red-600/20 text-red-200 border-red-500/40" : "bg-slate-950 text-slate-500 border-slate-800 hover:text-slate-300"}`}>{k}</button>
        ))}
      </div>
      <div ref={boxRef} className="max-h-[62vh] overflow-y-auto rounded-lg bg-black/40 border border-slate-800 p-3 font-mono space-y-0.5">
        {shown.map((e) => (
          <div key={e.id} className="flex gap-2 text-[11.5px] leading-relaxed">
            <span className="text-slate-700 shrink-0">[{String(e.t).padStart(4, "0")}s]</span>
            <span className={`shrink-0 font-bold ${KIND_STYLE[e.kind]}`}>{e.greek}</span>
            <span className="text-slate-400">{e.msg}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* ================================================================
   VIEW: Chains
   ================================================================ */

export function ChainsView({ chains, selected, setSelected, redLocked }) {
  const chain = chains.find((c) => c.id === selected) || chains[0];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {chains.map((c) => (
          <button key={c.id} onClick={() => setSelected(c.id)} className={`px-3 py-2 rounded-lg text-left border text-[12px] ${selected === c.id ? "bg-red-600/15 border-red-500/40" : "bg-slate-950/60 border-slate-800 hover:border-slate-600"}`}>
            <div className="font-bold text-slate-200">{c.id} · {c.name}</div>
            <div className="text-[10px] text-slate-500">{c.status} · ${c.cost} est. · {c.findings.length} findings linked</div>
          </button>
        ))}
      </div>
      <Panel title={`Chain-state map — ${chain.name}`} right={<span className="text-[10px] text-slate-500">objective: {chain.objective}</span>}>
        {redLocked && <div className="mb-2 text-[11px] text-red-300">Red tier locked — chain display is read-only recon state until RoE is signed.</div>}
        <svg viewBox="0 0 720 300" className="w-full bg-black/30 rounded-lg border border-slate-800">
          {chain.edges.map(([a, b], i) => {
            const na = chain.nodes.find((n) => n.id === a);
            const nb = chain.nodes.find((n) => n.id === b);
            const active = na.verified && nb.verified;
            return (
              <line key={i} x1={na.x + 55} y1={na.y + 18} x2={nb.x - 5} y2={nb.y + 18}
                stroke={active ? "#10b981" : "#475569"} strokeWidth={active ? 2.5 : 1.5} strokeDasharray={active ? "" : "6 4"} />
            );
          })}
          {chain.nodes.map((n) => {
            const st = NODE_STYLE[n.type];
            return (
              <g key={n.id}>
                <rect x={n.x - 5} y={n.y - 12} width={130} height={60} rx={10}
                  fill={n.verified ? `${st.fill}22` : "#0f172a"} stroke={n.verified ? st.fill : "#475569"} strokeWidth={n.verified ? 2 : 1.2} strokeDasharray={n.verified ? "" : "5 4"} />
                <text x={n.x + 60} y={n.y + 4} textAnchor="middle" fontSize={10} fill={n.verified ? "#e2e8f0" : "#64748b"} fontFamily="monospace">
                  {n.label.split("\n").map((line, j) => (
                    <tspan key={j} x={n.x + 60} dy={j === 0 ? -2 : 12}>{line}</tspan>
                  ))}
                </text>
                <text x={n.x - 5} y={n.y - 16} fontSize={9} fill={st.fill} fontFamily="monospace">{st.icon} {n.type}</text>
              </g>
            );
          })}
        </svg>
        <div className="mt-3 grid md:grid-cols-3 gap-3 text-[11px]">
          <div className="rounded-lg border border-slate-800 p-3">
            <div className="font-bold text-slate-300 mb-1">Chain discipline</div>
            <div className="text-slate-500">Every link carries evidence + why it was necessary. The mission objective is the <span className="text-slate-300">shortest verified chain</span> per success criterion — loudness decided per link, documented.</div>
          </div>
          <div className="rounded-lg border border-slate-800 p-3">
            <div className="font-bold text-slate-300 mb-1">Linked findings</div>
            <div className="text-slate-500 font-mono">{chain.findings.join(" · ")}</div>
          </div>
          <div className="rounded-lg border border-slate-800 p-3">
            <div className="font-bold text-slate-300 mb-1">Economics</div>
            <div className="text-slate-500">Est. ${chain.cost} of local compute to full chain. Cost-per-verified-chain is a first-class metric — it decides automate vs. human.</div>
          </div>
        </div>
      </Panel>
    </div>
  );
}
