import React, { useEffect, useMemo, useRef, useState } from "react";
import { MemoryRouter, Routes, Route, NavLink } from "react-router-dom";
import {
  WORKFLOW_PIN, AGENTS, OPPLAN, FINDINGS_SEED, FINDINGS_LATER,
  CHAINS, FEED_POOL, uid, rand, pick,
} from "./data.js";
import {
  MissionControl, MissionSetup, SwarmView, FeedView, ChainsView,
} from "./views1.jsx";
import {
  OpplanView, FindingsView, GatesView, ReportView, SetupView,
} from "./views2.jsx";
import { ArchitectureView } from "./views3.jsx";
import { EvidenceView } from "./views4.jsx";
import { ExecutionView } from "./views5.jsx";
import { ResilienceView } from "./views6.jsx";
import { ArsenalView } from "./views7.jsx";
import { OpsecView } from "./views8.jsx";
import { StandoutView } from "./views9.jsx";

/* ================================================================
   ROOT APP — G9 RED-OPS // CHIMERA COMMAND
   ================================================================ */

export default function App() {
  const [mission, setMission] = useState({
    name: "RED-LAB Range — G9 self-test #7",
    env: "RED-LAB (disposable guests)",
    scope: "10.10.0.0/24 · *.g9.local (lab namespace) · lab-agentgw MCP gateway",
    objectives: "1) Read payment records from lab tenant\n2) DA equivalence in lab forest\n3) Extract one canary secret via poisoned agent",
    roeSigned: false,
    window: "Standing tier authorization · blast radius = guest",
  });
  const [running, setRunning] = useState(false);
  const [tick, setTick] = useState(0);
  const [stats, setStats] = useState({ hosts: 18, subdomains: 47, requests: 128441, advisories: 96, cveMatches: 31, cost: 2.4 });
  const [findings, setFindings] = useState(FINDINGS_SEED.map((f) => ({ ...f })));
  const [laterIdx, setLaterIdx] = useState(0);
  const [feed, setFeed] = useState([
    { id: uid("ev"), t: 0, kind: "gate", greek: "CERBERUS", msg: "Control plane online. Red tier HOLD: RoE unsigned. Egress proxy armed." },
    { id: uid("ev"), t: 0, kind: "gate", greek: "ATLAS", msg: `Workflow snapshot pinned: ${WORKFLOW_PIN.id}@v${WORKFLOW_PIN.version} · sha256:${WORKFLOW_PIN.sha256.slice(0, 16)}… — immutable for this thread.` },
    { id: uid("ev"), t: 0, kind: "intel", greek: "METIS", msg: "Threat intel watch armed — advisory feed streaming (24/7)." },
  ]);
  const [approvals, setApprovals] = useState([
    { id: uid("ap"), t: 12, agent: "CHIMERA", action: "host-plane: write persistence marker to lab-forensics host", risk: "high", plane: "host", status: "pending", args: "target=lab-forensics.g9.local op=touch /var/.g9_marker" },
  ]);
  const [gateLog, setGateLog] = useState([
    { id: uid("gl"), t: 3, msg: "Lab-plane standing authorization verified (RED-LAB tier) — auto-execution permitted inside guests." },
    { id: uid("gl"), t: 4, msg: "Host-plane mutation requires HERMES-mediated human approval — per-action, exact arguments." },
    { id: uid("gl"), t: 5, msg: "AEGIS armed: veto-only. Code policy (CERBERUS) is load-bearing; LLM verdicts advisory." },
  ]);
  const [chart, setChart] = useState(() => Array.from({ length: 24 }, (_, i) => ({ t: i, events: 20 + Math.floor(Math.random() * 30), finds: 1 + Math.floor(Math.random() * 4) })));
  const [selectedChain, setSelectedChain] = useState("C-01");
  const feedBoxRef = useRef(null);
  const findingsRef = useRef(findings);
  useEffect(() => { findingsRef.current = findings; }, [findings]);

  const redLocked = !mission.roeSigned;

  /* ---- live simulation ---- */
  useEffect(() => {
    if (!running) return;
    const iv = setInterval(() => {
      setTick((t) => t + 1);
      setStats((s) => ({
        hosts: s.hosts + rand(0, 2),
        subdomains: s.subdomains + rand(0, 3),
        requests: s.requests + rand(400, 2600),
        advisories: s.advisories + (Math.random() < 0.15 ? 1 : 0),
        cveMatches: s.cveMatches + (Math.random() < 0.1 ? 1 : 0),
        cost: +(s.cost + rand(3, 18) / 100).toFixed(2),
      }));
      setChart((c) => [...c.slice(-29), { t: c.length, events: 20 + rand(10, 70), finds: 1 + rand(0, 5) }]);
      // feed event
      const tpl = pick(FEED_POOL);
      setFeed((f) => [
        ...f.slice(-199),
        { id: uid("ev"), t: tick + 1, kind: tpl.kind, greek: tpl.greek, msg: tpl.msg.replace("{t}", pick(["lab-api.g9.local", "lab-portal.g9.local", "staging.g9.local", "lab-shop.g9.local"])).replace("{n2}", String(rand(2, 40))).replace(/\{n\}/g, String(rand(3, 90))) },
      ]);
      // new candidate finding occasionally
      if (Math.random() < 0.22 && laterIdx < FINDINGS_LATER.length) {
        const nf = FINDINGS_LATER[laterIdx];
        setLaterIdx((i) => i + 1);
        setFindings((fs) => [...fs, { ...nf }]);
        setFeed((f) => [...f.slice(-199), { id: uid("ev"), t: tick + 1, kind: "finding", greek: "ARGUS", msg: `Candidate finding ${nf.id} triaged (${nf.sev}) — queued for CERBERUS PoV check.` }]);
      }
      // verify a candidate occasionally (deterministic post-condition, not LLM judgment)
      const candNow = findingsRef.current.filter((x) => x.status === "candidate");
      if (candNow.length > 0 && Math.random() < 0.3) {
        const c = pick(candNow);
        setFindings((fs) => fs.map((x) => (x.id === c.id ? { ...x, status: "verified" } : x)));
        setFeed((f) => [...f.slice(-199), { id: uid("ev"), t: tick + 1, kind: "gate", greek: "CERBERUS", msg: `Post-condition check PASSED for ${c.id} — "${c.pov}". Status → verified. No LLM self-grading.` }]);
      }
      // approval requests occasionally
      if (Math.random() < 0.12) {
        const acts = [
          { agent: "CHIMERA", action: "host-plane: install cleanup manifest hook on lab-hypervisor console", risk: "high", plane: "host", args: "op=register-hook manifest=cleanup_v3" },
          { agent: "HYDRA-CLOUD", action: "host-plane: export lab artifact bucket listing to evidence store", risk: "medium", plane: "host", args: "bucket=lab-artifacts op=list op=ship-evidence" },
          { agent: "TALOS", action: "host-plane: mutate RE workspace mount (add sample corpus)", risk: "medium", plane: "host", args: "mount=re-sandbox op=add-corpus n=3" },
        ];
        const a = pick(acts);
        setApprovals((ap) => [...ap, { id: uid("ap"), t: tick + 1, ...a, status: "pending" }]);
        setFeed((f) => [...f.slice(-199), { id: uid("ev"), t: tick + 1, kind: "gate", greek: "HERMES", msg: `Approval requested: ${a.action}. Fail-safe: no response = deny.` }]);
      }
    }, 2200);
    return () => clearInterval(iv);
  }, [running, tick, laterIdx]);

  useEffect(() => {
    if (feedBoxRef.current) feedBoxRef.current.scrollTop = feedBoxRef.current.scrollHeight;
  }, [feed]);

  const signRoe = () => {
    setMission((m) => ({ ...m, roeSigned: true }));
    setGateLog((g) => [...g, { id: uid("gl"), t: tick, msg: "RoE signed by operator via HERMES. Graduated authorization: lab-plane auto-run, host-plane per-action." }]);
    setFeed((f) => [...f, { id: uid("ev"), t: tick, kind: "gate", greek: "CERBERUS", msg: "RoE signature verified. RED TIER UNLOCKED inside lab scope. Blast radius = guest." }]);
  };
  const engage = () => {
    if (redLocked) return;
    setRunning((r) => !r);
    setFeed((f) => [...f, { id: uid("ev"), t: tick, kind: "gate", greek: "ATLAS", msg: !running ? "Swarm engaged: 24/7 continuous cycle started (recon → discovery → chain → verify → report)." : "Swarm paused by operator." }]);
  };
  const decide = (id, ok) => {
    setApprovals((ap) => ap.map((a) => (a.id === id ? { ...a, status: ok ? "approved" : "denied" } : a)));
    const ap = approvals.find((a) => a.id === id);
    setGateLog((g) => [...g, { id: uid("gl"), t: tick, msg: `${ok ? "APPROVED" : "DENIED"} — ${ap ? ap.action : ""}` }]);
    setFeed((f) => [...f, { id: uid("ev"), t: tick, kind: "gate", greek: "CERBERUS", msg: ok ? "Host-plane action released after human approval. Logged, hashed, replayable." : "Host-plane action DENIED. Fail-safe held. Chain re-planned around refusal." }]);
  };
  const verifyFinding = (id) => {
    setFindings((fs) => fs.map((f) => (f.id === id ? { ...f, status: "verified" } : f)));
    const f = findings.find((x) => x.id === id);
    setFeed((fd) => [...fd, { id: uid("ev"), t: tick, kind: "gate", greek: "CERBERUS", msg: `Post-condition check PASSED for ${id} — "${f ? f.pov : ""}". Status → verified.` }]);
  };
  const markReported = () => {
    setFindings((fs) => fs.map((f) => (f.status === "verified" ? { ...f, status: "reported" } : f)));
    setFeed((f) => [...f, { id: uid("ev"), t: tick, kind: "report", greek: "CALLIOPE", msg: "Owner report packaged: findings, chains, remediation, purple-team package delivered via HERMES." }]);
  };

  const sevCount = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => (c[f.sev] += 1));
    return c;
  }, [findings]);
  const verifiedCount = findings.filter((f) => f.status === "verified" || f.status === "reported").length;
  const zeroDayCount = findings.filter((f) => f.zeroDay).length;

  return (
    <MemoryRouter>
      <div className="min-h-screen bg-slate-950 text-slate-200 font-sans">
        {/* Top bar */}
        <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
          <div className="mx-auto max-w-7xl px-4 py-3 flex items-center gap-4">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-lg bg-red-600/20 border border-red-500/50 flex items-center justify-center">
                <span className="text-lg">🛡</span>
              </div>
              <div>
                <div className="text-sm font-black tracking-wide text-slate-100">G9 RED-OPS <span className="text-red-400">//</span> CHIMERA COMMAND</div>
                <div className="text-[10px] text-slate-500 tracking-widest uppercase">Autonomous red team swarm · CT9 control plane</div>
              </div>
            </div>
            <div className="ml-auto flex items-center gap-2 text-[11px]">
              <span title={`Immutable workflow pin — resumes keep this snapshot; a different workflow requires a new execution thread.\nsha256:${WORKFLOW_PIN.sha256}`}
                className="hidden lg:inline-block px-2 py-1 rounded border bg-violet-500/10 text-violet-300 border-violet-500/40 font-mono">
                PINNED {WORKFLOW_PIN.id}@v{WORKFLOW_PIN.version} · {WORKFLOW_PIN.sha256.slice(0, 8)}…
              </span>
              <span className={`px-2 py-1 rounded border font-bold ${redLocked ? "bg-red-500/15 text-red-300 border-red-500/50" : "bg-emerald-500/15 text-emerald-300 border-emerald-500/50"}`}>
                {redLocked ? "RED TIER: LOCKED" : "RED TIER: ARMED"}
              </span>
              <span className="hidden sm:inline-block px-2 py-1 rounded border bg-slate-800 text-slate-300 border-slate-700">CERBERUS: ENFORCING</span>
              <span className="hidden md:inline-block px-2 py-1 rounded border bg-slate-800 text-slate-300 border-slate-700">AEGIS: ARMED</span>
              <span className={`px-2 py-1 rounded border font-bold ${running ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/50" : "bg-slate-800 text-slate-400 border-slate-700"}`}>
                {running ? "● SCANNING 24/7" : "○ PAUSED"}
              </span>
            </div>
          </div>
        </header>

        {/* RoE gate banner */}
        {redLocked && (
          <div className="border-b border-red-500/40 bg-red-500/10">
            <div className="mx-auto max-w-7xl px-4 py-2 text-[12px] text-red-200 flex items-center gap-2">
              <span className="font-bold">⛔ AUTHORIZATION GATE:</span>
              Red tier is holding. No offensive action runs until the operator signs the Rules of Engagement. Passive recon & intel watch only.
              <NavLink to="/mission" className="ml-2 underline font-bold text-red-300">Sign RoE →</NavLink>
            </div>
          </div>
        )}

        <div className="mx-auto max-w-7xl px-4 py-4 flex gap-4">
          {/* Sidebar */}
          <nav className="hidden md:flex w-44 shrink-0 flex-col gap-1 sticky top-16 self-start">
            {[
              ["/", "Mission Control", "▣"],
              ["/swarm", "Agent Swarm", "⌘"],
              ["/feed", "Live Feed 24/7", "≡"],
              ["/chains", "Chain State", "⛓"],
              ["/opplan", "OPPLAN Objectives", "◈"],
              ["/findings", "Findings", "⚑"],
              ["/gates", "CERBERUS Gates", "⛨"],
              ["/report", "Owner Report", "▤"],
              ["/setup", "Setup & Adapters", "⚙"],
              ["/architecture", "SPECTRE Architecture", "◫"],
              ["/evidence", "Evidence Graph", "◈"],
              ["/execution", "Trusted Execution", "⛨"],
              ["/resilience", "Resilience & Scheduling", "⚠"],
              ["/arsenal", "Tool Arsenal", "⚒"],
              ["/opsec", "OPSEC · HYPNOS", "☾"],
              ["/standout", "Standout Capabilities", "★"],
            ].map(([to, label, icon]) => (
              <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => `flex items-center gap-2 px-3 py-2 rounded-lg text-[13px] font-semibold border ${isActive ? "bg-red-600/15 text-red-200 border-red-500/40" : "text-slate-400 border-transparent hover:bg-slate-900 hover:text-slate-200"}`}>
                <span className="w-4 text-center">{icon}</span> {label}
              </NavLink>
            ))}
            <div className="mt-4 px-3 py-2 rounded-lg bg-slate-900/60 border border-slate-800 text-[10px] text-slate-500 leading-relaxed">
              Uptime {Math.floor((tick * 2) / 60)}m {tick * 2 < 60 ? tick * 2 : (tick * 2) % 60}s<br />
              Agents online: {AGENTS.length}<br />
              Local models only on red tier.<br /> No external LLM calls.
            </div>
          </nav>

          {/* Content */}
          <main className="flex-1 min-w-0">
            <Routes>
              <Route path="/" element={<MissionControl mission={mission} stats={stats} sevCount={sevCount} verifiedCount={verifiedCount} zeroDayCount={zeroDayCount} chart={chart} feed={feed} running={running} redLocked={redLocked} onSign={signRoe} onEngage={engage} approvals={approvals} />} />
              <Route path="/mission" element={<MissionSetup mission={mission} onSign={signRoe} redLocked={redLocked} onEngage={engage} running={running} />} />
              <Route path="/swarm" element={<SwarmView redLocked={redLocked} findings={findings} />} />
              <Route path="/feed" element={<FeedView feed={feed} boxRef={feedBoxRef} running={running} />} />
              <Route path="/chains" element={<ChainsView chains={CHAINS} selected={selectedChain} setSelected={setSelectedChain} redLocked={redLocked} />} />
              <Route path="/opplan" element={<OpplanView objectives={OPPLAN} chains={CHAINS} findings={findings} />} />
              <Route path="/findings" element={<FindingsView findings={findings} onVerify={verifyFinding} />} />
              <Route path="/gates" element={<GatesView approvals={approvals} gateLog={gateLog} onDecide={decide} mission={mission} />} />
              <Route path="/report" element={<ReportView findings={findings} chains={CHAINS} mission={mission} onMarkReported={markReported} />} />
              <Route path="/setup" element={<SetupView />} />
              <Route path="/architecture" element={<ArchitectureView />} />
              <Route path="/evidence" element={<EvidenceView />} />
              <Route path="/execution" element={<ExecutionView />} />
              <Route path="/resilience" element={<ResilienceView />} />
              <Route path="/arsenal" element={<ArsenalView />} />
              <Route path="/opsec" element={<OpsecView />} />
              <Route path="/standout" element={<StandoutView />} />
            </Routes>
          </main>
        </div>

        <footer className="border-t border-slate-800 mt-6">
          <div className="mx-auto max-w-7xl px-4 py-3 flex flex-wrap items-center gap-3 text-[10px] text-slate-500">
            <span className="font-bold text-slate-400">G9 RED-OPS</span>
            <span>· Demo deployment: telemetry simulated. On the G9 host, the same gates drive real scoped tool adapters via CERBERUS.</span>
            <span>· Doctrine: capability separation in code · oversight holds no tools · verdicts enforced by CERBERUS · local models only on red tier.</span>
            <span>· Governance concepts adapted from Decepticon (workflow pinning · OPPLAN DAG · Soundwave planning docs).</span>
          </div>
        </footer>
      </div>
    </MemoryRouter>
  );
}
