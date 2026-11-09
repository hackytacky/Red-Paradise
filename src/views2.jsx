import React, { useMemo, useState } from "react";
import {
  SEV_ORDER, OBJ_STATE_STYLE, WORKFLOW_PIN,
} from "./data.js";
import { SevBadge, StatusBadge, Panel, Section } from "./views1.jsx";

/* ================================================================
   VIEW: OPPLAN objectives (Decepticon DAG contract)
   ================================================================ */

export function OpplanView({ objectives, chains, findings }) {
  const byId = useMemo(() => Object.fromEntries(objectives.map((o) => [o.id, o])), [objectives]);
  const readiness = (o, seen = new Set()) => {
    if (o.state === "complete") return true;
    if (seen.has(o.id)) return false;
    seen.add(o.id);
    return o.deps.every((d) => byId[d] && readiness(byId[d], seen));
  };
  return (
    <div className="space-y-4">
      <Panel title="OPPLAN — the only execution task lifecycle (evidence-driven DAG, not a kill-chain ladder)">
        <div className="text-[11px] text-slate-500 mb-3 leading-relaxed">
          Readiness comes from <span className="text-slate-300 font-semibold">real dependency paths and evidence</span>, never a fixed recon → exploit sequence. Supplied source, captures or footholds can satisfy discovery; missing evidence creates a prerequisite. <span className="text-slate-300 font-semibold">Proof → independent verification → reporting</span> retain their dependencies per finding — a completed unrelated finding never satisfies another finding's verification.
        </div>
        <div className="space-y-2">
          {objectives.map((o) => {
            const chain = chains.find((c) => c.id === o.chain);
            const ready = readiness(o);
            return (
              <div key={o.id} className={`rounded-lg border p-3 ${o.state === "blocked" ? "border-red-500/40 bg-red-500/5" : "border-slate-800 bg-slate-950/60"}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] text-slate-500">{o.id}</span>
                  <span className="text-[13px] font-bold text-slate-100">{o.title}</span>
                  <span className={`ml-auto px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${OBJ_STATE_STYLE[o.state]}`}>
                    {o.state === "waiting" ? (ready ? "dispatch-ready" : "waiting on deps") : o.state}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-violet-500/15 text-violet-300 border border-violet-500/40">stage: {o.stage}</span>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-slate-500">
                  <span>deps: <span className="font-mono text-slate-400">{o.deps.length ? o.deps.join(", ") : "none"}</span></span>
                  {chain && <span>chain: <span className="font-mono text-slate-400">{chain.id} ({chain.status})</span></span>}
                </div>
                {o.evidence.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {o.evidence.map((ev, i) => (
                      <div key={i} className="flex gap-2 text-[11px]">
                        <span className={`font-bold shrink-0 ${ev.ok ? "text-emerald-400" : "text-red-400"}`}>{ev.ok ? "✓" : "✕"} {ev.kind}</span>
                        <span className="text-slate-400">{ev.ref}</span>
                      </div>
                    ))}
                  </div>
                )}
                {o.blockedBy && (
                  <div className="mt-2 rounded border border-amber-500/40 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-200">
                    ⛔ Blocked: {o.blockedBy}
                  </div>
                )}
              </div>
            );
          })}
        </div>
        <div className="mt-3 pt-3 border-t border-slate-800 text-[10px] text-slate-500 leading-relaxed">
          Dispatch contract: the orchestrator creates bounded objectives, selects eligible specialists, records dependencies and inspects real evidence before completion. A failed tool, missing artifact or blocked objective is not successful coverage. Objectives bind to the pinned workflow stage — the stage ID is not the objective ID.
        </div>
      </Panel>
      <Panel title="Coverage truth (no findings ≠ no work)">
        <div className="grid md:grid-cols-3 gap-3 text-[11px]">
          <div className="rounded-lg border border-slate-800 p-3">
            <div className="font-bold text-slate-300 mb-1">Tested surface</div>
            <div className="text-slate-500">{findings.length} findings across {new Set(findings.map((f) => f.vector)).size} vectors; {findings.filter((f) => f.status !== "candidate").length} passed deterministic verification.</div>
          </div>
          <div className="rounded-lg border border-slate-800 p-3">
            <div className="font-bold text-slate-300 mb-1">Negative results</div>
            <div className="text-slate-500">Paths tried and failed stay in internal notes — they inform detection and future retesting even when they never reach the report.</div>
          </div>
          <div className="rounded-lg border border-slate-800 p-3">
            <div className="font-bold text-slate-300 mb-1">Untested coverage & limits</div>
            <div className="text-slate-500">Every report states what was not tested and why (scope, authorization, environment limits) — silence about gaps is a finding against us.</div>
          </div>
        </div>
      </Panel>
    </div>
  );
}

/* ================================================================
   VIEW: Findings
   ================================================================ */

export function FindingsView({ findings, onVerify }) {
  const [sevF, setSevF] = useState("all");
  const [stF, setStF] = useState("all");
  const [sel, setSel] = useState(findings[0] ? findings[0].id : null);
  const shown = findings.filter((f) => (sevF === "all" || f.sev === sevF) && (stF === "all" || f.status === stF)).sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  const f = findings.find((x) => x.id === sel) || shown[0];
  return (
    <div className="space-y-4">
      <Panel title="Findings pipeline — candidates are hypotheses until CERBERUS verifies the post-condition">
        <div className="flex flex-wrap gap-1 mb-3">
          {["all", "critical", "high", "medium", "low", "info"].map((s) => (
            <button key={s} onClick={() => setSevF(s)} className={`px-2.5 py-1 rounded text-[11px] font-bold border ${sevF === s ? "bg-red-600/20 text-red-200 border-red-500/40" : "bg-slate-950 text-slate-500 border-slate-800"}`}>{s}</button>
          ))}
          <span className="w-2" />
          {["all", "candidate", "verified", "reported"].map((s) => (
            <button key={s} onClick={() => setStF(s)} className={`px-2.5 py-1 rounded text-[11px] font-bold border ${stF === s ? "bg-indigo-600/20 text-indigo-200 border-indigo-500/40" : "bg-slate-950 text-slate-500 border-slate-800"}`}>{s}</button>
          ))}
        </div>
        <div className="grid lg:grid-cols-2 gap-4">
          <div className="space-y-1.5 max-h-[62vh] overflow-y-auto pr-1">
            {shown.map((x) => (
              <button key={x.id} onClick={() => setSel(x.id)} className={`w-full text-left rounded-lg border p-3 ${sel === x.id ? "border-red-500/40 bg-red-600/10" : "border-slate-800 bg-slate-950/60 hover:border-slate-600"}`}>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-[10px] text-slate-500">{x.id}</span>
                  <SevBadge sev={x.sev} />
                  <StatusBadge status={x.status} />
                  {x.zeroDay && <span className="px-2 py-0.5 rounded text-[10px] font-black bg-fuchsia-500/15 text-fuchsia-300 border border-fuchsia-500/40">ZERO-DAY</span>}
                  <span className="ml-auto text-[10px] text-slate-600 font-mono">{x.vector}</span>
                </div>
                <div className="text-[12px] font-semibold text-slate-200 mt-1">{x.title}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">{x.target}</div>
              </button>
            ))}
          </div>
          {f && (
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-[11px] text-slate-500">{f.id}</span>
                <SevBadge sev={f.sev} /> <StatusBadge status={f.status} />
                {f.zeroDay && <span className="px-2 py-0.5 rounded text-[10px] font-black bg-fuchsia-500/15 text-fuchsia-300 border border-fuchsia-500/40">ZERO-DAY · no CVE assigned</span>}
              </div>
              <div className="text-sm font-bold text-slate-100">{f.title}</div>
              <div className="text-[11px] text-slate-500">target: <span className="font-mono text-slate-400">{f.target}</span> · vector: <span className="font-mono text-slate-400">{f.vector}</span></div>
              <Section label="Evidence">{f.evidence}</Section>
              <Section label="Deterministic PoV check (CERBERUS)"><span className="font-mono text-emerald-300">✓ {f.pov}</span> — no LLM grades its own exploit success.</Section>
              <Section label="Remediation (owner action)">{f.remediation}</Section>
              <Section label="Verification (prove the fix)">{f.verification}</Section>
              {f.status === "candidate" && (
                <button onClick={() => onVerify(f.id)} className="w-full px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold">
                  Run post-condition check → verify
                </button>
              )}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

/* ================================================================
   VIEW: CERBERUS gates
   ================================================================ */

export function GatesView({ approvals, gateLog, onDecide, mission }) {
  const pending = approvals.filter((a) => a.status === "pending");
  const decided = approvals.filter((a) => a.status !== "pending");
  const rules = [
    ["Scope enforcement", "Every tool call's target is matched against the RoE allowlist in the egress proxy. Out-of-scope = blocked, logged, tripwired."],
    ["Typed, authenticated messages", "Inter-agent messages validated against sender allowlists. An instruction its sender-type cannot issue = detected attack."],
    ["Post-condition grading", "Exploit success is a deterministic check (file read, shell, hash, body match). LLMs plan; CERBERUS grades."],
    ["Immutable workflow pin", "The execution workflow (id, version, full source, SHA-256) is pinned at dispatch; resumes keep the pin and conflicting pins fail closed. Chat messages or retrieved docs never become a trusted workflow selector."],
    ["Blast-radius caps", "Per-agent secrets from VAULT, injected at execution, never in model context. No shared keys."],
    ["Fail-safe approvals", "Host-plane actions need per-action approval of the exact arguments. No response or timeout = deny, never proceed."],
    ["Canary & tripwire layer", "Canary secrets and fake high-value tools in agent context; encoded payloads, out-of-scope hosts, context dumps are tripwires."],
    ["Memory integrity", "MNEMOSYNE versioned writes with rollback; canary memories; poisoned writes restore from checkpoint."],
    ["MANTIS self-test", "A standing adversary inside RED-LAB attacks the swarm itself (staged payloads, honeypot lures, reward hacking). Every win hardens a gate."],
  ];
  return (
    <div className="space-y-4">
      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="Approval queue — host-plane (per-action, exact arguments)">
          <div className="space-y-2">
            {pending.length === 0 && <div className="text-[12px] text-slate-500">No pending host-plane actions. Lab-plane runs on standing tier authorization (blast radius = guest).</div>}
            {pending.map((a) => (
              <div key={a.id} className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-3">
                <div className="flex items-center gap-2 text-[10px] mb-1">
                  <span className="font-bold text-amber-300">{a.agent}</span>
                  <span className="text-slate-600">plane: {a.plane} · risk: {a.risk}</span>
                  <span className="ml-auto text-slate-600 font-mono">{a.t}s</span>
                </div>
                <div className="text-[12px] text-slate-200">{a.action}</div>
                <div className="text-[10px] text-slate-500 font-mono mt-1">{a.args}</div>
                <div className="flex gap-2 mt-2">
                  <button onClick={() => onDecide(a.id, true)} className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-bold">Approve exact action</button>
                  <button onClick={() => onDecide(a.id, false)} className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-bold">Deny (fail-safe)</button>
                </div>
              </div>
            ))}
            {decided.slice(-5).reverse().map((a) => (
              <div key={a.id} className={`rounded-lg border p-2.5 text-[11px] ${a.status === "approved" ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-200" : "border-slate-700 bg-slate-950/60 text-slate-500"}`}>
                {a.status === "approved" ? "✓" : "✕"} {a.action} <span className="opacity-60">— {a.status}</span>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Load-bearing code policy — CERBERUS (deterministic) · AEGIS (LLM veto, advisory)">
          <div className="space-y-2">
            {rules.map(([h, b]) => (
              <div key={h} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="text-[11px] font-bold text-emerald-300">{h}</div>
                <div className="text-[11px] text-slate-400 leading-relaxed">{b}</div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
      <Panel title="Gate decision log (append-only, hashed, off-agent reach)">
        <div className="max-h-64 overflow-y-auto font-mono text-[11px] space-y-0.5">
          {gateLog.slice().reverse().map((g) => (
            <div key={g.id} className="flex gap-2"><span className="text-slate-700">[{String(g.t).padStart(4, "0")}s]</span><span className="text-emerald-300/80">{g.msg}</span></div>
          ))}
        </div>
        <div className="mt-2 text-[10px] text-slate-600">Active RoE: {mission.name} · {mission.window}</div>
      </Panel>
    </div>
  );
}

/* ================================================================
   VIEW: Owner report
   ================================================================ */

function buildReport(verified, chains, mission) {
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  verified.forEach((f) => (sev[f.sev] += 1));
  const sorted = verified.slice().sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  const L = [];
  L.push("# G9 RED-OPS — Engagement Report");
  L.push(`**Mission:** ${mission.name}`);
  L.push(`**Scope:** ${mission.scope}`);
  L.push(`**Environment:** ${mission.env}`);
  L.push(`**Authorization:** ${mission.window}`);
  L.push(`**Workflow pin:** ${WORKFLOW_PIN.id}@v${WORKFLOW_PIN.version} · sha256:${WORKFLOW_PIN.sha256.slice(0, 16)}… (immutable for this execution thread)`);
  L.push("");
  L.push("## Summary");
  L.push(`The autonomous swarm ran a continuous recon → discovery → chaining → verification cycle against the agreed scope. ` +
    `${verified.length} findings were verified by deterministic post-condition checks (never by model self-assessment) — ` +
    `${sev.critical} critical, ${sev.high} high, ${sev.medium} medium, ${sev.low} low. ` +
    `${verified.filter((f) => f.zeroDay).length} findings are novel vulnerability classes with no assigned CVE. Shortest verified attack chains and per-finding fixes are below.`);
  L.push("");
  L.push("## Attack-chain analysis");
  chains.forEach((c) => {
    L.push(`### ${c.id} — ${c.name}`);
    L.push(`Objective: ${c.objective} · Status: ${c.status} · Linked findings: ${c.findings.join(", ")}`);
    L.push("Path: " + c.nodes.map((n) => n.label.replace(/\n/g, " ")).join("  →  "));
    L.push("");
  });
  L.push("## Findings");
  sorted.forEach((f, i) => {
    L.push(`### ${i + 1}. [${f.sev.toUpperCase()}] ${f.title}`);
    L.push(`- **ID / vector / target:** ${f.id} · ${f.vector} · ${f.target}${f.zeroDay ? " · **zero-day (no CVE assigned)**" : ""}`);
    L.push(`- **Evidence:** ${f.evidence}`);
    L.push(`- **Verified by (deterministic):** ${f.pov}`);
    L.push(`- **Remediation:** ${f.remediation}`);
    L.push(`- **Verification (re-test):** ${f.verification}`);
    L.push("");
  });
  L.push("## Control gap analysis");
  const gaps = [];
  if (verified.some((f) => f.vector === "web" && f.title.includes("SQL"))) gaps.push("Input validation boundary missing at the data-access layer (injection class).");
  if (verified.some((f) => f.id === "F-0004")) gaps.push("Metadata service exposure: host-level egress controls absent on the app tier; IMDSv2 not enforced.");
  if (verified.some((f) => f.id === "F-0006")) gaps.push("Identity: no monitoring on delegation abuse paths; weak service-account hygiene.");
  if (verified.some((f) => f.vector === "ai")) gaps.push("AI governance: untrusted-content discipline absent at the agent gateway (tool descriptions, RAG corpus treated as trusted).");
  if (gaps.length === 0) gaps.push("Per-finding gaps listed in each remediation above.");
  gaps.forEach((g) => L.push(`- ${g}`));
  L.push("");
  L.push("## Purple-team package (for the defenders)");
  chains.forEach((c) => {
    L.push(`- ${c.id}: replay the chain above; expected telemetry: service error anomalies on ${c.nodes[1] ? "the foothold step" : "entry"}, identity-graph shortest-path alerts, canary activations on the agent gateway. Each replay must alert; silence is a detection finding.`);
  });
  L.push("");
  L.push("## Next steps");
  L.push("1. Fix in severity order; each remediation ships with its own verification step above — the re-test plan is the acceptance criterion.");
  L.push("2. Re-run this report's chains against the fixed environment; all post-condition checks must fail closed.");
  L.push("3. Add the shipped detection rules to monitoring before the next cycle begins.");
  L.push("");
  L.push("---");
  L.push("_Generated autonomously by CALLIOPE (G9). Evidence sealed and hashed by CERBERUS. Report reviewed under THEMIS evidence standards: every finding reproduced once on a clean session before delivery._");
  return L.join("\n");
}

export function ReportView({ findings, chains, mission, onMarkReported }) {
  const [sel, setSel] = useState(findings.filter((f) => f.status !== "candidate").map((f) => f.id));
  const verified = findings.filter((f) => sel.includes(f.id) && f.status !== "candidate");
  const [copied, setCopied] = useState(false);
  const md = useMemo(() => buildReport(verified, chains, mission), [sel, findings, chains, mission]);
  const toggle = (id) => setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const copy = async () => {
    try { await navigator.clipboard.writeText(md); setCopied(true); setTimeout(() => setCopied(false), 1800); } catch (e) { setCopied(false); }
  };
  return (
    <div className="space-y-4">
      <Panel title="CALLIOPE — owner-facing report builder" right={
        <div className="flex gap-2">
          <button onClick={copy} className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-bold">{copied ? "Copied ✓" : "Copy Markdown"}</button>
          <button onClick={onMarkReported} className="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-[11px] font-bold">Deliver & mark reported</button>
        </div>
      }>
        <div className="grid lg:grid-cols-3 gap-4">
          <div>
            <div className="text-[10px] font-bold tracking-widest text-slate-600 uppercase mb-2">Include verified findings ({sel.length})</div>
            <div className="space-y-1 max-h-[60vh] overflow-y-auto pr-1">
              {findings.filter((f) => f.status !== "candidate").map((f) => (
                <label key={f.id} className="flex items-start gap-2 rounded border border-slate-800 bg-slate-950/60 p-2 cursor-pointer hover:border-slate-600">
                  <input type="checkbox" checked={sel.includes(f.id)} onChange={() => toggle(f.id)} className="mt-0.5 accent-indigo-500" />
                  <span className="text-[11px]">
                    <span className="font-mono text-slate-500">{f.id} </span>
                    <SevBadge sev={f.sev} /> <span className="text-slate-300">{f.title.slice(0, 60)}…</span>
                  </span>
                </label>
              ))}
            </div>
          </div>
          <div className="lg:col-span-2">
            <div className="text-[10px] font-bold tracking-widest text-slate-600 uppercase mb-2">Preview (delivered to owners with fixes + re-test plan)</div>
            <pre className="max-h-[60vh] overflow-auto rounded-lg bg-black/40 border border-slate-800 p-4 text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap font-mono">{md}</pre>
          </div>
        </div>
      </Panel>
    </div>
  );
}

/* ================================================================
   VIEW: Setup & adapters
   ================================================================ */

export function SetupView() {
  const adapters = [
    ["nmap-scoped", "service sweep", "lab-plane", "nmap -sS -sV within scope allowlist; flags schema-validated"],
    ["httpx / ffuf", "web enumeration", "lab-plane", "content & vhost discovery; JS param mining"],
    ["nuclei-rules", "known-CVE triage", "lab-plane", "scanner hypotheses only — every hit hand-confirmed before it becomes a finding"],
    ["variant-analysis", "zero-day hunt (ARGUS)", "lab-plane", "Big-Sleep-style diff analysis + AI fuzz target generation (discovery union)"],
    ["ghidra-scoped-api", "reverse engineering (TALOS)", "lab-plane", "REA-style: constrained tool API — decompile/xrefs/rename; never ambient shell"],
    ["model-file-audit", "GGUF/safetensors RE", "lab-plane", "weight inspection, backdoor hunting, model diffing"],
    ["injection-corpus", "AI red teaming (HYDRA-AI)", "lab-plane", "standing corpus per ingest path; every control change re-runs it"],
    ["graph-paths", "identity graph", "lab-plane", "shortest-path search over collected enumeration"],
    ["egress-proxy", "policy enforcement", "structural", "allowlist destinations; block raw IPs, shorteners; decode & re-inspect URLs"],
    ["post-condition-check", "grading", "structural", "deterministic exploit-success checks; no LLM self-grading"],
  ];
  const models = [
    ["g9-32b-red-ft", "red tier (CHIMERA, HYDRAs)", "local · domain-fine-tuned", "exploit traces + chain logs + REA transcripts"],
    ["g9-judge-32b", "THEMIS / SOCRATES / EPIMETHEUS", "local · judge", "pre-Stage-1 benchmark gated"],
    ["g9-32b-re-ft", "TALOS reverse engineering", "local", "refusal-proof: no hosted-model dependency"],
    ["g9-14b-osint-ft", "PANOPTES recon", "local", "passive-intel corpus"],
    ["g9-32b-aired-ft", "HYDRA-AI", "local", "injection corpus + MCP attack lab"],
  ];
  return (
    <div className="space-y-4">
      <Panel title="Tool adapters (executed by CERBERUS only — the model never runs tools directly)">
        <div className="text-[11px] text-slate-500 mb-3">This canvas deployment is the control plane with simulated telemetry. On the G9 host, these adapters run for real inside RED-LAB guests, behind the same gates you see in this app.</div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-slate-500 text-left border-b border-slate-800">
                <th className="py-1.5 pr-3">Adapter</th><th className="pr-3">Purpose</th><th className="pr-3">Plane</th><th>Contract</th>
              </tr>
            </thead>
            <tbody>
              {adapters.map(([a, p, pl, c]) => (
                <tr key={a} className="border-b border-slate-800/50">
                  <td className="py-1.5 pr-3 font-mono text-slate-300">{a}</td>
                  <td className="pr-3 text-slate-400">{p}</td>
                  <td className="pr-3"><span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${pl === "structural" ? "bg-emerald-500/15 text-emerald-300" : "bg-slate-700/40 text-slate-300"}`}>{pl}</span></td>
                  <td className="text-slate-500">{c}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="Local model registry (red tier never calls external APIs)">
          <div className="space-y-2">
            {models.map(([m, u, t, d]) => (
              <div key={m} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[12px] text-cyan-300 font-bold">{m}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-bold">{t}</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">used by: {u}</div>
                <div className="text-[10px] text-slate-600">training data: {d}</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Continuous mission configuration">
          <div className="space-y-2 text-[11px]">
            {[
              ["Cadence", "24/7 continuous cycle; METIS advisory watch triggers re-scan of affected stack versions automatically."],
              ["Stealth doctrine", "Grey-box for coverage, black-box for tradecraft; loud runs validate DAEDALUS detections — silence is a finding."],
              ["Zero-day discipline", "Novel findings get no CVE claims — they carry evidence, gadget chains, PoV and disclosure notes only."],
              ["Reporting threshold", "Only CERBERUS-verified findings reach CALLIOPE. Candidates stay in the pipeline or die there."],
              ["Cleanup", "Any persistence exercised ships with a cleanup manifest; blue gets the removal package with the report."],
            ].map(([h, b]) => (
              <div key={h} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="font-bold text-slate-300">{h}</div>
                <div className="text-slate-400 leading-relaxed">{b}</div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
