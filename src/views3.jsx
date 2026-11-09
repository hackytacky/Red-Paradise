import React from "react";
import { Panel } from "./views1.jsx";

/* ================================================================
   VIEW: G9 SPECTRE Architecture
   ================================================================ */

const SPECTRE_DIAGRAM = `                      G9 SPECTRE
              Security Intelligence Platform
                           |
                 G9 Command Plane
               Scope / RoE / Approvals
                           |
                 G9 Agent Orchestrator
              LangGraph + Typed Contracts
                           |
              ┌────────────┴────────────┐
              |                         |
        Agent Planning             Model Router
       Task DAG / Memory          Local / Cloud
              |                         |
              └────────────┬────────────┘
                           |
                  Specialist Services
                           |
      ┌─────────────────────┼─────────────────────┐
      |                     |                     |
 Recon Intelligence   Pentest Execution   Application Security
   RedAmon-style        PentAGI-style        Strix-style
      |                     |                     |
      ├─────────────────────┼─────────────────────┤
      |                     |                     |
 Reverse Engineering  Adversary Emulation   AI Red Teaming
        REA            Decepticon-style    PyRIT / Promptfoo
      |                     |              Garak / AgentDojo
      └─────────────────────┼─────────────────────┘
                            |
                  Independent Validator
                Replay / Evidence / Scope
                            |
                   G9 Evidence Graph
                 PostgreSQL + Neo4j
                            |
                  Findings and Reporting
                 SARIF / Reports / SIEM`;

const PRIORITIES = [
  { rank: 1, name: "PentAGI", role: "Platform foundation", status: "planned",
    detail: "Security task execution · agent-to-tool interfaces · session persistence · provider-independent inference · result processing & monitoring. Replace overly permissive execution paths with G9-controlled capability grants and evidence verification.", },
  { rank: 2, name: "RedAmon", role: "Intelligence plane (conditional on dependency review)", status: "planned",
    detail: "Recon orchestration · Neo4j graph modeling · agent planning & MCP interfaces · scope-aware workflow · exploit-to-remediation correlation. The 101/104 XBOW result is developer-reported, not independently established." },
  { rank: 3, name: "Strix", role: "G9 AppSec Agent", status: "planned",
    detail: "Web applications, API endpoints, authentication flows, vulnerability reproduction, and regression validation. Specialization complements the broader PentAGI/RedAmon designs." },
  { rank: 4, name: "REA", role: "G9 REA Intelligence Service", status: "planned",
    detail: "Reverse-engineering subsystem connected to the evidence graph: function references, binary hashes, call graphs, confidence levels, analyst notes, reproducible observations. Essential for differentiating G9 from ordinary AI pentesting wrappers." },
  { rank: 5, name: "Decepticon", role: "Adversary emulation & mission control", status: "reference",
    detail: "Study for adversary-emulation and mission-control subsystems. Do NOT merge its autonomous execution loop with PentAGI's — share common task and evidence contracts instead." },
];

const COMPONENTS = [
  ["Primary orchestrator", "LangGraph", "Explicit workflow control"],
  ["Tool and result contracts", "Pydantic schemas", "Validated data exchange"],
  ["Broad security execution", "PentAGI-derived adapter or runtime", "General pentesting capability"],
  ["Reconnaissance intelligence", "RedAmon-derived services", "Graph-oriented asset discovery"],
  ["Web/API security", "Strix-derived specialist", "Deep application testing"],
  ["Reverse engineering", "REA integration", "Binary and application intelligence"],
  ["Red-team emulation", "Decepticon-derived specialist", "Operational adversary simulation"],
  ["AI red teaming", "PyRIT + Promptfoo + Garak", "Coverage of AI-specific failure modes"],
  ["Relational persistence", "PostgreSQL", "Durable engagement records"],
  ["Semantic retrieval", "pgvector", "Investigation context"],
  ["Attack graph", "Neo4j", "Asset and attack-path relationships"],
  ["Execution isolation", "Dedicated sandboxed workers", "Separation of tool execution and control"],
  ["Observability", "OpenTelemetry-compatible tracing", "Auditability and debugging"],
];

const CAPABILITIES = [
  { name: "G9 Evidence Graph", priority: "Critical",
    detail: "Asset → Service → Technology → Hypothesis → Test → Observation → Finding → Attack Path. Each node carries source, timestamp, model/tool provenance, confidence, validation status, scope, artifact links. Hypotheses, observations and confirmed facts are distinct node classes.",
    benefit: "Prevents duplicate rediscovery; enables graph-based attack-path reasoning." },
  { name: "G9 Autonomous Research Analyst", priority: "Critical",
    detail: "Researches unfamiliar services, advisories, source code, architecture and patch changes before execution. Escalates uncertain conclusions to specialists rather than inventing answers: tech ID, advisory/patch analysis, config assessment, hypothesis development, evidence-driven prioritization.",
    benefit: "Improves reasoning quality and reduces wasted tool executions." },
  { name: "G9 Verification Authority", priority: "Critical",
    detail: "Findings accepted only on explicit evidence requirements: Hypothesis → Candidate → Reproduced → Confirmed → Remediated → Regression-Verified. The primary agent's own success statement is never sufficient proof.",
    benefit: "Reduces hallucinated findings; supports defensible professional reporting." },
  { name: "G9 Adaptive Agent Scheduler", priority: "High",
    detail: "Task-specific model routing: deterministic parsers/small local models for tool output, local models for recon correlation and structured reports, strong reasoning models for research, hypothesis review and final adjudication.",
    benefit: "Better compute utilization; configuration chosen by G9-specific evaluations, not parameter counts." },
  { name: "G9 Adversarial Resilience Layer", priority: "Critical",
    detail: "Untrusted data cannot alter agent authority · tool results are never system instructions · capability grants are centrally issued · destinations checked independently of model instructions · credentials scoped per agent · destructive actions explicitly authorized · no model self-promotes findings · every action attributable and auditable.",
    benefit: "Limits consequences of compromised tool output, agent errors, and hostile target content." },
];

const INTELLIGENCE_INDICATORS = [
  ["Hypothesis quality", "Plausible vulnerabilities from incomplete evidence", "Repeated irrelevant scans"],
  ["Adaptive planning", "New observations alter the investigation", "Repeating a fixed checklist"],
  ["Attack-chain reasoning", "Findings connected into validated paths", "Listing unrelated CVEs"],
  ["Tool-use accuracy", "Commands, parameters, interpretations correct", "Invalid commands or invented outcomes"],
  ["Evidence discipline", "Claims reproducible and independently supported", "Exploitation reported without proof"],
];

const STATUS_STYLE_ARCH = {
  planned: "bg-cyan-500/15 text-cyan-300 border-cyan-500/40",
  reference: "bg-slate-500/15 text-slate-400 border-slate-600/40",
};

const TIERS = [
  { name: "Tier 1 — Essential G9 foundations", tone: "red", items: [
    ["Agent runtime", "LangGraph", "pending comparison with Pydantic AI — durable state and multi-agent workflow control"],
    ["Authorization", "Cedar", "fine-grained policy decisions"],
    ["Execution isolation", "G9-specific KVM-backed broker", "independent enforcement of scope and permissions"],
    ["MCP infrastructure", "ToolHive", "governed tool/server access"],
    ["Finding verification", "Cloudflare Security Audit methodology", "independent evidence verification"],
    ["Vulnerability research", "Google Mantis", "hypothesis, analysis, reproduction, and patch workflows"],
  ]},
  { name: "Tier 2 — Core cybersecurity capabilities", tone: "amber", items: [
    ["Reconnaissance", "RedAmon", "graph-oriented attack-surface intelligence"],
    ["Broad pentesting", "PentAGI 2.2.0+", "after isolation validation — multi-agent security-tool execution"],
    ["Application security", "Strix", "specialized web/API testing"],
    ["Reverse engineering", "REA", "evidence-oriented binary and application analysis"],
    ["Adversary emulation", "Decepticon", "conditional — broader operational agent specialization"],
    ["Vulnerability research", "OSS-CRS + Buttercup", "fuzzing and patch-validation research"],
  ]},
  { name: "Tier 3 — Evaluation and operational intelligence", tone: "cyan", items: [
    ["AI red teaming", "PyRIT", "adaptive adversarial tests"],
    ["AI regression testing", "Promptfoo", "repeatable evaluations"],
    ["Broad LLM probing", "Garak", "additional vulnerability coverage"],
    ["Agent-security benchmarking", "AgentDojo", "prompt-injection and tool-use attack scenarios"],
    ["Observability", "OpenTelemetry + Phoenix", "agent telemetry and evaluation"],
    ["Deterministic code analysis", "Semgrep + Joern", "complementary static-analysis evidence"],
  ]},
];

const SUBSYSTEMS = [
  ["G9 COMMAND", "Mission control, engagement authorization, agent orchestration, model routing", "▣"],
  ["G9 INTELLIGENCE", "Reconnaissance, OSINT, threat intelligence, attack graphs, persistent memory", "◉"],
  ["G9 OFFENSE", "Authorized pentesting, AppSec, adversary emulation, reverse engineering", "⚔"],
  ["G9 RESEARCH", "Vulnerability research, source analysis, fuzzing, exploitability assessment", "◇"],
  ["G9 DEFENSE", "Detection engineering, defensive validation, attack-to-detection correlation", "⛨"],
  ["G9 ASSURANCE", "Independent verification, agent-security testing, isolation, telemetry, evaluation", "✓"],
];

const NEW_DISCOVERIES = [
  ["Strands Agents Harness SDK", "9.4", "Agent lifecycle control; model portability; MCP; multi-agent graphs; memory/session management", "Benchmark against LangGraph"],
  ["Anthropic Sandbox Runtime", "9.3", "Filesystem controls; network restrictions; subprocess isolation; MCP sandboxing; execution-policy configuration", "Secondary isolation layer"],
  ["Graphiti", "9.3", "Temporal graphs; relationship extraction; episodic memory; hybrid retrieval; graph-aware reranking", "Integrate memory concepts; evaluate code"],
  ["Inspect AI", "9.3", "Agent evaluations; tool-use scenarios; multi-turn testing; custom scorers; reproducible experiments", "Primary evaluation-framework candidate"],
  ["Snyk Agent Scan", "9.1", "MCP scanning; tool poisoning; agent-skill security; credential-risk detection; malicious-content analysis", "Third-party component admission testing"],
];

export function ArchitectureView() {
  return (
    <div className="space-y-4">
      <Panel title="G9 SPECTRE — Security Intelligence Platform (target architecture)">
        <div className="text-[11px] text-slate-500 mb-3 leading-relaxed">
          Doctrine: <span className="text-slate-300 font-semibold">separate the agent-control plane from the security-execution plane</span> — models, tools and individual security agents upgrade without rebuilding the system. <span className="text-slate-300 font-semibold">One authoritative mission state:</span> specialists submit structured observations; the central verifier decides what becomes a confirmed finding. Full documentation in <span className="font-mono text-slate-400">docs/architecture/</span>.
        </div>
        <pre className="overflow-x-auto rounded-lg bg-black/40 border border-slate-800 p-4 text-[10.5px] leading-[1.45] text-slate-300 font-mono">{SPECTRE_DIAGRAM}</pre>
      </Panel>

      <Panel title="Integration priorities">
        <div className="space-y-2">
          {PRIORITIES.map((p) => (
            <div key={p.rank} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="h-6 w-6 rounded-full bg-red-600/20 border border-red-500/40 text-red-300 text-[11px] font-black flex items-center justify-center">{p.rank}</span>
                <span className="text-[13px] font-black text-slate-100">{p.name}</span>
                <span className="text-[11px] text-slate-500">— {p.role}</span>
                <span className={`ml-auto px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${STATUS_STYLE_ARCH[p.status]}`}>{p.status}</span>
              </div>
              <div className="mt-1.5 text-[11px] text-slate-400 leading-relaxed">{p.detail}</div>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="Component-to-implementation map">
          <div className="overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="text-slate-500 text-left border-b border-slate-800">
                  <th className="py-1.5 pr-3">Component</th><th className="pr-3">Implementation</th><th>Why</th>
                </tr>
              </thead>
              <tbody>
                {COMPONENTS.map(([c, i, w]) => (
                  <tr key={c} className="border-b border-slate-800/50">
                    <td className="py-1.5 pr-3 text-slate-300">{c}</td>
                    <td className="pr-3 font-mono text-cyan-300">{i}</td>
                    <td className="text-slate-500">{w}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Measuring actual intelligence (marketing is unreliable)">
          <div className="text-[11px] text-slate-500 mb-2">Agent counts, tool counts and solved-benchmark claims do not demonstrate reasoning. Sixth operational metric: <span className="text-slate-300 font-semibold">useful validated findings per unit of time and cost</span>.</div>
          <div className="space-y-1.5">
            {INTELLIGENCE_INDICATORS.map(([h, m, f]) => (
              <div key={h} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="text-[11px] font-bold text-emerald-300">{h}</div>
                <div className="text-[11px] text-slate-400">measures: {m}</div>
                <div className="text-[11px] text-red-300/80">failure: {f}</div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="Five custom capabilities that differentiate G9">
        <div className="grid md:grid-cols-2 gap-3">
          {CAPABILITIES.map((c, i) => (
            <div key={c.name} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-[11px] text-slate-600">{String(i + 1).padStart(2, "0")}</span>
                <span className="text-[12px] font-black text-slate-100">{c.name}</span>
                <span className={`ml-auto px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${c.priority === "Critical" ? "bg-red-500/15 text-red-300 border-red-500/40" : "bg-amber-500/15 text-amber-300 border-amber-500/40"}`}>{c.priority}</span>
              </div>
              <div className="mt-1.5 text-[11px] text-slate-400 leading-relaxed">{c.detail}</div>
              <div className="mt-1.5 text-[11px] text-emerald-300/90">Benefit: {c.benefit}</div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Final recommendations — operational priority tiers (docs/architecture/final-recommendations.md)">
        <div className="text-[11px] text-slate-500 mb-3 leading-relaxed">
          <span className="text-red-300 font-semibold">Architectural rule (inviolable):</span> security decisions are enforced <span className="text-slate-300 font-semibold">outside the AI model</span>. The model can propose, reason, and request; it cannot grant itself permissions, expand scope, or declare its own exploitation results independently verified. Scores measure expected benefit to G9, not independent proof of security or benchmark superiority — every dependency requires a pinned revision, source audit, dependency analysis, isolated testing, and explicit approval before integration.
        </div>
        <div className="grid lg:grid-cols-3 gap-3">
          {TIERS.map((t) => (
            <div key={t.name} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
              <div className={`text-[11px] font-black uppercase tracking-wide mb-2 ${t.tone === "red" ? "text-red-300" : t.tone === "amber" ? "text-amber-300" : "text-cyan-300"}`}>{t.name}</div>
              <div className="space-y-1.5">
                {t.items.map(([c, s, r]) => (
                  <div key={c} className="text-[10.5px] leading-relaxed">
                    <span className="text-slate-500">{c}: </span>
                    <span className="text-slate-200 font-bold">{s}</span>
                    <span className="text-slate-500"> — {r}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="The six G9 subsystems — common evidence schema, central authorization">
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {SUBSYSTEMS.map(([n, r, icon]) => (
            <div key={n} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
              <div className="flex items-center gap-2">
                <span className="w-5 text-center text-emerald-300">{icon}</span>
                <span className="text-[12px] font-black text-slate-100">{n}</span>
              </div>
              <div className="text-[10.5px] text-slate-500 leading-relaxed mt-0.5">{r}</div>
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="Expanded research — new harnesses, memory, and isolation">
          <div className="space-y-1.5">
            {NEW_DISCOVERIES.map(([n, v, caps, rec]) => (
              <div key={n} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[12px] font-bold text-slate-100">{n}</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-violet-500/15 text-violet-300 border border-violet-500/40">{v}/10</span>
                  <span className="ml-auto text-[10px] text-cyan-300 font-semibold">{rec}</span>
                </div>
                <div className="text-[10.5px] text-slate-500 leading-relaxed mt-0.5">{caps}</div>
              </div>
            ))}
          </div>
          <div className="mt-3 rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-2.5 text-[10.5px] text-slate-400 leading-relaxed">
            <span className="font-bold text-cyan-300">Orchestration competition updated:</span> LangGraph vs. Pydantic AI Harness vs. Strands Harness SDK. Also: CALDERA MCP (AI-assisted emulation — lab enclave only, never exposed to untrusted networks) and CyberGym-E2E (920 tasks / 139 projects; staged discover–prove–fix acceptance testing) as the measurable harness-comparison benchmark.
          </div>
        </Panel>

        <Panel title="Overall verdict">
          <div className="space-y-2 text-[11px]">
            {[
              ["Best new discovery", "Google Mantis — organized vulnerability-research methodology (research, critique, reproduction, patch-validation) rather than more tools"],
              ["Best evidence-verification foundation", "Cloudflare Security Audit — structured evidence states, coverage tracking, independent verification; foundational to the G9 Verification Authority"],
              ["Best agent-runtime candidates", "LangGraph (provisional) and Pydantic AI Harness — direct comparison before the decision is final"],
              ["Best intelligence combination", "RedAmon + REA — graph-driven reconnaissance plus lower-level reverse-engineering evidence"],
            ].map(([h, b]) => (
              <div key={h} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="font-bold text-emerald-300 text-[11px]">{h}</div>
                <div className="text-slate-400 leading-relaxed">{b}</div>
              </div>
            ))}
            <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-2.5 font-mono text-[10.5px] text-violet-200 leading-relaxed">
              LangGraph or Pydantic AI + Cedar + G9 KVM broker + ToolHive + Cloudflare verification + Mantis + RedAmon + PentAGI + Strix + REA + OSS-CRS/Buttercup + PyRIT/Promptfoo/Garak
            </div>
          </div>
        </Panel>
      </div>

      <Panel title="AI Security Studio — G9 AI red-team stack">
        <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-2 text-[11px]">
          {[
            ["Promptfoo", "Continuous regression testing for prompts, RAG, tool-calling agents, AI apps"],
            ["PyRIT", "Adaptive adversarial evaluation, multi-turn attack strategies"],
            ["Garak", "Broad automated probing across recognized LLM vulnerability categories"],
            ["DeepTeam", "Scenario-based testing and evaluation"],
            ["AgentDojo", "Controlled experiments: agent susceptibility to indirect prompt injection"],
          ].map(([n, d]) => (
            <div key={n} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
              <div className="font-bold text-violet-300 text-[12px]">{n}</div>
              <div className="text-slate-500 leading-relaxed mt-0.5">{d}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 text-[10px] text-slate-500 leading-relaxed">
          Evidence-preservation requirement: raw attack transcripts, model configurations, expected outcomes, observed outcomes, and test-environment versions are retained — G9 measures improvements rather than generating impressive-looking red-team reports.
        </div>
      </Panel>
    </div>
  );
}
