import React, { useMemo, useState } from "react";
import { Panel } from "./views1.jsx";
import {
  makeRegistry, registerTool, admissionReview, qualifiedTools, issueGrant, recommendForTask,
} from "./lib/toolRegistry.js";
import { makePolicyEngine, evaluate } from "./lib/policyEngine.js";

/* ================================================================
   VIEW: Tool Arsenal — universal tool admission + policy gate
   Priority 1: red team & pentest. Any tool, anywhere, if it is
   the most useful for the task — admitted once, gated every call.
   ================================================================ */

const SEED_TOOLS = [
  { id: "nmap-scoped", name: "nmap (scoped profile)", source: "github.com/nmap/nmap", license: "GPL-2.0", protocols: ["tcp", "udp"], capabilityClass: "network-recon", sandboxClass: "restricted-analysis", revision: "7.95" },
  { id: "httpx", name: "httpx", source: "github.com/projectdiscovery/httpx", license: "MIT", protocols: ["http"], capabilityClass: "web-recon", sandboxClass: "restricted-analysis", revision: "v1.6.0" },
  { id: "bloodhound-ce", name: "BloodHound CE", source: "github.com/SpecterOps/BloodHound", license: "Apache-2.0", protocols: ["http"], capabilityClass: "identity-analysis", sandboxClass: "restricted-analysis", revision: "v5.1.0" },
  { id: "nuclei", name: "nuclei", source: "github.com/projectdiscovery/nuclei", license: "MIT", protocols: ["http"], capabilityClass: "web-scanning", sandboxClass: "restricted-analysis", revision: "v3.3.7" },
  { id: "ghidra-scoped", name: "Ghidra (scoped API)", source: "github.com/NationalSecurityAgency/ghidra", license: "Apache-2.0", protocols: ["local"], capabilityClass: "reverse-engineering", sandboxClass: "restricted-analysis", revision: "11.2" },
  { id: "custom-fuzzer", name: "any-tool-from-github (unvetted fuzzer)", source: "github.com/example/fuzzer", license: "AGPL-3.0", protocols: ["tcp", "dns"], capabilityClass: "fuzzing", sandboxClass: "hostile-research-vm" },
];

const STATE_TONE = {
  qualified: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  unqualified: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  "admission-review": "bg-cyan-500/15 text-cyan-300 border-cyan-500/40",
  rejected: "bg-red-500/15 text-red-300 border-red-500/40",
};

export function ArsenalView() {
  const registry = useMemo(() => {
    const r = makeRegistry();
    for (const t of SEED_TOOLS) {
      registerTool(r, t);
      if (t.revision) admissionReview(r, { toolId: t.id, decision: "qualified", revision: t.revision, reviewedBy: "operator:hackytacky" });
    }
    return r;
  }, []);

  const [grant, setGrant] = useState(() => issueGrant(registry, { engagementId: "ENG-REDLAB-7", toolIds: ["nmap-scoped", "httpx", "bloodhound-ce", "nuclei", "ghidra-scoped"] }));
  const [admitMsg, setAdmitMsg] = useState(null);

  const engine = useMemo(() => makePolicyEngine({
    policyRevision: "ceder@v1",
    engagements: {
      "ENG-REDLAB-7": {
        scope: ["lab-api.g9.local", "lab-portal.g9.local", "lab-dc-01.g9.local"],
        roeSigned: true,
        principals: { "agent:hydra-svc": { revoked: false }, "agent:chimera": { revoked: false } },
      },
    },
    grants: { "ENG-REDLAB-7": grant },
  }), [grant]);

  const [req, setReq] = useState({
    principalId: "agent:hydra-svc", toolId: "nmap-scoped", targets: "lab-api.g9.local",
    sandboxClass: "restricted-analysis", highImpact: false, selfAuthorized: false,
  });
  const [decision, setDecision] = useState(null);

  const tools = [...registry.tools.values()];
  const qualified = qualifiedTools(registry);

  const admit = (toolId, decisionType) => {
    const t = registry.tools.get(toolId);
    if (decisionType === "qualified") {
      const rev = `rev-${Math.floor(Math.random() * 1e6)}`;
      admissionReview(registry, { toolId, decision: "qualified", revision: rev, reviewedBy: "operator:hackytacky", residualRisks: ["AGPL — license gate for commercial integration"] });
      setAdmitMsg(`✓ ${toolId} qualified at pinned revision ${rev} — now grantable, still gated per call`);
    } else {
      admissionReview(registry, { toolId, decision: "rejected", reviewedBy: "operator:hackytacky", note: "unvetted source" });
      setAdmitMsg(`✕ ${toolId} rejected at admission review — recorded, never silently usable`);
    }
    setGrant(issueGrant(registry, { engagementId: "ENG-REDLAB-7", toolIds: qualifiedTools(registry).map((x) => x.id) }));
  };

  const runPolicy = () => {
    const d = evaluate(engine, {
      requestId: "REQ-" + Math.floor(Math.random() * 1e4),
      engagementId: "ENG-REDLAB-7",
      principalId: req.principalId,
      toolId: req.toolId,
      targets: req.targets.split(",").map((s) => s.trim()).filter(Boolean),
      sandboxClass: req.sandboxClass,
      requiredSandboxClass: registry.tools.get(req.toolId)?.sandboxClass,
      highImpact: req.highImpact,
      selfAuthorized: req.selfAuthorized,
    });
    setDecision(d);
  };

  const rec = recommendForTask(registry, { protocols: ["http"], capabilityClass: "web-scanning" });
  const recFuzz = recommendForTask(registry, { protocols: ["tcp", "dns"], capabilityClass: "fuzzing" });

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-4">
        <div className="text-[13px] font-black text-red-200">PRIORITY 1 — RED TEAM & PENTEST EXECUTION</div>
        <div className="text-[11px] text-red-200/80 mt-1 leading-relaxed">
          Specialists may select <span className="font-bold">any pentest tool available — GitHub or anywhere</span> when they decide it is the most useful for the task. The arsenal is open; execution is not. Every tool passes a one-time recorded admission (pinned revision, license, protocol surface, sandbox class) before it can be granted, and <span className="font-bold">every single call</span> still passes the deny-by-default policy engine, the digest-bound action spec, and the tripwire scanner. An agent's preference for a tool never substitutes for admission or authorization.
        </div>
      </div>

      <Panel title="Universal tool registry — admission state (live engine)">
        <div className="overflow-x-auto">
          <table className="w-full text-[10.5px]">
            <thead>
              <tr className="text-slate-500 text-left border-b border-slate-800">
                <th className="py-1.5 pr-2">Tool</th><th className="pr-2">Source</th><th className="pr-2">License</th><th className="pr-2">Protocols</th><th className="pr-2">Capability</th><th className="pr-2">Sandbox</th><th className="pr-2">State</th><th></th>
              </tr>
            </thead>
            <tbody>
              {tools.map((t) => (
                <tr key={t.id} className="border-b border-slate-800/50">
                  <td className="py-1.5 pr-2 font-mono text-slate-200">{t.id}{t.revision ? <span className="text-slate-600"> @{t.revision}</span> : null}</td>
                  <td className="pr-2 text-slate-500 font-mono">{t.source}</td>
                  <td className="pr-2 text-slate-500">{t.license}</td>
                  <td className="pr-2 font-mono text-cyan-300">{t.protocols.join("/")}</td>
                  <td className="pr-2 text-slate-400">{t.capabilityClass}</td>
                  <td className="pr-2 text-slate-500">{t.sandboxClass}</td>
                  <td className="pr-2"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${STATE_TONE[t.state]}`}>{t.state}</span></td>
                  <td>
                    {t.state === "unqualified" && (
                      <span className="flex gap-1">
                        <button onClick={() => admit(t.id, "qualified")} className="px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[9px] font-bold">qualify</button>
                        <button onClick={() => admit(t.id, "rejected")} className="px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 text-white text-[9px] font-bold">reject</button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {admitMsg && <div className="mt-2 text-[10.5px] text-slate-400 font-mono">{admitMsg}</div>}
        <div className="mt-2 text-[10px] text-slate-500">capability grant (ENG-REDLAB-7): <span className="font-mono text-slate-400">{[...grant.tools].join(" · ")}</span></div>
      </Panel>

      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="Deny-by-default policy gate (live engine — Cedar-style PDP)">
          <div className="grid grid-cols-2 gap-2 text-[10.5px]">
            <label className="block">
              <span className="text-slate-500">Principal</span>
              <select value={req.principalId} onChange={(e) => setReq({ ...req, principalId: e.target.value })} className="mt-0.5 w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-800 font-mono">
                <option>agent:hydra-svc</option><option>agent:chimera</option><option>agent:unknown</option>
              </select>
            </label>
            <label className="block">
              <span className="text-slate-500">Tool</span>
              <select value={req.toolId} onChange={(e) => setReq({ ...req, toolId: e.target.value })} className="mt-0.5 w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-800 font-mono">
                {tools.map((t) => <option key={t.id}>{t.id}</option>)}
              </select>
            </label>
            <label className="col-span-2 block">
              <span className="text-slate-500">Targets (comma-separated — scope: lab-api · lab-portal · lab-dc-01)</span>
              <input value={req.targets} onChange={(e) => setReq({ ...req, targets: e.target.value })} className="mt-0.5 w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-800 font-mono" />
            </label>
            <label className="col-span-2 flex items-center gap-4 text-slate-400">
              <label className="flex items-center gap-1"><input type="checkbox" checked={req.highImpact} onChange={(e) => setReq({ ...req, highImpact: e.target.checked })} className="accent-red-500" /> high-impact (no approval attached)</label>
              <label className="flex items-center gap-1"><input type="checkbox" checked={req.selfAuthorized} onChange={(e) => setReq({ ...req, selfAuthorized: e.target.checked })} className="accent-red-500" /> agent self-authorization attempt</label>
            </label>
          </div>
          <button onClick={runPolicy} className="mt-2 px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-[11px] font-bold">Evaluate request</button>
          {decision && (
            <div className={`mt-3 rounded-lg border p-2.5 ${decision.effect === "allow" ? "border-emerald-500/40 bg-emerald-500/5" : "border-red-500/40 bg-red-500/5"}`}>
              <div className={`text-[12px] font-black uppercase ${decision.effect === "allow" ? "text-emerald-300" : "text-red-300"}`}>{decision.effect} · {decision.policyRevision}</div>
              {decision.reasons.length > 0 ? (
                <ul className="mt-1 space-y-0.5 text-[10.5px] text-red-200/90 list-disc pl-4">
                  {decision.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              ) : (
                <div className="mt-1 text-[10.5px] text-emerald-200/80">all seven checks passed — release to the execution broker</div>
              )}
            </div>
          )}
          <div className="mt-2 text-[10px] text-slate-500 leading-relaxed">
            Checks: engagement validity & RoE signature · principal identity/revocation · per-target scope membership · capability-grant membership · sandbox-class satisfaction · high-impact approval binding & digest match · self-authorization refusal. Absence of any fact is a deny with the precise reason.
          </div>
        </Panel>

        <div className="space-y-4">
          <Panel title="Task-driven tool selection (any-tool doctrine)">
            <div className="space-y-2 text-[11px]">
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="text-slate-400">Task: web scanning over HTTP</div>
                <div className="text-emerald-300 font-mono mt-0.5">→ {rec.qualified.map((t) => t.id).join(", ") || "none"}</div>
                <div className="text-slate-600">needs admission: {rec.needsAdmission.map((t) => t.id).join(", ") || "none"}</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2.5">
                <div className="text-slate-400">Task: fuzzing over TCP+DNS</div>
                <div className="text-emerald-300 font-mono mt-0.5">→ {recFuzz.qualified.map((t) => t.id).join(", ") || "none qualified"}</div>
                <div className="text-amber-300">needs admission: {recFuzz.needsAdmission.map((t) => t.id).join(", ") || "none"}</div>
                <div className="text-slate-600 mt-0.5">The agent may want any fuzzer it finds — but it surfaces here for admission; it is never silently installed or executed.</div>
              </div>
            </div>
          </Panel>

          <Panel title="Flow: from agent preference to executed tool call">
            <div className="space-y-1 font-mono text-[10.5px] text-slate-400">
              {[
                "agent decides tool X is most useful for the task",
                "→ registry lookup: qualified? (one-time admission: revision, license, protocols, sandbox class)",
                "→ recommendForTask: qualified match or admission candidate — never silent install",
                "→ capability grant issued per engagement (agents never hold tools directly)",
                "→ policy engine: deny-by-default, seven checks, precise deny reasons",
                "→ action spec: canonicalized, digest-bound approval, tamper invalidates",
                "→ tripwire scan: canaries, injection, encoded payloads, scope hosts",
                "→ execution broker: sandbox class enforced, OUTCOME_UNKNOWN reconciliation",
                "→ evidence graph: provenance-tagged observation → verification authority",
              ].map((l, i) => (
                <div key={i} className={i === 0 ? "text-slate-200" : ""}>{l}</div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
