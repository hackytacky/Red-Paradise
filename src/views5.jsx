import React, { useMemo, useState } from "react";
import { Panel } from "./views1.jsx";
import {
  makeActionSpec, bindApproval, validateAgainstApproval, digest, ACTION_SPEC_FIELDS, AUTH_RELEVANT_FIELDS,
} from "./lib/actionSpec.js";
import {
  makeExecution, transition, reconcile, canRetry, resetForRetry, EXEC_STATES,
} from "./lib/approvalStateMachine.js";

/* ================================================================
   VIEW: Trusted Execution — live action-spec + approval state machine
   ================================================================ */

const SPEC_INPUT = {
  action_id: "ACT-DEMO-01",
  engagement_id: "ENG-REDLAB-7",
  principal_id: "operator:hackytacky",
  agent_id: "hydra-web",
  tool_id: "nmap-scoped",
  tool_version: "7.95",
  normalized_arguments: { flags: "-sS -sV", ports: "1-1000", hosts: ["lab-api.g9.local"] },
  target_set: ["lab-api.g9.local", "lab-portal.g9.local"],
  working_directory: "/workspace/run",
  environment_profile: "lab-plane",
  sandbox_profile: "restricted-analysis",
  network_policy_id: "NETPOL-REDLAB",
  resource_budget: { cpu: 2, mem_gb: 4, minutes: 10 },
  policy_revision: "ceder@v3",
};

const HAPPY_PATH = ["CREATED", "SCHEMA_VALIDATED", "POLICY_EVALUATED", "AWAITING_APPROVAL", "APPROVED", "PRE_EXECUTION_VALIDATION", "DISPATCHED", "RUNNING", "COMPLETED", "EVIDENCE_PRESERVED"];
const DETOURS = ["DENIED", "REJECTED", "INVALIDATED", "CANCELLED", "FAILED", "OUTCOME_UNKNOWN"];

const WORKER_CLASSES = [
  ["Trusted service", "API, policy engine, database access", "Hardened host service", "emerald"],
  ["Restricted analysis worker", "Parsing, read-only analysis, approved utilities", "Restricted process/container sandbox", "cyan"],
  ["Hostile research worker", "Untrusted binaries, generated PoCs, fuzzing", "Disposable KVM guest — no G9 management credentials, no host Docker daemon", "red"],
];

const AUDIT_FINDINGS = [
  ["Workflow replay of security actions", "Critical", "Durable action identity and reconciliation"],
  ["Agent-generated authorization claims", "Critical", "External policy enforcement"],
  ["MCP tool poisoning", "Critical", "Tool qualification and restricted capabilities"],
  ["Host Docker socket exposure", "Critical", "Dedicated isolated execution environment"],
  ["Unauthorized network egress", "Critical", "Independent network-layer controls (non-HTTP protocols included)"],
  ["Unsafe generated code", "Critical", "Disposable research environments"],
];

export function ExecutionView() {
  const baseSpec = useMemo(() => makeActionSpec(SPEC_INPUT), []);
  const [spec, setSpec] = useState(baseSpec);
  const [approval, setApproval] = useState(() => bindApproval(baseSpec, { approvalId: "APR-DEMO-1", approvedBy: "operator:hackytacky" }));
  const [exec, setExec] = useState(() => makeExecution({ actionId: baseSpec.action_id, specDigest: baseSpec.spec_digest, toolId: baseSpec.tool_id }));
  const [log, setLog] = useState([]);

  const say = (ok, msg) => setLog((l) => [...l.slice(-7), { ok, msg, at: new Date().toISOString() }]);

  const step = (event, opts = {}) => {
    const r = transition(exec, event, { approval, ...opts });
    say(r.ok, r.ok ? `${event} → ${exec.state === r.exec.state ? "" : ""}${r.exec.state}` : `✕ ${event}: ${r.reason}`);
    setExec({ ...r.exec });
  };

  const tamper = () => {
    const tampered = { ...spec, normalized_arguments: { ...spec.normalized_arguments, ports: "1-65535" } };
    const r = validateAgainstApproval(tampered, approval);
    say(false, `tamper attempt (ports → 1-65535): ${r.reason}`);
    setSpec(tampered);
  };

  const reapprove = () => {
    const fresh = makeActionSpec({ ...spec, action_id: spec.action_id });
    const a = bindApproval(fresh, { approvalId: "APR-DEMO-" + Math.floor(Math.random() * 1e4), approvedBy: "operator:hackytacky" });
    setSpec(fresh);
    setApproval(a);
    setExec(makeExecution({ actionId: fresh.action_id, specDigest: fresh.spec_digest, toolId: fresh.tool_id }));
    say(true, `re-approved ${a.approvalId} bound to new digest ${fresh.spec_digest.slice(0, 12)}… — execution reset to CREATED`);
  };

  const reconcileNow = () => {
    const r = reconcile(exec, { evidence: { workerLogs: "sha256:…", exit: "signal-9", sideEffects: "pcap captured" }, sideEffectsOccurred: "unknown" });
    say(r.ok, r.ok ? "execution evidence reconciled — replay now permitted (manual decision, not automatic)" : `✕ ${r.reason}`);
    setExec({ ...r.exec });
  };

  const retryNow = () => {
    const r = resetForRetry(exec);
    say(r.ok, r.ok ? "retry accepted — re-entering PRE_EXECUTION_VALIDATION with fresh approval check" : `✕ retry refused: ${r.reason}`);
    setExec({ ...r.exec });
  };

  const nextHappy = {
    CREATED: "schema_valid", SCHEMA_VALIDATED: "policy_evaluated", POLICY_EVALUATED: "approval_required",
    AWAITING_APPROVAL: "approved", APPROVED: "pre_execution_validation", PRE_EXECUTION_VALIDATION: "dispatched",
    DISPATCHED: "running", RUNNING: "completed", COMPLETED: "evidence_preserved",
  }[exec.state];

  return (
    <div className="space-y-4">
      <Panel title="G9 Trusted Execution — canonical action specification (live engine)">
        <div className="text-[11px] text-slate-500 mb-3 leading-relaxed">
          An agent-generated command is <span className="text-slate-300 font-semibold">never executed solely because it conforms to the expected JSON schema</span>. The specification is canonicalized and approval is bound to its digest; <span className="text-red-300 font-semibold">any change to authorization-relevant fields invalidates the approval</span>. Authorization-relevant fields: <span className="font-mono text-slate-400">{AUTH_RELEVANT_FIELDS.join(" · ")}</span>.
        </div>
        <div className="grid md:grid-cols-2 gap-3 text-[10.5px] font-mono">
          {ACTION_SPEC_FIELDS.filter((f) => f !== "spec_digest").map((f) => (
            <div key={f} className="flex gap-2 rounded border border-slate-800 bg-slate-950/60 px-2.5 py-1.5">
              <span className="text-slate-600 w-40 shrink-0">{f}</span>
              <span className="text-slate-300 truncate">{JSON.stringify(spec[f])}</span>
            </div>
          ))}
          <div className="md:col-span-2 flex gap-2 rounded border border-violet-500/30 bg-violet-500/5 px-2.5 py-1.5">
            <span className="text-violet-400 w-40 shrink-0">spec_digest</span>
            <span className="text-violet-200">{spec.spec_digest}</span>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button onClick={tamper} className="px-3 py-1.5 rounded bg-red-600/80 hover:bg-red-500 text-white text-[11px] font-bold">Tamper with arguments (must invalidate)</button>
          <button onClick={reapprove} className="px-3 py-1.5 rounded bg-violet-600 hover:bg-violet-500 text-white text-[11px] font-bold">Re-approve new digest</button>
        </div>
      </Panel>

      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="Approval / execution state machine (live engine)">
          <div className="flex flex-wrap gap-1 mb-3">
            {HAPPY_PATH.map((s) => {
              const idx = HAPPY_PATH.indexOf(exec.state);
              const cur = HAPPY_PATH.indexOf(s);
              return (
                <span key={s} className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${cur < idx ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40" : cur === idx ? "bg-cyan-500/20 text-cyan-200 border-cyan-500/50" : "bg-slate-950 text-slate-600 border-slate-800"}`}>
                  {cur < idx ? "✓" : ""}{s.replace(/_/g, " ")}
                </span>
              );
            })}
            {DETOURS.includes(exec.state) && (
              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border bg-red-500/20 text-red-300 border-red-500/50">{exec.state.replace(/_/g, " ")}</span>
            )}
          </div>
          <div className="text-[11px] text-slate-500 mb-2">attempts: {exec.attempts} · reconciled: {String(exec.reconciled)} · bound approval: <span className="font-mono text-slate-400">{approval.approvalId}</span></div>
          <div className="flex flex-wrap gap-2">
            {nextHappy && exec.state !== "EVIDENCE_PRESERVED" && (
              <button onClick={() => step(nextHappy)} className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-bold">Advance: {nextHappy.replace(/_/g, " ")}</button>
            )}
            {exec.state === "RUNNING" && (
              <>
                <button onClick={() => step("outcome_unknown", { note: "worker crash after possible side effect" })} className="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white text-[11px] font-bold">Simulate worker crash → OUTCOME_UNKNOWN</button>
                <button onClick={() => step("failed", { note: "tool error before external action" })} className="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-white text-[11px] font-bold">Fail cleanly</button>
              </>
            )}
            {exec.state === "OUTCOME_UNKNOWN" && !exec.reconciled && (
              <button onClick={reconcileNow} className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px] font-bold">Reconcile execution evidence</button>
            )}
            {canRetry(exec).ok && (
              <button onClick={retryNow} className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-bold">Request retry</button>
            )}
            {exec.state === "OUTCOME_UNKNOWN" && !exec.reconciled && (
              <button onClick={retryNow} className="px-3 py-1.5 rounded bg-red-600/80 hover:bg-red-500 text-white text-[11px] font-bold">Try auto-replay (must refuse)</button>
            )}
          </div>
          <div className="mt-3 pt-3 border-t border-slate-800">
            <div className="text-[10px] font-bold tracking-widest text-slate-600 uppercase mb-1">Broker log</div>
            <div className="space-y-0.5 font-mono text-[10.5px]">
              {log.length === 0 && <div className="text-slate-700">no actions yet — walk the machine or simulate a crash</div>}
              {log.map((l, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-slate-700">{l.at.slice(11, 19)}</span>
                  <span className={l.ok ? "text-emerald-300/80" : "text-red-300/90"}>{l.msg}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="mt-3 text-[10px] text-slate-500 leading-relaxed">
            <span className="text-amber-300 font-bold">OUTCOME_UNKNOWN is essential:</span> a worker may crash after performing an external action but before the broker records its result. Automatic replay is prohibited — exactly-once external side effects cannot be assumed merely because a workflow engine provides durable state.
          </div>
        </Panel>

        <div className="space-y-4">
          <Panel title="Worker isolation — three classes">
            <div className="space-y-2">
              {WORKER_CLASSES.map(([c, w, i, tone]) => (
                <div key={c} className={`rounded-lg border p-2.5 ${tone === "emerald" ? "border-emerald-500/30 bg-emerald-500/5" : tone === "cyan" ? "border-cyan-500/30 bg-cyan-500/5" : "border-red-500/30 bg-red-500/5"}`}>
                  <div className="text-[12px] font-black text-slate-100">{c}</div>
                  <div className="text-[10.5px] text-slate-400">workload: {w}</div>
                  <div className="text-[10.5px] text-slate-500">isolation: {i}</div>
                </div>
              ))}
            </div>
            <div className="mt-2 text-[10px] text-slate-500 leading-relaxed">
              Network policy is enforced independently at the VM/network layer (ToolHive's HTTP/HTTPS egress proxy does not cover raw TCP/UDP/DNS). Detection telemetry (Falco/Tetragon) is a <span className="text-slate-300">detection system, not an enforcement boundary</span>.
            </div>
          </Panel>

          <Panel title="Adversarial audit — replay & authorization findings (from the triple audit)">
            <div className="space-y-1.5">
              {AUDIT_FINDINGS.map(([f, s, c]) => (
                <div key={f} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${s === "Critical" ? "bg-red-500/15 text-red-300 border-red-500/40" : "bg-amber-500/15 text-amber-300 border-amber-500/40"}`}>{s}</span>
                    <span className="text-[11px] font-bold text-slate-200">{f}</span>
                  </div>
                  <div className="text-[10.5px] text-emerald-300/80 mt-0.5">control: {c}</div>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
