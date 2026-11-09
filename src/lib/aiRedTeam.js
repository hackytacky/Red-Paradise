/* ============================================================
   G9 AI Security Studio — LLM/agent/RAG/MCP red teaming
   (the capability competitors lack: conventional pentest agents do
   not test AI systems at all)

   - Standing injection corpus per ingest path (web, email, files,
     RAG, inter-agent, tool descriptions)
   - Every control change re-runs the corpus; regressions BLOCK the
     change (CI/CD regression gate)
   - Results preserve raw transcripts, target config, expected and
     observed outcomes — measure improvement, not flashy reports
   ============================================================ */

export const INGEST_PATHS = ["web", "email", "files", "rag", "inter-agent", "tool-descriptions"];

export function makeStudio({ targetId, targetConfig }) {
  if (!targetId || !targetConfig) throw new Error("AIStudio: targetId and targetConfig are required");
  return {
    targetId, targetConfig,
    corpus: new Map(), // path -> [{ id, payload, expected: blocked|allowed }]
    runs: [],
  };
}

export function addCorpusCase(studio, { path, id, payload, expected }) {
  if (!INGEST_PATHS.includes(path)) throw new Error(`AIStudio: unknown ingest path ${path}`);
  if (!["blocked", "allowed"].includes(expected)) throw new Error("AIStudio: expected must be blocked|allowed");
  if (!studio.corpus.has(path)) studio.corpus.set(path, []);
  const cases = studio.corpus.get(path);
  if (cases.some((c) => c.id === id)) throw new Error(`AIStudio: duplicate case ${id}`);
  cases.push({ id, payload, expected });
  return cases[cases.length - 1];
}

/* Run the corpus against a control function: (path, payload) =>
   "blocked" | "allowed". The control is code, never a model's
   self-assessment. */
export function runCorpus(studio, { control, controlVersion, reason = "" }) {
  if (typeof control !== "function") throw new Error("AIStudio: control must be a function (code-enforced)");
  const results = [];
  for (const [path, cases] of studio.corpus) {
    for (const c of cases) {
      const observed = control(path, c.payload);
      results.push({
        path, id: c.id, expected: c.expected, observed,
        pass: observed === c.expected,
        transcript: `${path}:${c.id} → control ${controlVersion}: ${observed}`,
      });
    }
  }
  const failures = results.filter((r) => !r.pass);
  const run = {
    at: new Date().toISOString(), controlVersion, reason,
    total: results.length, failures: failures.length,
    pass: failures.length === 0,
    verdict: failures.length === 0 ? "green" : "regression",
    results,
  };
  studio.runs.push(run);
  return run;
}

/* Regression gate: a control change whose corpus run has failures
   is BLOCKED. No exceptions, no "it's probably fine". */
export function regressionGate(run) {
  if (run.verdict === "green") return { ok: true, verdict: "promote" };
  return {
    ok: false,
    verdict: "blocked",
    reason: `injection regression: ${run.failures}/${run.total} corpus cases failed on control ${run.controlVersion} — the change is blocked until the corpus is green`,
    failures: run.results.filter((r) => !r.pass).map((r) => `${r.path}/${r.id}: expected ${r.expected}, observed ${r.observed}`),
  };
}

export function coverageByPath(studio) {
  const out = {};
  for (const p of INGEST_PATHS) out[p] = studio.corpus.get(p)?.length ?? 0;
  return out;
}
