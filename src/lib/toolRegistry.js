/* ============================================================
   G9 Universal Tool Registry — tool-agnostic pentest execution
   (Priority 1: red team & pentest)

   Doctrine: specialist agents may use ANY pentest tool available
   (GitHub or elsewhere) when they decide it is the most useful for
   the task — but no tool executes because the agent wants it to.
   Every tool passes a one-time ADMISSION before first use:

     unqualified → admission-review → qualified (pinned revision)

   Admission records: source repo/URL, exact revision, license,
   protocol surface (raw TCP/UDP/DNS/HTTP), capability class, and
   sandbox class required. A qualified tool is still per-call
   gated by the policy engine + action spec + tripwires.
   ============================================================ */

export const TOOL_STATES = ["unqualified", "admission-review", "qualified", "rejected"];
export const SANDBOX_CLASSES = ["restricted-analysis", "hostile-research-vm", "trusted-service"];

export function makeRegistry() {
  return { tools: new Map(), admissions: [] };
}

export function registerTool(registry, tool) {
  for (const f of ["id", "name", "source", "license", "protocols", "capabilityClass", "sandboxClass"]) {
    if (!tool[f]) throw new Error(`ToolRegistry: tool requires ${f}`);
  }
  if (!Array.isArray(tool.protocols) || tool.protocols.length === 0) {
    throw new Error("ToolRegistry: protocols must be a non-empty array (e.g. ['tcp','udp','dns'])");
  }
  if (!SANDBOX_CLASSES.includes(tool.sandboxClass)) {
    throw new Error(`ToolRegistry: unknown sandbox class ${tool.sandboxClass}`);
  }
  if (registry.tools.has(tool.id)) throw new Error(`ToolRegistry: duplicate tool id ${tool.id}`);
  registry.tools.set(tool.id, {
    state: "unqualified",
    revision: null,
    admittedAt: null,
    admittedBy: null,
    residualRisks: [],
    ...tool,
  });
  return registry.tools.get(tool.id);
}

/* Admission decision — recorded, reviewable, never silent. */
export function admissionReview(registry, { toolId, decision, revision, reviewedBy, residualRisks = [], note = "" }) {
  const t = registry.tools.get(toolId);
  if (!t) throw new Error(`ToolRegistry: unknown tool ${toolId}`);
  if (t.state !== "unqualified" && t.state !== "admission-review") {
    throw new Error(`ToolRegistry: ${toolId} already ${t.state}`);
  }
  if (decision === "qualified") {
    if (!revision) throw new Error("ToolRegistry: qualification requires a pinned revision");
    t.state = "qualified";
    t.revision = revision;
    t.admittedAt = new Date().toISOString();
    t.admittedBy = reviewedBy;
    t.residualRisks = [...residualRisks];
  } else {
    t.state = "rejected";
    t.rejectionNote = note || "rejected at admission review";
  }
  registry.admissions.push({ toolId, decision, revision, reviewedBy, at: new Date().toISOString(), note });
  return t;
}

export function qualifiedTools(registry) {
  return [...registry.tools.values()].filter((t) => t.state === "qualified");
}

/* A capability grant is derived per engagement from qualified tools.
   The grant is what the policy engine checks — agents never hold
   tools directly. */
export function issueGrant(registry, { engagementId, toolIds }) {
  const granted = [];
  for (const id of toolIds) {
    const t = registry.tools.get(id);
    if (!t || t.state !== "qualified") {
      throw new Error(`issueGrant: tool ${id} is not qualified — admission is a prerequisite to any grant`);
    }
    granted.push(id);
  }
  return { engagementId, tools: new Set(granted), issuedAt: new Date().toISOString() };
}

/* Any-tool doctrine: given a task need (protocols + capability),
   recommend the most useful QUALIFIED tools. Unqualified candidates
   are surfaced for admission — never silently used. */
export function recommendForTask(registry, { protocols = [], capabilityClass = null }) {
  const qualified = qualifiedTools(registry);
  const match = qualified.filter(
    (t) => (capabilityClass === null || t.capabilityClass === capabilityClass) &&
      protocols.every((p) => t.protocols.includes(p))
  );
  const candidates = [...registry.tools.values()].filter(
    (t) => t.state !== "qualified" && (capabilityClass === null || t.capabilityClass === capabilityClass)
  );
  return { qualified: match, needsAdmission: candidates };
}
