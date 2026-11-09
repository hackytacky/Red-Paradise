/* ============================================================
   G9 Adaptive Agent Scheduler (docs/architecture/
   custom-capabilities.md §4; g9-spectre-v3.md §11 model routing)

   Task-specific routing instead of assigning every investigation
   to the largest model. The optimal configuration is determined
   by G9-specific evaluations, not model parameter counts.
   Cloud escalation requires explicit approval — never default.
   ============================================================ */

export const MODEL_CLASSES = {
  deterministic: { desc: "Deterministic parser / rule engine", local: true, cost: 0 },
  small_local: { desc: "Small local model (1–4B class)", local: true, cost: 1 },
  local_7_14b: { desc: "Local 7B–14B cybersecurity model", local: true, cost: 2 },
  coding_specialist: { desc: "Specialist coding model", local: true, cost: 3 },
  reasoning_local: { desc: "Strong local reasoning model", local: true, cost: 4 },
  cloud_reasoning: { desc: "Approved cloud reasoning model", local: false, cost: 9, requiresApproval: true },
};

export const ROUTING_RULES = [
  { task: "tool-result-normalization", model: "deterministic" },
  { task: "basic-classification", model: "small_local" },
  { task: "recon-correlation", model: "local_7_14b" },
  { task: "structured-report", model: "local_7_14b" },
  { task: "complex-code-analysis", model: "coding_specialist" },
  { task: "technical-reasoning", model: "reasoning_local" },
  { task: "re-interpretation", model: "reasoning_local" },
  { task: "hypothesis-review", model: "reasoning_local" },
  { task: "final-adjudication", model: "reasoning_local" },
  { task: "difficult-reasoning-escalation", model: "cloud_reasoning" },
];

/* VRAM budgeting: a 16 GB card cannot hold a 35B 4-bit model
   (~17.5 GB weights alone). The scheduler refuses configurations
   that exceed the budget rather than silently offloading. */
export function makeScheduler({ vramGb = 16 }) {
  return { vramGb, resident: new Map(), pinned: new Set(), decisions: [] };
}

/* Explicitly pin a resident model class: it is never evicted. */
export function pin(scheduler, modelClass) {
  if (!scheduler.resident.has(modelClass)) {
    const load = ensureResident(scheduler, modelClass);
    if (!load.ok) return load;
  }
  scheduler.pinned.add(modelClass);
  return { ok: true };
}

export function route(scheduler, { task, approvedCloudEscalation = false }) {
  const rule = ROUTING_RULES.find((r) => r.task === task);
  if (!rule) return { ok: false, reason: `no routing rule for task ${JSON.stringify(task)}` };
  const model = MODEL_CLASSES[rule.model];
  if (!model.local && !approvedCloudEscalation) {
    return { ok: false, reason: "cloud escalation requires explicit operator approval — local fallback required", fallback: "reasoning_local" };
  }
  const decision = { task, modelClass: rule.model, model, at: new Date().toISOString() };
  scheduler.decisions.push(decision);
  return { ok: true, decision };
}

/* Resident-model management: load a model class only if it fits
   alongside already-resident weights. Eviction is explicit. */
export function ensureResident(scheduler, modelClass) {
  const m = MODEL_CLASSES[modelClass];
  if (!m) return { ok: false, reason: `unknown model class ${modelClass}` };
  if (!m.local) return { ok: false, reason: "cloud models are never resident" };
  if (scheduler.resident.has(modelClass)) return { ok: true, alreadyResident: true };
  const used = [...scheduler.resident.values()].reduce((a, x) => a + x, 0);
  const need = weightsGb(modelClass);
  if (used + need > scheduler.vramGb) {
    const evictable = [...scheduler.resident.entries()].filter(([c]) => c !== modelClass && !scheduler.pinned.has(c));
    evictable.sort((a, b) => (b[1] - a[1]));
    let free = used;
    const evictions = [];
    for (const [c, gb] of evictable) {
      if (free - gb + need <= scheduler.vramGb) { /* not enough yet */ }
      free -= gb; evictions.push(c);
      if (free + need <= scheduler.vramGb) break;
    }
    if (free + need > scheduler.vramGb) {
      return { ok: false, reason: `insufficient VRAM: need ${need} GB, free ${scheduler.vramGb - free} GB after evictions — refusing to oversubscribe`, evictions };
    }
    for (const c of evictions) scheduler.resident.delete(c);
    scheduler.resident.set(modelClass, need);
    return { ok: true, evicted: evictions };
  }
  scheduler.resident.set(modelClass, need);
  return { ok: true };
}

function weightsGb(modelClass) {
  return { deterministic: 0, small_local: 2, local_7_14b: 8, coding_specialist: 8, reasoning_local: 14 }[modelClass] ?? 8;
}
