/* ============================================================
   G9 Advisory Watch — 24/7 continuous mode
   (the capability competitors lack: they run once; G9 watches)

   - Technology inventory per engagement asset
   - Advisory matching: a new advisory against inventoried
     technology triggers a rescan task automatically
   - Dedupe: the same advisory never queues twice
   ============================================================ */

export function makeWatch({ engagementId }) {
  return { engagementId, inventory: new Map(), advisories: new Map(), queue: [] };
}

export function addAsset(watch, { id, technologies }) {
  if (!id || !Array.isArray(technologies) || technologies.length === 0) {
    throw new Error("AdvisoryWatch: asset requires id and technologies[]");
  }
  if (watch.inventory.has(id)) throw new Error(`AdvisoryWatch: duplicate asset ${id}`);
  watch.inventory.set(id, { id, technologies });
  return watch.inventory.get(id);
}

/* An advisory affects a technology (optionally a version range).
   Matching is against the inventory — the watch never trusts a
   vendor's marketing severity, only affectedness. */
export function ingestAdvisory(watch, { id, technology, title, versions = null, severity = null, source }) {
  if (!id || !technology || !title) throw new Error("AdvisoryWatch: advisory requires id, technology, title");
  if (watch.advisories.has(id)) throw new Error(`AdvisoryWatch: duplicate advisory ${id} — dedupe before ingest`);
  watch.advisories.set(id, { id, technology, title, versions, severity, source, at: new Date().toISOString() });
  const affected = [...watch.inventory.values()].filter((a) => a.technologies.includes(technology));
  if (affected.length > 0) {
    const task = {
      taskId: `rescan-${id}`,
      advisoryId: id,
      reason: `${title} affects ${technology} on ${affected.map((a) => a.id).join(", ")}`,
      affectedAssets: affected.map((a) => a.id),
      state: "queued",
      queuedAt: new Date().toISOString(),
    };
    watch.queue.push(task);
    return { advisory: watch.advisories.get(id), matched: true, task };
  }
  return { advisory: watch.advisories.get(id), matched: false, task: null };
}

export function completeTask(watch, taskId) {
  const t = watch.queue.find((x) => x.taskId === taskId);
  if (!t) throw new Error(`AdvisoryWatch: unknown task ${taskId}`);
  t.state = "complete";
  t.completedAt = new Date().toISOString();
  return t;
}

export function pendingTasks(watch) {
  return watch.queue.filter((t) => t.state === "queued");
}
