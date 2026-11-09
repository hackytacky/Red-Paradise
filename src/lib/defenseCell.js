/* ============================================================
   G9 Defense Cell — attack-to-detection correlation
   (the capability competitors lack: they test, but never measure
   the defender's visibility)

   - Maps chain techniques to Sigma-style detection rules
   - Coverage matrix: technique × rule × telemetry × validation
   - Purple-team replay: an authorized chain replay MUST fire its
     detections — silence during a loud chain is itself a finding
   - Unmonitored behaviors are explicit findings, not silence
   ============================================================ */

export function makeDetectionCell({ engagementId }) {
  return { engagementId, rules: new Map(), chains: [], replays: [] };
}

/* Sigma-style detection rule: covers one or more techniques,
   states its telemetry source and expected signal. */
export function addRule(cell, { id, name, techniques, telemetry, signal, version = 1 }) {
  if (!id || !name || !Array.isArray(techniques) || techniques.length === 0 || !telemetry || !signal) {
    throw new Error("DefenseCell: rule requires id, name, techniques[], telemetry, signal");
  }
  if (cell.rules.has(id)) throw new Error(`DefenseCell: duplicate rule ${id}`);
  cell.rules.set(id, { id, name, techniques, telemetry, signal, version, validated: false });
  return cell.rules.get(id);
}

export function registerChain(cell, { id, name, techniques, loudness }) {
  if (!id || !Array.isArray(techniques) || techniques.length === 0) {
    throw new Error("DefenseCell: chain requires id and techniques[]");
  }
  cell.chains.push({ id, name, techniques, loudness: loudness ?? "medium" });
  return cell.chains[cell.chains.length - 1];
}

/* Coverage matrix: for every technique in every chain, which rules
   cover it — and which are unmonitored (explicit findings). */
export function coverageMatrix(cell) {
  const rows = [];
  for (const chain of cell.chains) {
    for (const technique of chain.techniques) {
      const covering = [...cell.rules.values()].filter((r) => r.techniques.includes(technique));
      rows.push({
        chainId: chain.id, technique,
        covered: covering.length > 0,
        rules: covering.map((r) => r.id),
        telemetry: [...new Set(covering.map((r) => r.telemetry))],
      });
    }
  }
  const gaps = rows.filter((r) => !r.covered);
  return { rows, gaps, coverage: rows.length === 0 ? 1 : (rows.length - gaps.length) / rows.length };
}

/* Purple-team replay: the chain runs again in coordination with the
   defenders. Expected detections are computed from coverage; the
   observed set is what actually fired. Missing detections on a loud
   chain are detection findings — silence is a finding. */
export function replayChain(cell, { chainId, observedSignals, note = "" }) {
  const chain = cell.chains.find((c) => c.id === chainId);
  if (!chain) throw new Error(`DefenseCell: unknown chain ${chainId}`);
  const expected = [...cell.rules.values()].filter(
    (r) => r.techniques.some((t) => chain.techniques.includes(t))
  );
  const observed = new Set(observedSignals);
  const fired = expected.filter((r) => observed.has(r.id));
  const missed = expected.filter((r) => !observed.has(r.id));
  const replay = {
    chainId, note, at: new Date().toISOString(),
    expected: expected.map((r) => r.id),
    fired: fired.map((r) => r.id),
    missed: missed.map((r) => r.id),
    verdict: missed.length === 0 ? "detection-validated" : "detection-finding",
    headline: missed.length > 0 && chain.loudness === "loud"
      ? "LOUD chain ran undetected — headline detection finding"
      : null,
  };
  cell.replays.push(replay);
  for (const r of fired) r.validated = true;
  return replay;
}

export function detectionReport(cell) {
  const matrix = coverageMatrix(cell);
  return {
    engagementId: cell.engagementId,
    coverage: Math.round(matrix.coverage * 100),
    gaps: matrix.gaps.map((g) => `${g.chainId}/${g.technique}`),
    replays: cell.replays.length,
    unvalidatedRules: [...cell.rules.values()].filter((r) => !r.validated).map((r) => r.id),
    doctrine: "a detection without a response runbook is a log line, not a control; silence during a loud chain is a finding",
  };
}
