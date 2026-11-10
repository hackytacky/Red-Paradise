/* ============================================================
   G9 live API client — talks to the real FastAPI control plane.
   Base URL: VITE_G9_API (default http://127.0.0.1:8700 — the
   loopback dev server). Every call fails soft: a backend that
   isn't running returns { ok: false } instead of throwing, so
   demo views keep working without the backend.
   ============================================================ */

const BASE = (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_G9_API) || "http://127.0.0.1:8700";

async function call(path, options = {}) {
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (!res.ok) return { ok: false, reason: `HTTP ${res.status}` };
    return await res.json();
  } catch (e) {
    return { ok: false, reason: `backend unreachable at ${BASE} — start it with: cd backend && uv run uvicorn g9_backend.api:app --port 8700` };
  }
}

export const g9api = {
  base: BASE,
  runLabMission: () => call("/lab/run", { method: "POST" }),
  labReport: () => call("/lab/report"),
  labArsenal: () => call("/lab/arsenal"),
  audit: () => call("/audit"),
  policyEvaluate: (req) => call("/policy/evaluate", { method: "POST", body: JSON.stringify(req) }),
  invokeTool: (spec, callArgs, executeNow = false) =>
    call("/tools/invoke", { method: "POST", body: JSON.stringify({ spec, call: callArgs, execute_now: executeNow }) }),
};
