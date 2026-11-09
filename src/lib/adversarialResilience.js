/* ============================================================
   G9 Adversarial Resilience Layer (docs/architecture/
   custom-capabilities.md §5; g9-spectre-v3.md adversarial audit)

   Agents process untrusted web pages, repository files, scanner
   results and hostile application responses. This engine enforces:
   - Untrusted data cannot alter agent authority.
   - Tool results do not become system instructions.
   - Tool calls require centrally issued capability grants.
   - Network destinations are checked independently of model claims.
   - Destructive/high-impact actions require explicit authorization.
   - Every agent action is attributable and auditable.

   Tripwires (Layer 6 detection): canary tokens, encoded payloads,
   out-of-scope hosts, unexpected URLs, context dumps, instruction-
   injection patterns, and attempts to touch canary tools.
   ============================================================ */

export const TRIPWIRES = {
  canary_token: { severity: "critical", action: "halt", label: "Canary token touched — confirmed compromise" },
  canary_tool: { severity: "critical", action: "halt", label: "Canary (fake high-value) tool invoked — confirmed compromise" },
  context_dump: { severity: "critical", action: "halt", label: "Prompt/context dump detected in output — exfiltration attempt" },
  instruction_injection: { severity: "high", action: "quarantine", label: "Instruction-injection pattern in untrusted content" },
  encoded_payload: { severity: "high", action: "quarantine", label: "Encoded payload (base64/hex/zero-width) in tool arguments" },
  out_of_scope_host: { severity: "high", action: "block", label: "Out-of-scope network destination" },
  unexpected_url: { severity: "medium", action: "quarantine", label: "URL present where none is expected" },
  self_authorization: { severity: "critical", action: "halt", label: "Agent attempts to grant itself authority/scope" },
};

/* Zero-width and invisible characters used to hide injections */
const ZERO_WIDTH = /[\u200b-\u200f\u202a-\u202e\u2060\u2061-\u2064\ufeff]/;
const BASE64_LONG = /[A-Za-z0-9+/]{40,}={0,2}/;
const HEX_LONG = /\b(?:[0-9a-fA-F]{2}){20,}\b/;
const URL_RE = /https?:\/\/[^\s"'<>]+|www\.[^\s"'<>]+/;

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?|rules?)/i,
  /system\s*[:：]\s*/i,
  /you\s+are\s+now\s+(an?|the)\s+/i,
  /disregard\s+(your|all|the)\s+/i,
  /(reveal|print|repeat|dump)\s+(your\s+)?(system\s+)?(prompt|instructions|context)/i,
  /(grant|give|elevate)\s+(me|yourself)\s+(admin|root|sudo|authority|permission)/i,
  /<\s*\/?\s*(system|assistant|tool)\s*>/i,
];

export function makeCanarySet({ tokens = [], tools = [] } = {}) {
  return { tokens: [...tokens], tools: [...tools] };
}

/* Scan one tool-call attempt (agent, tool, arguments) against the
   resilience policy. The model's own claim about safety is never
   consulted — only the content and the policy. */
export function scanToolCall({ agentId, toolId, arguments: args, canaries, scopeHosts = [], urlExpected = false, approvedTools = null, approvalId = null }) {
  const findings = [];
  const blob = typeof args === "string" ? args : JSON.stringify(args ?? {});

  if (canaries) {
    for (const t of canaries.tokens ?? []) {
      if (blob.includes(t)) findings.push({ tripwire: "canary_token", detail: `token "${t.slice(0, 8)}…" present` });
    }
    for (const ct of canaries.tools ?? []) {
      if (toolId === ct) findings.push({ tripwire: "canary_tool", detail: `tool "${ct}" is a canary` });
    }
  }

  if (ZERO_WIDTH.test(blob)) findings.push({ tripwire: "encoded_payload", detail: "zero-width/invisible characters detected" });
  if (BASE64_LONG.test(blob) || HEX_LONG.test(blob)) findings.push({ tripwire: "encoded_payload", detail: "long base64/hex run detected" });

  for (const re of INJECTION_PATTERNS) {
    if (re.test(blob)) findings.push({ tripwire: "instruction_injection", detail: `pattern ${re.source.slice(0, 40)}` });
  }
  if (/(system\s+prompt|full\s+context|conversation\s+history|your\s+instructions)/i.test(blob)) {
    findings.push({ tripwire: "context_dump", detail: "context/prompt material referenced in output" });
  }
  if (/(expand|broaden|extend)\s+(the\s+)?scope|out[-\s]?of[-\s]?scope\s+is\s+(now\s+)?(allowed|ok|fine)/i.test(blob)) {
    findings.push({ tripwire: "self_authorization", detail: "scope-expansion language in agent output" });
  }

  const urls = blob.match(URL_RE) ?? [];
  if (urls.length > 0 && !urlExpected) findings.push({ tripwire: "unexpected_url", detail: `URL(s) where none expected: ${urls[0].slice(0, 60)}` });

  if (scopeHosts.length > 0) {
    const hosts = new Set(scopeHosts);
    const mentioned = urls.map((u) => u.replace(/^https?:\/\//, "").replace(/^www\./, "").split(/[/:?#]/)[0]);
    const out = mentioned.filter((h) => h && !hosts.has(h));
    if (out.length > 0) findings.push({ tripwire: "out_of_scope_host", detail: `host(s) outside scope allowlist: ${out.join(", ")}` });
  }

  if (approvedTools && !approvedTools.has(toolId)) {
    findings.push({ tripwire: "self_authorization", detail: `tool "${toolId}" not in the centrally issued capability grant` });
  }
  if (approvedTools && !approvalId) {
    findings.push({ tripwire: "self_authorization", detail: "tool call attempted without an approval reference" });
  }

  const decisions = findings.map((f) => ({ ...f, ...TRIPWIRES[f.tripwire] }));
  const worst = decisions.reduce(
    (acc, d) => (acc === null || severityRank(d.severity) > severityRank(acc.severity) ? d : acc),
    null
  );
  return {
    agentId, toolId,
    verdict: decisions.length === 0 ? "allow" : worst.action,
    findings: decisions,
    auditable: { at: new Date().toISOString(), agentId, toolId, count: decisions.length },
  };
}

function severityRank(s) {
  return { critical: 3, high: 2, medium: 1 }[s] ?? 0;
}

/* Session policy on a tripwire verdict — never auto-retry. */
export function applySessionPolicy(session, scan) {
  if (scan.verdict === "allow") return { ok: true, session };
  session.state = scan.verdict === "halt" ? "halted" : "quarantined";
  session.incidents.push({ at: new Date().toISOString(), verdict: scan.verdict, findings: scan.findings.map((f) => f.tripwire), agentId: scan.agentId, toolId: scan.toolId });
  session.requiresHumanReview = true;
  return { ok: false, reason: `tripwire ${scan.verdict}: session ${session.state} — human review required; auto-retry prohibited`, session };
}

export function makeSession({ engagementId }) {
  return { engagementId, state: "active", incidents: [], requiresHumanReview: false };
}
