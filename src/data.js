import React from "react";

/* ============================================================
   G9 RED-OPS // CHIMERA COMMAND — shared constants & data
   Demo deployment: telemetry is simulated; on the G9 host the
   same gates and pipeline drive real tool adapters via CERBERUS.
   Doctrine: graduated authorization · code-enforced verdicts ·
   no LLM grades its own exploit success · owner-facing reports.

   Governance concepts adapted from Decepticon (BitterSecurity):
   - Immutable workflow pinning (workflow_snapshot: id, version,
     SHA-256 — resumes keep the pin; conflicting pins fail closed)
   - OPPLAN evidence-driven objective DAG (readiness comes from
     real dependency paths + evidence, never a fixed kill-chain
     ladder; proof → independent verification → reporting)
   - Soundwave planning documents (operator-provisioned roe.json
     + optional planning JSON set)
   ============================================================ */

export const WORKFLOW_PIN = {
  id: "red-team",
  version: "1",
  sha256: "9f2c41ab77e0d3c58b1e6a2f90d4c7e5b8a1f3d6c9e2b4a7f1d8c3e6b9a2f4d7",
  note: "Immutable for this execution thread. A different workflow requires a new thread.",
};

export const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const SEV_STYLE = {
  critical: "bg-red-500/15 text-red-300 border-red-500/40",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  low: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  info: "bg-slate-500/15 text-slate-300 border-slate-500/40",
};
export const STATUS_STYLE = {
  candidate: "bg-slate-500/15 text-slate-300 border-slate-500/40",
  verified: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  reported: "bg-indigo-500/15 text-indigo-300 border-indigo-500/40",
};
export const KIND_STYLE = {
  recon: "text-cyan-300", scan: "text-sky-300", finding: "text-amber-300",
  chain: "text-rose-300", gate: "text-emerald-300", intel: "text-violet-300", report: "text-indigo-300",
};
export const NODE_STYLE = {
  recon: { fill: "#0e7490", icon: "◉" },
  foothold: { fill: "#dc2626", icon: "◆" },
  cred: { fill: "#ea580c", icon: "🔑" },
  pivot: { fill: "#a21caf", icon: "⤳" },
  privesc: { fill: "#be123c", icon: "▲" },
  objective: { fill: "#16a34a", icon: "★" },
};
export const OBJ_STATE_STYLE = {
  complete: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  ready: "bg-cyan-500/15 text-cyan-300 border-cyan-500/40",
  waiting: "bg-slate-500/15 text-slate-400 border-slate-600/40",
  blocked: "bg-red-500/15 text-red-300 border-red-500/40",
};

let _uid = 0;
export const uid = (p) => p + "-" + (++_uid) + "-" + Math.floor(Math.random() * 1e4);
export const rand = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
export const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

/* ---------------- Agents ---------------- */

export const AGENTS = [
  { id: "atlas", greek: "ATLAS", tier: "T1 Command", role: "Orchestrator — routes work, holds no tools", model: "g9-14b-orch-ft", tools: ["message-router"], status: "working" },
  { id: "strategos", greek: "STRATEGOS", tier: "T1 Command", role: "Planner — success criteria & campaign design", model: "g9-32b-plan-ft", tools: ["plan-doc"], status: "working" },
  { id: "hermes", greek: "HERMES", tier: "T1 Command", role: "Human liaison — only agent that talks to you", model: "g9-14b-liaison-ft", tools: ["approve-request"], status: "idle" },
  { id: "themis", greek: "THEMIS", tier: "T2 Oversight", role: "Evidence judge — pure function, no tools", model: "g9-judge-32b", tools: [], status: "verifying" },
  { id: "socrates", greek: "SOCRATES", tier: "T2 Oversight", role: "Adversarial reviewer — attacks our own chains", model: "g9-judge-32b", tools: [], status: "verifying" },
  { id: "aegis", greek: "AEGIS", tier: "T2 Oversight", role: "Safety gate — veto-only, can block, never approve", model: "g9-aegis-14b", tools: [], status: "idle" },
  { id: "epimetheus", greek: "EPIMETHEUS", tier: "T2 Oversight", role: "Quality/regression judge — benchmark gates", model: "g9-judge-32b", tools: [], status: "idle" },
  { id: "argus", greek: "ARGUS", tier: "T3 Blue", role: "Vulnerabilities specialist — blue lead, discovery union", model: "g9-32b-vuln-ft", tools: ["variant-analysis", "ai-fuzz", "static-analysis"], status: "working" },
  { id: "talos", greek: "TALOS", tier: "T3 Blue", role: "Malware & reverse engineering (REA-style)", model: "g9-32b-re-ft (local)", tools: ["ghidra-scoped-api", "radare2", "model-file-audit"], status: "working" },
  { id: "metis", greek: "METIS", tier: "T3 Blue", role: "Threat intel — advisory & CVE matching, 24/7 watch", model: "g9-14b-intel-ft", tools: ["advisory-feed", "cve-match"], status: "working" },
  { id: "chimera", greek: "CHIMERA", tier: "T5 Red", role: "Red lead — chain construction & execution", model: "g9-32b-red-ft (local)", tools: ["chain-engine", "graph-search"], red: true, status: "working" },
  { id: "panoptes", greek: "PANOPTES", tier: "T5 Red", role: "OSINT & recon — passive-only first", model: "g9-14b-osint-ft", tools: ["passive-dns", "ct-logs", "archive"], red: true, status: "working" },
  { id: "hydra-web", greek: "HYDRA-WEB", tier: "T5 Red", role: "Web vector — injection, authz, logic", model: "g9-32b-web-ft", tools: ["httpx", "ffuf", "jwt-tool"], red: true, status: "working" },
  { id: "hydra-svc", greek: "HYDRA-SVC", tier: "T5 Red", role: "External services — daemons, protocols", model: "g9-14b-svc-ft", tools: ["nmap-scoped", "snmp-walk"], red: true, status: "working" },
  { id: "hydra-ident", greek: "HYDRA-IDENT", tier: "T5 Red", role: "Identity & directory — creds, delegation, ADCS", model: "g9-32b-ident-ft", tools: ["graph-paths", "kerberoast-check"], red: true, status: "working" },
  { id: "hydra-cloud", greek: "HYDRA-CLOUD", tier: "T5 Red", role: "Cloud & supply chain — buckets, metadata, CI/CD", model: "g9-32b-cloud-ft", tools: ["bucket-audit", "metadata-probe"], red: true, status: "working" },
  { id: "hydra-social", greek: "HYDRA-SOCIAL", tier: "T5 Red", role: "Social vector — surface modeling only (no execution)", model: "g9-14b-social-ft", tools: ["surface-model"], red: true, status: "idle" },
  { id: "hydra-ai", greek: "HYDRA-AI", tier: "T5 Red", role: "AI-systems vector — injection, memory & MCP poisoning", model: "g9-32b-aired-ft (local)", tools: ["injection-corpus", "mcp-probe", "memory-audit"], red: true, status: "working" },
  { id: "calliope", greek: "CALLIOPE", tier: "T7 Support", role: "Reporter — owner-facing reports & purple package", model: "g9-14b-report-ft", tools: ["report-builder"], status: "idle" },
  { id: "mnemosyne", greek: "MNEMOSYNE", tier: "T7 Support", role: "Memory curator — versioned, canary-protected", model: "g9-14b-mem-ft", tools: ["memory-vcs", "canary-check"], status: "working" },
  { id: "orpheus", greek: "ORPHEUS", tier: "T7 Support", role: "RAG & tradecraft retrieval", model: "g9-14b-rag-ft", tools: ["play-index"], status: "working" },
  { id: "prometheus", greek: "PROMETHEUS", tier: "T6 AI", role: "Model ops — fine-tunes & eval gates (local only)", model: "meta", tools: ["ft-trainer", "eval-harness"], status: "working" },
  { id: "helios", greek: "HELIOS", tier: "T6 AI", role: "Local inference — GPU scheduler", model: "system", tools: ["llama.cpp", "vllm"], status: "working" },
  { id: "cerberus", greek: "CERBERUS", tier: "Structural", role: "Sole executor & message gateway — code gates are load-bearing", model: "deterministic", tools: ["egress-proxy", "post-condition-check", "typed-messages"], structural: true, status: "working" },
  { id: "vault", greek: "VAULT", tier: "Structural", role: "Per-agent secrets injected at execution — never in context", model: "deterministic", tools: ["secret-inject"], structural: true, status: "working" },
];

/* ---------------- OPPLAN objectives (Decepticon DAG contract) ---------------- */

export const OPPLAN = [
  {
    id: "OBJ-1", title: "Read payment records from lab tenant", chain: "C-01", stage: "execution",
    deps: [], state: "complete",
    evidence: [
      { kind: "proof", ref: "F-0001 · SQLi auth bypass — PoV: role=admin in response", ok: true },
      { kind: "verification", ref: "CERBERUS post-condition: payment row retrieved", ok: true },
    ],
  },
  {
    id: "OBJ-2", title: "DA equivalence in lab forest", chain: "C-02", stage: "execution",
    deps: [], state: "complete",
    evidence: [
      { kind: "proof", ref: "F-0006 · Kerberoast → delegation path", ok: true },
      { kind: "verification", ref: "SOCRATES counter-play deflected; graph path confirmed", ok: true },
    ],
  },
  {
    id: "OBJ-3", title: "Extract one canary secret via poisoned agent", chain: "C-03", stage: "execution",
    deps: [], state: "blocked",
    evidence: [
      { kind: "proof", ref: "F-0008 · MCP tool-description injection — canary tool triggered", ok: true },
      { kind: "verification", ref: "Host-plane write gate PENDING — objective cannot complete without approval", ok: false },
    ],
    blockedBy: "HERMES approval queue — fail-safe: no response = deny",
  },
  {
    id: "OBJ-4", title: "Independent verification: reproduce F-0007 (CMS deserialization RCE) on clean session", stage: "verification",
    deps: [], state: "ready",
    evidence: [{ kind: "prerequisite", ref: "F-0007 sealed by THEMIS; clean-session replay scheduled", ok: true }],
  },
  {
    id: "OBJ-5", title: "Owner report: chains, fixes, purple-team package", stage: "reporting",
    deps: ["OBJ-4"], state: "waiting",
    evidence: [],
  },
];

/* ---------------- Findings pool ---------------- */

export const FINDINGS_SEED = [
  { id: "F-0001", sev: "critical", vector: "web", target: "lab-api.g9.local", title: "SQL injection in /api/v1/orders — auth bypass to admin session", evidence: "Union-based extraction; session cookie minted for role=admin via login bypass PoC.", remediation: "Parameterize queries at the DAL; reject duplicate role fields in session issuance.", verification: "Re-run PoC after patch — login bypass must fail closed; add regression case to ACADEMY.", cve: null, pov: "authenticated response contains role=admin", status: "verified" },
  { id: "F-0002", sev: "critical", vector: "web", target: "lab-api.g9.local", title: "JWT alg confusion — token accepted with algorithm 'none'", evidence: "Forged token with alg=none and role=auditor accepted by /api/v1/reports.", remediation: "Pin allowed algorithms server-side; enforce key-id binding; reject unsigned tokens.", verification: "Signed token suite replay — all 'none' tokens must 401.", cve: null, pov: "HTTP 200 on forged token", status: "verified" },
  { id: "F-0003", sev: "high", vector: "web", target: "lab-portal.g9.local", title: "IDOR — object-level authz missing on /api/v1/invoices/{id}", evidence: "Sequential ids of other lab tenants readable with low-priv token.", remediation: "Server-side ownership check on every object access; authz matrix tests in CI.", verification: "Cross-tenant read replay must 403.", cve: null, pov: "foreign-tenant invoice body retrieved", status: "verified" },
  { id: "F-0004", sev: "critical", vector: "cloud", target: "lab-edge.g9.local", title: "SSRF to cloud metadata (IMDSv1) — role credentials exposed", evidence: "SSRF in webhook tester reaches 169.254.169.254; role keys retrieved.", remediation: "Enforce IMDSv2 (token required); egress-filter link-local from app tier; allowlist webhook destinations.", verification: "Metadata request replay must return 401.", cve: null, pov: "role access key material returned", status: "verified" },
  { id: "F-0005", sev: "high", vector: "svc", target: "lab-sw-01.g9.local", title: "SNMP public community string exposes full network map", evidence: "snmpwalk returns interface table, routes, connected hosts — near-total recon value.", remediation: "Remove default community; SNMPv3 authPriv; restrict to management VLAN.", verification: "Default string walk must time out.", cve: null, pov: "walk returned route table", status: "verified" },
  { id: "F-0006", sev: "critical", vector: "ident", target: "lab-dc-01.g9.local", title: "Constrained delegation path: svc-build → DC via Kerberoast", evidence: "SPN found for svc-build; roastable hash cracked offline; delegation path to DC confirmed in graph.", remediation: "Rotate svc-build (long, random); enforce AES-only; remove unconstrained pattern; mark delegation edges in the identity graph for monitoring.", verification: "Graph query post-fix must show no shortest path to DA under 4 hops for the account.", cve: null, pov: "DC session obtained in lab", status: "verified" },
  { id: "F-0007", sev: "critical", vector: "web", target: "lab-cms.g9.local", title: "Zero-day: Java deserialization RCE in internal CMS plugin (no CVE)", evidence: "Gadget chain confirmed via TALOS RE of plugin jar; execution-grounded PoV: id command output from target.", remediation: "Remove/patch plugin; kill native deserialization at the boundary; add gadget-chain signature to DAEDALUS.", verification: "Deserialization probe must fail; canary class tripwire stays armed.", cve: null, zeroDay: true, pov: "command output contains host marker", status: "verified" },
  { id: "F-0008", sev: "high", vector: "ai", target: "lab-agentgw.g9.local", title: "Zero-day: MCP tool-description injection in internal agent gateway", evidence: "Tool description field on internal MCP server carries injected instructions; consuming agent follows them (canary tool triggered).", remediation: "Treat tool descriptions as untrusted data; schema-validate; strip instruction-like content at gateway; pin server identities.", verification: "Injection corpus replay must show zero canary activations.", cve: null, zeroDay: true, pov: "canary tool invoked by consuming agent", status: "verified" },
  { id: "F-0009", sev: "high", vector: "web", target: "lab-shop.g9.local", title: "Zero-day: race condition on coupon redemption (double-spend)", evidence: "Concurrent-requests replay redeems one coupon 3× with visible balance delta.", remediation: "Idempotency key + row-level lock on redemption; deny-on-conflict.", verification: "Concurrent replay must yield exactly one redemption.", cve: null, zeroDay: true, pov: "balance delta ×3 observed", status: "verified" },
  { id: "F-0010", sev: "medium", vector: "web", target: "staging.g9.local", title: "Exposed .git directory on staging host", evidence: ".git/config and objects retrievable; source + history reconstructable.", remediation: "Block .git at web server; scrub from artifact pipeline.", verification: "GET /.git/config must 404.", cve: null, pov: "config file body retrieved", status: "verified" },
  { id: "F-0011", sev: "medium", vector: "svc", target: "lab-icmpv6.g9.local", title: "IPv6 neighbor discovery bypasses IPv4-only ACLs", evidence: "Management interface reachable over IPv6 while IPv4 is filtered.", remediation: "Mirror ACLs to IPv6; disable unused IPv6 on management plane.", verification: "IPv6 probe must be filtered.", cve: null, pov: "banner grab succeeded over IPv6", status: "verified" },
  { id: "F-0012", sev: "medium", vector: "web", target: "lab-api.g9.local", title: "GraphQL introspection enabled + excessive query depth", evidence: "Full schema extracted; nested query at depth 14 causes 2.1s DB stalls.", remediation: "Disable introspection in prod; depth/complexity limits; persisted queries only.", verification: "Introspection query must error; depth-15 query must reject.", cve: null, pov: "schema dump returned", status: "verified" },
];

export const FINDINGS_LATER = [
  { id: "F-0013", sev: "high", vector: "web", target: "lab-mail.g9.local", title: "Password reset token predictability (time-seeded)", evidence: "30 tokens collected; all predicted offline — entropy far below spec.", remediation: "CSPRNG tokens, single-use, short TTL, bind to session.", verification: "Predict-attempt on 20 fresh tokens must succeed 0 times.", cve: null, pov: "token predicted before use", status: "candidate" },
  { id: "F-0014", sev: "critical", vector: "cloud", target: "lab-artifacts.g9.local", title: "Anonymous write to CI artifact bucket → build poisoning path", evidence: "Bucket policy allows anonymous PutObject; artifact consumed by build runner.", remediation: "Deny anonymous writes; signed uploads; provenance verification at build ingest.", verification: "Anonymous PUT must 403; SBOM check gates the runner.", cve: null, pov: "poisoned artifact consumed by runner", status: "candidate" },
  { id: "F-0015", sev: "high", vector: "ai", target: "lab-rag.g9.local", title: "RAG corpus poisoning — injected doc steers future answers", evidence: "Planted canary doc in knowledge corpus retrieved by 100% of relevant queries; canary phrase surfaced in answer.", remediation: "Provenance tags on ingest; write-scoped uploads; canary docs in corpus; retrieval-side tripwires.", verification: "Canary doc must never surface post-fix.", cve: null, zeroDay: true, pov: "canary phrase surfaced in answer", status: "candidate" },
  { id: "F-0016", sev: "medium", vector: "osint", target: "public surface", title: "Credential pattern leak: breach-data password patterns match admin set", evidence: "PANOPTES passive correlation: 2 of 11 admin accounts match breached-pattern class (no live credentials used).", remediation: "Rotation + banned-password list by pattern class; MFA on all admin.", verification: "Next credential audit shows zero pattern matches.", cve: null, pov: "pattern match score", status: "candidate" },
  { id: "F-0017", sev: "low", vector: "svc", target: "lab-vpn.g9.local", title: "TLS certificate near-expiry on VPN gateway (11 days)", evidence: "Certificate transparency + endpoint probe.", remediation: "Automated renewal; expiry alerting at 30 days (HEPHAESTUS rule).", verification: "Certificate lifetime above 60 days after renewal.", cve: null, pov: "probe data", status: "candidate" },
];

/* ---------------- Chains ---------------- */

export const CHAINS = [
  {
    id: "C-01", name: "Order API → Cloud Keys → Payment Records", objective: "Read payment records from lab tenant", cost: 8.4,
    status: "verified",
    nodes: [
      { id: "n0", label: "vhost discovery\nlab-api", type: "recon", x: 40, y: 150, verified: true },
      { id: "n1", label: "SQLi auth bypass\nfoothold", type: "foothold", x: 190, y: 80, verified: true },
      { id: "n2", label: "admin session\ncredential", type: "cred", x: 340, y: 80, verified: true },
      { id: "n3", label: "webhook SSRF\npivot", type: "pivot", x: 340, y: 220, verified: true },
      { id: "n4", label: "metadata creds\n(IMDSv1)", type: "cred", x: 490, y: 220, verified: true },
      { id: "n5", label: "read payment records\nOBJECTIVE", type: "objective", x: 640, y: 150, verified: true },
    ],
    edges: [["n0", "n1"], ["n1", "n2"], ["n2", "n3"], ["n3", "n4"], ["n4", "n5"]],
    findings: ["F-0001", "F-0004", "F-0003"],
  },
  {
    id: "C-02", name: "Identity Path: Kerberoast → Delegation → DC", objective: "Domain admin equivalence in lab forest", cost: 12.1,
    status: "verified",
    nodes: [
      { id: "m0", label: "SMB null session\nuser list", type: "recon", x: 40, y: 150, verified: true },
      { id: "m1", label: "SPN found\nsvc-build", type: "recon", x: 190, y: 150, verified: true },
      { id: "m2", label: "Kerberoast\noffline crack", type: "cred", x: 340, y: 80, verified: true },
      { id: "m3", label: "delegation abuse\npath to DC", type: "privesc", x: 490, y: 150, verified: true },
      { id: "m4", label: "DA equivalence\nOBJECTIVE", type: "objective", x: 640, y: 150, verified: true },
    ],
    edges: [["m0", "m1"], ["m1", "m2"], ["m2", "m3"], ["m3", "m4"]],
    findings: ["F-0006", "F-0005"],
  },
  {
    id: "C-03", name: "Agent Gateway: MCP Poisoning → Vault Secret", objective: "Extract one canary secret via poisoned agent", cost: 5.7,
    status: "candidate",
    nodes: [
      { id: "p0", label: "MCP server enum\ninternal gateway", type: "recon", x: 40, y: 150, verified: true },
      { id: "p1", label: "tool-description\ninjection", type: "foothold", x: 190, y: 150, verified: true },
      { id: "p2", label: "consuming agent\nhijacked", type: "pivot", x: 340, y: 80, verified: true },
      { id: "p3", label: "canary tool call\nPENDING GATE", type: "objective", x: 490, y: 150, verified: false },
    ],
    edges: [["p0", "p1"], ["p1", "p2"], ["p2", "p3"]],
    findings: ["F-0008"],
  },
];

/* ---------------- Feed templates ---------------- */

export const FEED_POOL = [
  { agent: "panoptes", greek: "PANOPTES", kind: "recon", msg: "Passive DNS sweep: subdomain deltas logged for {t}" },
  { agent: "panoptes", greek: "PANOPTES", kind: "recon", msg: "Certificate transparency pull: {n} new certs mapped to lab namespace" },
  { agent: "hydra-web", greek: "HYDRA-WEB", kind: "scan", msg: "Deep crawl of {t}: {n} endpoints, {n2} params mined from JS bundles" },
  { agent: "hydra-svc", greek: "HYDRA-SVC", kind: "scan", msg: "Scoped service sweep: {n} services fingerprinted, {n2} versions pinned" },
  { agent: "hydra-ident", greek: "HYDRA-IDENT", kind: "scan", msg: "Identity graph updated: delegation edges re-scored ({n} paths re-ranked)" },
  { agent: "hydra-cloud", greek: "HYDRA-CLOUD", kind: "scan", msg: "Bucket & metadata audit pass complete on lab-edge tenant ({n} policies checked)" },
  { agent: "hydra-ai", greek: "HYDRA-AI", kind: "scan", msg: "Injection corpus replay against lab-agentgw: {n}/40 probes, zero canary hits post-control" },
  { agent: "argus", greek: "ARGUS", kind: "finding", msg: "Variant analysis: hypothesis set regenerated for target diff (commit delta applied)" },
  { agent: "argus", greek: "ARGUS", kind: "finding", msg: "AI-fuzz union: {n} new crash triages queued for THEMIS review" },
  { agent: "talos", greek: "TALOS", kind: "finding", msg: "Scoped Ghidra API: plugin jar analyzed, gadget chain candidates narrowed to {n}" },
  { agent: "metis", greek: "METIS", kind: "intel", msg: "Advisory watch: {n} new advisories matched against target stack versions" },
  { agent: "chimera", greek: "CHIMERA", kind: "chain", msg: "Chain graph re-ranked: shortest path to objective reduced by 1 hop" },
  { agent: "chimera", greek: "CHIMERA", kind: "chain", msg: "Chain step evidence sealed and hashed ({n} links verified)" },
  { agent: "mnemosyne", greek: "MNEMOSYNE", kind: "gate", msg: "Memory integrity sweep: versioned writes only, canary memories intact" },
  { agent: "themis", greek: "THEMIS", kind: "gate", msg: "Evidence verdict: candidate finding accepted — PoV check is deterministic" },
  { agent: "socrates", greek: "SOCRATES", kind: "gate", msg: "Adversarial review: chain C-01 survives counter-play ({n} attacks deflected)" },
  { agent: "cerberus", greek: "CERBERUS", kind: "gate", msg: "Egress proxy: {n} requests allowed, {n2} blocked (out-of-scope host)" },
  { agent: "helios", greek: "HELIOS", kind: "intel", msg: "GPU schedule: red-tier batch served from local weights (no external calls)" },
  { agent: "orpheus", greek: "ORPHEUS", kind: "intel", msg: "Tradecraft retrieval: {n} prior plays matched to current surface" },
  { agent: "prometheus", greek: "PROMETHEUS", kind: "intel", msg: "Eval gate: red model regression suite green ({n} benchmarks, zero regression)" },
  { agent: "atlas", greek: "ATLAS", kind: "gate", msg: "OPPLAN dispatch: objective bound to workflow stage under pinned snapshot (hash verified)" },
];

/* ---------------- Planning documents (Soundwave set) ---------------- */

export const PLANNING_DOCS = [
  { file: "plan/roe.json", owner: "Operator (provisioned — Soundwave cannot rewrite it)", purpose: "Approved scope, techniques, window, deconfliction", present: true },
  { file: "plan/threat-profile.json", owner: "Soundwave (optional)", purpose: "Adversary model & relevant techniques", present: true },
  { file: "plan/conops.json", owner: "Soundwave (optional)", purpose: "Operational concept within reviewed scope", present: true },
  { file: "plan/deconfliction.json", owner: "Soundwave (optional)", purpose: "Operator identifiers & coordination", present: true },
  { file: "plan/contact.json", owner: "Soundwave (optional)", purpose: "Contacts & escalation", present: true },
  { file: "plan/data-handling.json", owner: "Soundwave (optional)", purpose: "Evidence handling & retention", present: true },
  { file: "plan/abort.json", owner: "Soundwave (optional)", purpose: "Stop conditions & response", present: true },
  { file: "plan/cleanup.json", owner: "Soundwave (optional)", purpose: "Expected artifacts & cleanup approach", present: false },
];
