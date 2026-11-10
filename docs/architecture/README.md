# G9 SPECTRE — Architecture Documentation

Security Intelligence Platform. This set defines the target architecture for the
G9 platform: which external projects to draw from, in what priority order, what
the control/execution split looks like, and which custom capabilities
differentiate G9 from ordinary AI-pentesting wrappers.

| Document | Contents |
|---|---|
| [spectre-platform.md](spectre-platform.md) | Platform diagram, integration priorities 1–5, component-to-implementation map, critical design rules |
| [landscape-comparison.md](landscape-comparison.md) | Project landscape: strengths, limitations, capability scoring, category winners, and the five indicators of actual agent intelligence |
| [agent-and-ai-redteam-frameworks.md](agent-and-ai-redteam-frameworks.md) | General-purpose agent framework rankings, the LangGraph + Pydantic recommendation, and the AI red-team stack (PyRIT / Promptfoo / Garak / DeepTeam / AgentDojo) |
| [custom-capabilities.md](custom-capabilities.md) | The five custom capabilities that differentiate G9: Evidence Graph, Research Analyst, Verification Authority, Adaptive Scheduler, Adversarial Resilience Layer |
| [framework-mapping.md](framework-mapping.md) | Operator framework requirements mapped to implementations: MCP tool-family contracts, execution sandbox, findings graph, evidence store, deterministic validators, budget/scope controller |
| [adapter-approval-list.md](adapter-approval-list.md) | The full tool arsenal for operator admission: container-class scanners, KVM-class research tools, and the AI red-team stack, with licenses and standing rules |
| [feed-adapters.md](feed-adapters.md) | Threat-intel feed adapters (Shodan, Censys, abuse.ch, AlienVault OTX) behind the same gated chain — API keys passed as env-var names only, never on the command line |
| [persistence.md](persistence.md) | Stage 04 durable storage behind the existing contracts: SQLite reference store, tampered-ledger refusal on load, Postgres/Neo4j as host-side drop-ins |
| [full-test-run.md](full-test-run.md) | The one-command full test run: lab mode (loopback target + native adapters, works anywhere) and host mode (compose + pinned tool containers on the G9 host) |
| [stages-0356.md](stages-0356.md) | Stage 03 orchestrator benchmark harness (identical tasks, deterministic scorer), Stage 05 nine specialist pipelines, Stage 06 measured evaluation — recall 1.0, FP rejection 1.0, gates 2/2, with honest boundaries |
| [standout-capabilities.md](standout-capabilities.md) | The four capabilities competitors lack: Defense Cell (purple detection correlation), AI Security Studio (injection corpus + regression gate), Research Loop (Mantis-style zero-day pipeline), Advisory Watch (24/7 mode) |
| [isolation-decision.md](isolation-decision.md) | Docker vs KVM decision: hybrid isolation — containers for restricted analysis, KVM as the outer boundary for hostile research; hostile work never downgrades to a container |
| [opsec-stealth-cleanup.md](opsec-stealth-cleanup.md) | OPSEC subsystem: HYPNOS guardian — per-phase stealth gate, operator anonymity scanning, and the no-traces artifact ledger + engagement close gate |
| [tool-agnostic-execution.md](tool-agnostic-execution.md) | Priority 1 doctrine: any pentest tool (GitHub or anywhere) usable when most useful for the task — via one-time recorded admission, capability grants, and the deny-by-default policy gate |
| [g9-spectre-v3.md](g9-spectre-v3.md) | SPECTRE v3.0 final system architecture: upstream admission, execution isolation, defensive telemetry, audit of new technologies, unified intelligence graph, 14-agent roster, trusted execution model, model/compute architecture, 31-module manifest, roadmap stages 00–08, and the final triple audit |
| [final-recommendations.md](final-recommendations.md) | Final recommendations by operational priority: Tier 1–3 selections, overall verdict, the six G9 subsystems, and expanded research (Strands, Anthropic Sandbox Runtime, Graphiti, Inspect AI, Snyk Agent Scan, CALDERA MCP, CyberGym-E2E) |

## Core doctrine

1. **Separate the agent-control plane from the security-execution plane.** Models, tools, and individual security agents can then be upgraded without rebuilding the system.
2. **One authoritative mission state.** No specialist (PentAGI, RedAmon, Strix, orchestrator) independently decides engagement scope or final finding status. Specialists submit structured observations; the central verifier decides what becomes a confirmed finding.
3. **Code-enforced verdicts.** A model never promotes its own finding to confirmed status; evidence requirements are explicit and machine-checked.
4. **Benchmark claims are developer-reported until independently established.** Scores below are architectural-suitability assessments, not measured success rates.
