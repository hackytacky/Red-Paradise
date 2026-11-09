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
| [final-recommendations.md](final-recommendations.md) | Final recommendations by operational priority: Tier 1–3 selections, overall verdict, the six G9 subsystems, and expanded research (Strands, Anthropic Sandbox Runtime, Graphiti, Inspect AI, Snyk Agent Scan, CALDERA MCP, CyberGym-E2E) |

## Core doctrine

1. **Separate the agent-control plane from the security-execution plane.** Models, tools, and individual security agents can then be upgraded without rebuilding the system.
2. **One authoritative mission state.** No specialist (PentAGI, RedAmon, Strix, orchestrator) independently decides engagement scope or final finding status. Specialists submit structured observations; the central verifier decides what becomes a confirmed finding.
3. **Code-enforced verdicts.** A model never promotes its own finding to confirmed status; evidence requirements are explicit and machine-checked.
4. **Benchmark claims are developer-reported until independently established.** Scores below are architectural-suitability assessments, not measured success rates.
