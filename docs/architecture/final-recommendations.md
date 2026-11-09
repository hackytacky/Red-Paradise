# G9 — Final Recommendations by Operational Priority

This deliverable is a **proposed engineering architecture and implementation
specification**, not an installed or production-tested system. Public GitHub
research does not establish that an entire third-party codebase is secure.
Every selected dependency requires a pinned revision, source audit, dependency
analysis, isolated testing, and explicit approval before G9 integration.

**Architectural rule (inviolable):** security decisions must be enforced
**outside the AI model**. The model can propose, reason, and request; it cannot
grant itself permissions, expand scope, or declare its own exploitation results
independently verified.

## Tier 1 — Essential G9 foundations

These are the highest-priority investments because they determine whether the
rest of the system can be trusted.

| Component | Selection | Rationale |
|---|---|---|
| Agent runtime | **LangGraph**, pending comparison with Pydantic AI | Durable state and multi-agent workflow control |
| Authorization | **Cedar** | Fine-grained policy decisions |
| Execution isolation | **G9-specific KVM-backed broker** | Independent enforcement of scope and permissions |
| MCP infrastructure | **ToolHive** | Governed tool/server access |
| Finding verification | **Cloudflare Security Audit methodology** | Independent evidence verification |
| Vulnerability research | **Google Mantis** | Hypothesis, analysis, reproduction, and patch workflows |

## Tier 2 — Core cybersecurity capabilities

These provide the specialist capabilities needed to make G9 more than a
general-purpose coding agent.

| Component | Selection | Rationale |
|---|---|---|
| Reconnaissance | **RedAmon** | Graph-oriented attack-surface intelligence |
| Broad pentesting | **PentAGI 2.2.0+**, after isolation validation | Multi-agent security-tool execution |
| Application security | **Strix** | Specialized web/API testing |
| Reverse engineering | **REA** | Evidence-oriented binary and application analysis |
| Adversary emulation | **Decepticon**, conditional | Broader operational agent specialization |
| Vulnerability research | **OSS-CRS + Buttercup** | Fuzzing and patch-validation research |

## Tier 3 — Evaluation and operational intelligence

These components improve agent quality, detect regressions, and support
measurable engineering decisions.

| Component | Selection | Rationale |
|---|---|---|
| AI red teaming | **PyRIT** | Adaptive adversarial tests |
| AI regression testing | **Promptfoo** | Repeatable evaluations |
| Broad LLM probing | **Garak** | Additional vulnerability coverage |
| Agent-security benchmarking | **AgentDojo** | Prompt-injection and tool-use attack scenarios |
| Observability | **OpenTelemetry + Phoenix** | Agent telemetry and evaluation |
| Deterministic code analysis | **Semgrep + Joern** | Complementary static-analysis evidence |

## Overall verdict

- **Best new discovery: Google Mantis.** Contributes an organized
  vulnerability-research methodology (research, critique, reproduction,
  patch-validation) rather than simply more tools — aligned with G9's objective
  of defensible findings.
- **Best evidence-verification foundation: Cloudflare Security Audit.**
  Structured evidence states, coverage tracking, and independent verification
  address the core weakness of autonomous agents: claiming success without
  sufficient proof. Make these principles foundational to the G9 Verification
  Authority.
- **Best agent-runtime candidates: LangGraph and Pydantic AI.** LangGraph is
  the provisional selection; compare Pydantic AI Harness directly before the
  decision is final.
- **Best intelligence combination: RedAmon + REA.** Graph-driven
  reconnaissance plus lower-level reverse-engineering evidence.

**The stack:**

> LangGraph or Pydantic AI + Cedar + G9 KVM execution broker + ToolHive +
> Cloudflare verification + Google Mantis + RedAmon + PentAGI + Strix + REA +
> OSS-CRS/Buttercup + PyRIT/Promptfoo/Garak.

This addresses orchestration, authorization, execution, reconnaissance,
application testing, reverse engineering, automated vulnerability discovery,
and AI red teaming without making any one third-party agent framework
responsible for the entire system.

## The six G9 subsystems

All six use a common evidence schema and a central authorization system.

| System | Primary responsibility |
|---|---|
| **G9 COMMAND** | Mission control, engagement authorization, agent orchestration, model routing |
| **G9 INTELLIGENCE** | Reconnaissance, OSINT, threat intelligence, attack graphs, persistent memory |
| **G9 OFFENSE** | Authorized pentesting, AppSec, adversary emulation, reverse engineering |
| **G9 RESEARCH** | Vulnerability research, source analysis, fuzzing, exploitability assessment |
| **G9 DEFENSE** | Detection engineering, defensive validation, attack-to-detection correlation |
| **G9 ASSURANCE** | Independent verification, agent-security testing, isolation, telemetry, evaluation |

## Expanded research — new AI-agent harnesses, memory, and isolation

Scores measure **expected benefit to G9**, not independent proof of security or
benchmark superiority.

| Rank | Repository | G9 value | Five strongest capabilities | Recommendation |
|---|---|---|---|---|
| **1** | Strands Agents Harness SDK | **9.4/10** | Agent lifecycle control; model portability; MCP; multi-agent graphs; memory/session management | **Benchmark against LangGraph** |
| **2** | Anthropic Sandbox Runtime | **9.3/10** | Filesystem controls; network restrictions; subprocess isolation; MCP sandboxing; execution-policy configuration | **Evaluate as a secondary isolation layer** |
| **3** | Graphiti | **9.3/10** | Temporal graphs; relationship extraction; episodic memory; hybrid retrieval; graph-aware reranking | **Integrate memory concepts and evaluate code** |
| **4** | Inspect AI | **9.3/10** | Agent evaluations; tool-use scenarios; multi-turn testing; custom scorers; reproducible experiments | **Primary evaluation-framework candidate** |
| **5** | Snyk Agent Scan | **9.1/10** | MCP scanning; tool poisoning; agent-skill security; credential-risk detection; malicious-content analysis | **Add to third-party component admission testing** |

### Three important discoveries

**1. CALDERA now has a dedicated AI-assisted operations plugin.** The CALDERA
MCP project supports natural-language development of emulation content,
conversion of threat reports into STIX, and planning operations from threat
intelligence — highly relevant to moving from security research to controlled
attack emulation and defender validation. However, CALDERA's maintainers warn
that its core web application is not designed to be exposed directly to
untrusted networks. G9 should host it only within a restricted laboratory or
controlled operational enclave.

**2. CyberGym-E2E provides a better acceptance test than subjective agent
demonstrations.** The benchmark contains 920 vulnerability tasks across 139
open-source projects and measures the discover–prove–fix lifecycle through
staged checks: reproducing the original fault, verifying the patch stops the
fault, preserving functional tests, and testing against a ground-truth
reproducer. For G9 this provides a measurable method of comparing agent
harnesses, reasoning models, and vulnerability-analysis pipelines.

**3. Strands is now a genuine alternative to the previously preferred
orchestrators.** The Strands Harness SDK consolidates Python and TypeScript
agent harnesses, SDKs, tools, sessions, model-provider support, tracing, and
evaluations. Its earlier standalone TypeScript SDK was archived on June 3,
2026, with active development moved into the harness monorepo. The
orchestration competition is therefore updated to:

> **LangGraph vs. Pydantic AI Harness vs. Strands Harness SDK.**
