# Agent Frameworks & AI Red-Team Stack

A strong penetration-testing agent does not necessarily provide the best
general-purpose orchestration infrastructure. G9 separates the **agent-control
plane** from the **security-execution plane** so models, tools, and individual
security agents can be upgraded without rebuilding the system.

## Ranked general-purpose agent frameworks

| Rank | Repository | G9 score | Top five strengths | Recommended role |
|---|---|---|---|---|
| **1** | LangGraph (langchain-ai/langgraph) | **9.4/10** | Stateful graphs; durable execution; conditional branching; human approval checkpoints; agent coordination | **Primary orchestration candidate** |
| **2** | Pydantic AI (pydantic/pydantic-ai) | **9.2/10** | Typed tool inputs; validated outputs; provider flexibility; evaluation support; instrumentation | **Agent and tool contracts** |
| **3** | OpenAI Agents SDK (openai/openai-agents-python) | **8.9/10** | Agent handoffs; execution loops; guardrails; tracing; tool integration | Lightweight agent alternative |
| **4** | Microsoft Agent Framework (microsoft/agent-framework) | **8.8/10** | Multi-agent workflows; production-oriented APIs; MCP/A2A interoperability; provider support; cross-runtime integration | Enterprise orchestration alternative |
| **5** | OpenHands (OpenHands/OpenHands) | **8.6/10** | Codebase navigation; coding agents; repository modifications; software debugging; sandboxed development workflows | Security development and remediation agent |
| **6** | CrewAI (crewAIInc/crewAI) | **8.0/10** | Role-based agents; delegation; collaborative tasks; workflows; rapid prototyping | Prototyping alternative |
| **7** | AutoGen (microsoft/autogen) | **4.5/10** | Agent collaboration; conversational coordination; tool execution; research patterns; orchestration examples | **Historical reference only** |

### Preferred combination: LangGraph + Pydantic AI

- **LangGraph** handles the lifecycle of investigations: branching, retries,
  checkpointing, persistent state, and human intervention.
- **Pydantic AI** implements strongly typed agent and tool boundaries, structured
  responses, and validation.
- Do **not** nest two competing agent runtimes. Use LangGraph for overall
  workflow control, with Pydantic-based schemas or selected Pydantic AI
  components at clear integration boundaries.
- Alternative: build on **Microsoft Agent Framework** if cross-runtime
  interoperability becomes a dominant requirement.

### AutoGen update

Microsoft's AutoGen repository is **archived and no longer maintained** and
recommends Microsoft Agent Framework for new applications. Despite its
historical popularity, it is not suitable for a new security-critical G9
control plane.

## G9 AI Security Studio — AI red-team frameworks

Conventional pentesting agents lack coverage of prompt injection, model misuse,
unsafe tool use, retrieval manipulation, and multi-turn adversarial behavior.
These frameworks belong in a dedicated **G9 AI Security Studio**.

| Rank | Repository | Score | Top five strengths | G9 integration |
|---|---|---|---|---|
| **1** | Promptfoo (promptfoo/promptfoo) | **9.3/10** | Prompt-injection testing; agent/RAG evaluations; test configuration; CI/CD regression; model comparison | **Core automated AI security evaluation** |
| **2** | Microsoft PyRIT (microsoft/PyRIT) | **9.2/10** | Adaptive adversarial testing; multi-turn attacks; attack orchestration; scoring; reusable datasets | **Core AI red-team engine** |
| **3** | NVIDIA Garak (NVIDIA/garak) | **9.0/10** | Vulnerability probes; automated test suites; attack detectors; model scanning; extensibility | **Broad AI vulnerability scanner** |
| **4** | DeepTeam (confident-ai/deepteam) | **8.7/10** | Red-team simulation; agent evaluation; vulnerability assessment; attack generation; test reporting | Supplemental AI testing |
| **5** | AgentDojo (ethz-spylab/agentdojo) | **8.5/10** | Prompt-injection research; agent attack scenarios; controlled evaluations; reproducibility; defense comparison | **Agent-security benchmark suite** |

These scores are based on **G9's AI security requirements**, not claims that one
framework finds more vulnerabilities than every alternative.

### Division of responsibilities

- **Promptfoo:** continuous regression testing for prompts, RAG systems,
  tool-calling agents, and AI applications.
- **PyRIT:** adaptive adversarial evaluation, including multi-turn attack
  strategies.
- **Garak:** broad automated probing across recognized LLM vulnerability
  categories.
- **DeepTeam:** additional scenario-based testing and evaluation.
- **AgentDojo:** controlled experiments measuring agent susceptibility to
  indirect prompt injection and related tool-use attacks.

### Evidence-preservation requirement

The integration must preserve raw attack transcripts, model configurations,
expected outcomes, observed outcomes, and test-environment versions. This lets
G9 measure improvements rather than simply generate impressive-looking red-team
reports.
