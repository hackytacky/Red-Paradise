# Project Landscape & Capability Comparison

All scores assess **documented architectural suitability** for each function.
They do **not** represent independently measured success rates. A score of 10
describes specialization and documented functionality — not an exploit success
rate. Scale: 10 = exceptional alignment; 5 = moderate; 1 = little relevance.

## Project strengths, limitations, and G9 use

| Project | Top five strengths | Most important limitation | G9 use |
|---|---|---|---|
| **PentestAgent** | Specialist agent teams; persistent sessions; task delegation; broad LLM support; Docker-based security-tool execution | Smaller infrastructure and verification footprint than the leaders | Study collaborative agent design |
| **Shannon** | Source-aware reasoning; web/API attack-path analysis; exploit validation; CI/CD integration; structured security reporting | AGPL-3.0 and limited focus outside application security | Evaluate as a specialist AppSec engine |
| **HexStrike AI** | Extensive tool catalog; MCP connectivity; tool selection; security automation; multi-category offensive tooling | Tool quantity does not establish reasoning quality or exploit reliability | Adapt selected tool interfaces |
| **PentestGPT** | Pentesting task trees; reasoning/generation/parsing separation; staged workflows; session persistence; local/cloud provider flexibility | Modern autonomous mode depends on coding-agent backends; older architecture is interactive | Adapt planning and state-management ideas |
| **T3MP3ST** | Coding-agent harness; multi-agent coordination; autonomous workflows; local-model integration; investigation workspace | AGPL licensing and limited independent benchmarking | Experimental G9 agent harness |
| **ARTEMIS** | Hierarchical supervision; worker delegation; task coordination; iterative investigation; agent-research instrumentation | Research prototype, not a mature security operations platform | Research hierarchical orchestration |
| **Osmedeus** | Declarative security workflows; distributed execution; conditional task routing; orchestration utilities; structured scanning pipelines | Workflow automation rather than general autonomous intelligence | Adapt deterministic workflow design |
| **DarkMoon** | Specialized security agents; local-model support; privacy gateway; multi-domain testing; controlled tool interface | GPL-3.0; some exploitation verification is agent-asserted rather than independently reproduced | Research privacy and agent specialization |
| **Pentest Swarm AI** | Swarm coordination; shared blackboard; specialist roles; distributed task selection; collaborative investigation | Developer documentation indicates more benchmark work is needed | Research decentralized coordination |
| **Vulnhuntr** | Source analysis; vulnerability hypotheses; code-path exploration; AI-assisted security review; identification of potentially exploitable conditions | Narrower scope and AGPL-3.0 | Specialist research component |
| **CyberStrikeAI** | Go implementation; MCP federation; YAML tool recipes; attack-chain visualization; audit/history features | Repository licensing was not conclusively established in this review | Study API and tool architecture |
| **CAI** | Academic agent experimentation; cybersecurity agent roles; multi-agent research; offensive workflows; evaluation concepts | Archived and no longer maintained; mixed licensing | Historical architecture reference only |

## Direct capability comparison

| Project | Recon / OSINT | Web / API | Network / infra | Reasoning / planning | Multi-agent orchestration | Evidence / validation | Local-model fit |
|---|---|---|---|---|---|---|---|
| **PentAGI** | 9 | 8 | **9** | **9** | **9** | 8 | **10** |
| **RedAmon** | **10** | 9 | 9 | **9** | **9** | 9 | 9 |
| **Strix** | 8 | **10** | 5 | 9 | 9 | **10** | 7 |
| **REA** | 4 | 5 | 5 | 9 | 8 | 9 | 8 |
| **Decepticon** | 8 | 8 | **9** | 9 | 9 | 8 | 8 |
| **PentestAgent** | 8 | 8 | 8 | 8 | 9 | 7 | 9 |
| **Shannon** | 6 | **10** | 3 | 9 | 8 | **10** | 6 |
| **HexStrike AI** | **9** | 8 | 9 | 7 | 7 | 6 | 9 |
| **PentestGPT** | 7 | 8 | 8 | 9 | 7 | 7 | 9 |
| **T3MP3ST** | 8 | 9 | 8 | 9 | 9 | 8 | 9 |
| **ARTEMIS** | 7 | 8 | 8 | **9** | **10** | 7 | 6 |
| **DarkMoon** | 8 | 8 | 8 | 8 | 9 | 7 | **10** |

## Category winners

| Category | Strongest candidate | Why |
|---|---|---|
| General autonomous pentesting | **PentAGI** | Broad execution architecture and self-hosted model flexibility |
| Reconnaissance and attack graphs | **RedAmon** | Integrated discovery and relationship-based intelligence |
| Web/API exploitation | **Strix** | Purpose-built autonomous AppSec testing |
| Source-aware AppSec | **Shannon** | Source-informed attack-path reasoning and validation |
| Adversary emulation | **Decepticon** | Operational red-team focus |
| Reverse engineering | **REA** | Agent-oriented binary and application analysis |
| Security tools via MCP | **HexStrike AI** | Large documented tool-access surface |
| Research-grade supervision | **ARTEMIS** | Hierarchical agent coordination |
| Distributed security workflows | **Osmedeus** | Declarative and distributed execution |
| Local-model privacy concepts | **DarkMoon** | Local inference and tokenization gateway |

## Measuring actual intelligence (repository marketing is unreliable)

A project may advertise 50 autonomous agents, 150 security tools, 100 solved
benchmark challenges, fully autonomous pentesting, or zero-day discovery. None
of those claims independently demonstrates stronger reasoning.

### The five indicators of actual agent intelligence

| Indicator | What it measures | Failure pattern |
|---|---|---|
| **Hypothesis quality** | Whether an agent identifies plausible vulnerabilities from incomplete evidence | Repeated irrelevant scans |
| **Adaptive planning** | Whether new observations alter the investigation appropriately | Repeating a fixed checklist |
| **Attack-chain reasoning** | Whether separate findings are connected into meaningful, validated paths | Listing unrelated CVEs |
| **Tool-use accuracy** | Whether commands, parameters, and result interpretations are correct | Invalid commands or invented outcomes |
| **Evidence discipline** | Whether claims are reproducible and independently supported | Reporting successful exploitation without proof |

**Sixth operational metric:** *useful validated findings per unit of time and
cost.* An agent that runs 40 tools and returns two verified findings may
outperform one that runs 150 tools and returns 30 unsupported allegations.
