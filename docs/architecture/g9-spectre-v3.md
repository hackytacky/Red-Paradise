# G9 SPECTRE v3.0 — Final System Architecture

This document records the v3.0 architecture: supply-chain assurance, execution
isolation, defensive telemetry, security audit findings from the expanded
review, the unified intelligence graph, the 14-agent roster, the trusted
execution model, the model/compute architecture, the engineering module
manifest, the development roadmap with acceptance gates, and the final triple
audit.

**Status:** proposed engineering architecture and implementation
specification, not an installed or production-tested system. All acceptance
thresholds are proposed targets, not achieved measurements.

## 1. Supply-chain assurance — the Upstream Admission Service

| Repository | Function | G9 recommendation |
|---|---|---|
| OpenSSF Scorecard | Repository maintenance and supply-chain risk indicators | Use during upstream qualification |
| Syft | Generate SPDX/CycloneDX SBOMs | Use for every imported dependency |
| OSV-Scanner | Identify known vulnerable dependencies | Required vulnerability-screening component |
| Grype | Scan SBOMs, filesystems, and container images | Complement OSV-Scanner |
| Sigstore Cosign | Verify signed artifacts and provenance | Use in artifact admission |
| Trivy | Container, dependency, and configuration assessment | Optional additional scanner |

**Design improvement:** every repository considered for G9 passes through an
**Upstream Admission Service**:

```
Discovery → Identity verification → License review → Dependency inventory →
Source audit → Vulnerability assessment → Sandbox tests → Approval →
Pinned integration
```

The service records the selected commit, dependencies, known advisories,
reviewer decisions, and accepted residual risks.

**Caveat:** Scorecard evaluates repository security practices; Syft generates
SBOMs; OSV-Scanner identifies known vulnerability records. None independently
proves a project contains no exploitable vulnerabilities.

**Recommendation:** upstream admission is a **mandatory prerequisite** to
production integration. Coding agents must not silently install dependencies
discovered during an investigation.

## 2. Execution isolation

| Technology | Security model | Best G9 use |
|---|---|---|
| KVM/QEMU | Hardware-assisted virtual machines | Primary isolation for hostile artifacts and testing workers |
| Firecracker | Lightweight microVMs | Future high-throughput worker infrastructure |
| Kata Containers | VM-backed OCI workloads | Future container-compatible isolated workers |
| gVisor | Userspace application-kernel isolation | Alternative for compatible container workloads |
| Anthropic Sandbox Runtime | OS-level filesystem and network restrictions | Additional restrictions for lower-risk agent tools |

Kata uses hardware virtualization to separate the workload's guest kernel from
the host kernel; gVisor is a userspace application-kernel layer and is **not**
equivalent to a conventional virtual machine.

**Initial release:** use existing Ubuntu/KVM capabilities. Do not introduce
Kubernetes, Firecracker, Kata, and multiple OCI runtimes simultaneously — that
increases privileged infrastructure and maintenance cost.

## 3. Defensive monitoring and attack-to-detection intelligence

| Repository | Specialty | G9 contribution |
|---|---|---|
| Cilium Tetragon | eBPF security observability and runtime enforcement | Monitor process activity and selected policy violations |
| Falco | Runtime security detection | Detect suspicious execution behavior |
| SigmaHQ Sigma | Portable detection-rule specifications | Generate and validate defensive detections |
| Atomic Red Team | ATT&CK-mapped test library | Controlled technique-level validation |
| Velociraptor | Endpoint visibility, DFIR, artifact collection | Host investigation and evidence acquisition |
| osquery | SQL-based endpoint telemetry | Endpoint configuration and state inspection |

**Critical distinction:** Falco's own documentation describes it as a
**detection system, not an enforcement boundary** — it alerts but does not
block execution. Tetragon supports observability and selected runtime
enforcement. These technologies serve two separate functions: monitoring the
security of G9's own workers, and measuring the defender's visibility during
explicitly authorized emulation exercises. **Do not treat detection telemetry
as authorization enforcement.**

## 4. Security audit of newly discovered technologies

**A. ToolHive's network isolation is not a universal egress firewall —
VERIFIED, important integration limitation.** ToolHive documents local-server
isolation through an HTTP/HTTPS egress proxy; other protocols are not
filtered. Insufficient as G9's only network boundary because pentesting tools
may use raw TCP, UDP, DNS. *Decision:* ToolHive governs MCP tools; G9 enforces
network policy independently at the VM/network layer.

**B. Snyk Agent Scan has execution and data-disclosure considerations —
VERIFIED, requires operator approval.** Inspecting MCP configurations can
start configured servers and make outbound requests; analysis sends component
descriptions to Snyk's API; JSON output is not a stable production API.
*Decision:* do not enable automatically; offline source/config inspection is
the default; Snyk Agent Scan is an optional, separately approved audit utility.

**C. OpenAEV has Community and Enterprise editions — VERIFIED, commercial
feature gate.** Community is Apache-2.0; Enterprise features are separately
licensed; usage telemetry is documented. *Decision:* integrate through
documented interfaces; do not assume Enterprise functionality; review
telemetry settings before deployments involving client data.

**D. Benchmark environments may require privileged host changes — VERIFIED,
host-hardening consideration.** CyberGym-E2E's setup includes a host
ASLR-entropy change and relies on container images plus a dedicated
firewall-proxy environment. *Decision:* keep benchmark execution in disposable
research environments; do not weaken the G9 host to accommodate a benchmark.

### Additional repository-selection decisions

| Technology | Final recommendation | Reason |
|---|---|---|
| Strands Harness SDK | **Benchmark first** | Strong active alternative to existing agent runtimes |
| Graphiti | **Prototype temporal-memory adapter** | Good fit for time-sensitive security findings |
| Inspect AI | **Primary evaluation candidate** | Broad, reusable agent-evaluation infrastructure |
| CyberGym-E2E | **Primary vulnerability-lifecycle benchmark** | Measures discovery, reproduction, and patch effectiveness |
| CALDERA | **Dedicated isolated service** | Strong ATT&CK emulation capabilities |
| OpenAEV | **Evaluate as purple-team service** | Adds defensive measurement absent from basic pentesting agents |
| Microsoft GraphRAG | **Do not select as core** | Upstream is in maintenance mode |
| Snyk Agent Scan | **Optional manual evaluation** | External analysis and potentially active MCP inspection |
| Anthropic Sandbox Runtime | **Defense in depth** | Useful restrictions, but not equivalent to hardware isolation |

Microsoft states GraphRAG is largely in maintenance mode with new feature work
discontinued — making Graphiti and a G9-specific evidence schema more
attractive for new development.

## 5. Specialist engines worth retaining

| Repository | G9 value | Specific advantage | Decision |
|---|---|---|---|
| BloodHound Community Edition | **9.3/10** | Identity relationships, privilege analysis, graph-based attack-path reasoning | **Add identity-security specialist** |
| SpecterOps Nemesis | **8.9/10** | Ingestion, enrichment, and analysis of offensive-security artifacts | **Study for evidence-processing architecture** |
| Joern | **9.0/10** | Code-property graphs and vulnerability-oriented program analysis | **Add source-analysis backend** |
| angr | **9.0/10** | Symbolic execution, control/data-flow analysis, binary analysis | **Add specialist RE backend** |
| AFL++ | **9.0/10** | Coverage-guided fuzzing and instrumentation | **Add isolated fuzzing backend; license gate** |
| Nuclei | **8.8/10** | Template-driven vulnerability testing and workflow execution | **Add controlled scanning adapter** |
| OWASP Threat Dragon | **8.6/10** | STRIDE and other threat-modeling methodologies | **Adapt modeling concepts** |
| Sigma + pySigma | **9.1/10** | Detection rules, portable query conversion, threat hunting | **Add detection-engineering subsystem** |

**Why:** BloodHound CE's OpenGraph architecture extends analysis beyond AD and
Azure — more appropriate than expecting a generic recon agent to infer every
identity attack path. Nemesis informs the evidence-processing pipeline but
must not become another authoritative database. angr/AFL++ provide
deterministic analysis and fuzzing that complement LLM reasoning (AFL++ has
mixed licensing including AGPL-3.0-or-later — commercial integration requires
review). Sigma's upstream rule repository plus pySigma connect authorized
emulation exercises to detection rules, observed telemetry, and coverage gaps.

**Updated design decision:** G9 SPECTRE does not have one generic "hacking
agent." It uses specialized reasoning agents backed by domain-specific
deterministic tools, with independent verification and a shared knowledge
system.

## 6. Architecture selection

| Subsystem | Primary selection | Alternative | Decision |
|---|---|---|---|
| Agent orchestration | LangGraph | Strands / Pydantic AI | Benchmark all three; select one |
| Durable execution | Native runtime checkpointing | Temporal | Avoid a second workflow engine until justified |
| Authorization | Cedar | Custom policy evaluation | Cedar preferred |
| High-risk isolation | KVM/QEMU | Firecracker / Kata | KVM first |
| MCP gateway | ToolHive | G9-native gateway | Conditional integration |
| Structured contracts | Pydantic | JSON Schema / Protobuf | Pydantic + versioned JSON Schema |
| Application backend | FastAPI | Go services | FastAPI for initial control plane |
| Execution broker | G9-native isolated service | Existing harness broker | Build G9-owned |
| Relational storage | PostgreSQL | — | Primary source of truth |
| Semantic retrieval | pgvector | Dedicated vector database | pgvector first |
| Graph intelligence | Neo4j | Other graph databases | Neo4j |
| Temporal memory | Graphiti | G9-native temporal graph layer | Prototype and evaluate |
| Evidence verification | G9 verifier inspired by Cloudflare | Mantis validators | Independent service |
| Observability | OpenTelemetry | Phoenix | Use Phoenix when evaluation UI justifies it |
| Model evaluation | Inspect AI | Custom benchmark harness | Inspect AI preferred |
| UI | React / TypeScript | — | G9 command console |

**Key recommendation:** do not introduce another datastore, agent runtime,
container platform, or distributed workflow service unless a measurable
requirement justifies the operational cost.

## 7. Logical architecture (nine subsystems)

```
G9 SPECTRE
├── 01. COMMAND & GOVERNANCE — Command Center · Engagement Scope Manager ·
│   RoE Engine · Identity & Authorization · Human Approval Service · Audit Ledger
├── 02. AGENT INTELLIGENCE — Orchestrator · Specialist Registry · Task Planner ·
│   Model Router · Context Manager · Temporal Memory · Agent Evaluation Service
├── 03. OFFENSIVE SECURITY — Recon · OSINT · Web/API · Infrastructure ·
│   Identity/AD · Cloud · Adversary Emulation · Reverse Engineering
├── 04. VULNERABILITY RESEARCH — Source Analysis · Binary Analysis ·
│   Hypothesis Generator · Fuzzing Coordinator · Crash Triage · Patch Analysis ·
│   Reproduction/Regression Tests
├── 05. DEFENSIVE SECURITY — Threat Intelligence · Detection Engineering ·
│   Threat Hunting · Endpoint Telemetry · Exposure Validation · Purple-Team Correlation
├── 06. TRUSTED EXECUTION — Immutable Action Specification · Policy Decision
│   Point · Approval Verification · Tool Gateway · KVM Worker Manager ·
│   Network Egress Enforcement · Execution Result Collector · Worker Destruction/Recovery
├── 07. EVIDENCE & KNOWLEDGE — Ingestion · Provenance Verification · Evidence
│   Graph · Temporal Relationships · Finding Verification · Attack Flow Modeling · Reporting
├── 08. PLATFORM ASSURANCE — Upstream Admission · Dependency/SBOM Analysis ·
│   AI Red-Team Evaluations · Agent Benchmarking · Runtime Monitoring ·
│   Regression Testing · Release Qualification
└── 09. G9 USER EXPERIENCE — Mission Dashboard · Attack Graph Explorer ·
    Agent Activity Monitor · Vulnerability Research Studio · RE Studio ·
    Detection Coverage Dashboard · Model Evaluation Dashboard · Evidence/Report Workspace
```

These are **logical subsystems**, not necessarily separate processes. Keep
most trusted control-plane components in a modular application; isolate
high-risk, independently managed security engines into separate processes or
VMs.

## 8. G9 Unified Intelligence Graph

One canonical G9 evidence model — not independent knowledge graphs per engine.

### Primary entities

| Entity | Purpose | Important attributes |
|---|---|---|
| Engagement | Authorized assessment boundary | Scope, owner, dates, policy revision |
| Asset | Host, domain, service, application, repository | Identity, environment, scope |
| Identity | User, role, principal, service account | Source, permissions, validity |
| Observation | Raw technical evidence | Origin, timestamp, artifact reference |
| Hypothesis | Proposed security weakness | Supporting observations, confidence |
| Finding | Independently evaluated issue | Verification state, severity, impact |
| AttackPath | Relationships between attack-relevant facts | Ordered steps, prerequisites |
| Technique | ATT&CK/ATLAS technique | Identifier, mapping, source |
| CodeArtifact | Source file, function, binary | Hash, revision, symbol identity |
| ToolExecution | A bounded external operation | Action ID, authorization, output |
| AgentTask | Delegated reasoning assignment | Owner, state, dependencies |
| Detection | Defensive rule or observed control | Rule version, telemetry, outcome |
| Evaluation | Benchmark or regression result | Dataset, model, harness, metrics |

### Relationships

```
Asset        EXPOSES→Service · CONTAINS→Application · OWNED_BY→Engagement · ACCESSED_BY→Identity
Application  DEPENDS_ON→Component · IMPLEMENTS→Endpoint · CONTAINS→CodeArtifact
Observation  SUPPORTS→Hypothesis · PRODUCED_BY→ToolExecution · REFERENCES→EvidenceArtifact
Finding      AFFECTS→Asset · SUPPORTED_BY→Observation · VERIFIED_BY→Evaluation · ASSOCIATED_WITH→Technique
AttackPath   INCLUDES→Finding · REQUIRES→Identity · MAPS_TO→Technique
Detection    COVERS→Technique · OBSERVED_IN→ToolExecution · VALIDATED_BY→Evaluation
```

### Temporal intelligence

Every significant relationship tracks: first observed · when valid · last
verified · whether current · supporting evidence · confidence and validation
state. **Acceptance requirement:** expired or superseded facts must not
silently reappear as current security findings. Temporal memory improves
recall but must not become an authorization source.

## 9. Agent architecture — 14 specialist roles

Activated as needed, not 14 simultaneously running models.

| Agent | Specialty | Primary tools | Deliverable |
|---|---|---|---|
| 01. Mission Planner | Investigation planning, task decomposition | Orchestrator, evidence graph | Authorized task DAG |
| 02. Research Analyst | Advisories, patch intelligence, research | Research sources, source analysis | Evidence-backed hypotheses |
| 03. OSINT Analyst | External intelligence and discovery | Recon sources, RedAmon workflows | Asset intelligence |
| 04. Recon Analyst | Network/service mapping | Approved scanners, discovery adapters | Verified asset inventory |
| 05. AppSec Specialist | Web applications and APIs | Strix-derived service, Nuclei, code analysis | Application findings |
| 06. Infrastructure Specialist | Systems, services, network security | PentAGI-derived execution service | Infrastructure findings |
| 07. Identity Specialist | AD, identity relationships, privilege | BloodHound-derived integration | Identity attack paths |
| 08. Cloud Specialist | Cloud IAM and security posture | Approved cloud assessment adapters | Cloud risk findings |
| 09. Reverse Engineer | Binary and firmware analysis | REA, angr, disassemblers | Binary intelligence |
| 10. Vulnerability Researcher | Code weaknesses, fuzzing, root cause | Mantis, Joern, AFL++, OSS-CRS | Reproduced vulnerability hypotheses |
| 11. Adversary Emulation Specialist | ATT&CK-informed defensive exercises | CALDERA, OpenAEV | Technique execution and coverage |
| 12. AI Security Specialist | LLM, RAG, MCP, and agent security | PyRIT, Promptfoo, Garak, AgentDojo | AI security assessments |
| 13. Detection Engineer | Defensive telemetry and rule development | Sigma, pySigma, telemetry systems | Tested detections |
| 14. Reporting Analyst | Technical findings and evidence summaries | Evidence graph, reporting schemas | Reproducible reports |

**Two functions must NOT be ordinary LLM agents:**
- **Authorization Authority** — a deterministic policy service backed by trusted engagement data.
- **Finding Verification Authority** — an independent evidence-processing service with optional specialist AI review.

This prevents a model from authorizing its own actions or independently
certifying its own conclusions.

### Agent execution rules

Agents may request other agents to analyze information; they may not
automatically delegate execution authority. (Research Analyst → AppSec
Specialist may pass a hypothesis + evidence; the AppSec Specialist must
independently request permission for any external test; the original agent's
permissions are never inherited implicitly.)

1. Every agent action has an identifiable parent task.
2. Delegated permissions cannot exceed the originating authorization.
3. Tool execution requires an independently validated capability.
4. Results are tagged with model, version, and tool provenance.
5. Agents cannot alter confirmed evidence records.
6. Failure, cancellation, and resumption are explicit states.

## 10. Trusted execution model

An agent-generated command is never executed solely because it conforms to the
expected JSON schema. The execution broker evaluates the full intended action.

### Canonical action specification

| Field | Purpose |
|---|---|
| action_id | Unique operation identity |
| engagement_id | Authorized engagement |
| principal_id | Requesting identity |
| agent_id | Requesting agent |
| tool_id | Approved tool |
| tool_version | Exact tool build |
| normalized_arguments | Exact execution inputs |
| target_set | Authorized targets |
| working_directory | Execution location |
| environment_profile | Permitted environment |
| sandbox_profile | Isolation requirements |
| network_policy_id | Network constraints |
| resource_budget | CPU, memory, time, traffic limits |
| approval_id | Operator approval reference |
| policy_revision | Authorization-policy version |
| spec_digest | Integrity reference |

The specification is canonicalized and approval is bound to its digest. **Any
change to authorization-relevant arguments, targets, or environment settings
invalidates the approval.**

### Approval state machine

```
CREATED → SCHEMA_VALIDATED → POLICY_EVALUATED ──(deny)──→ DENIED
                                      │
                        (approval required) → AWAITING_APPROVAL ──(reject)──→ REJECTED
                                      │ (approve)
                                    APPROVED → PRE_EXECUTION_VALIDATION ──(changed)──→ INVALIDATED
                                      │
                                 DISPATCHED → RUNNING ──(cancel/fail/unknown)──→ CANCELLED / FAILED / OUTCOME_UNKNOWN
                                      │
                                 COMPLETED → EVIDENCE_PRESERVED
```

**OUTCOME_UNKNOWN is essential.** A worker may crash after performing an
external action but before the broker records its result. **Do not
automatically replay such actions** — require reconciliation of execution
evidence before allowing retries. Exactly-once external side effects cannot be
assumed merely because a workflow engine provides durable state.

### Network isolation requirements

The execution broker enforces: engagement-specific destination policy · IPv4
and IPv6 restrictions · DNS-resolution and DNS-rebinding defenses · egress
limits · unauthorized-proxy-bypass prevention · cloud-metadata-endpoint
blocking · host/management-network restrictions · **non-HTTP protocol
coverage** · separation of test traffic from control-plane traffic. The
model's assessment of whether an address is in scope never substitutes for
these controls.

### Worker isolation (three classes)

| Class | Workload | Isolation |
|---|---|---|
| **Trusted service** | API, policy engine, database access | Hardened host service |
| **Restricted analysis worker** | Parsing, read-only analysis, approved utilities | Restricted process/container sandbox |
| **Hostile research worker** | Untrusted binaries, generated PoCs, fuzzing | Disposable KVM guest |

Hostile research workers receive no G9 management credentials — only the
minimum inputs and capabilities required for their task. No worker accesses
the host's unrestricted Docker daemon.

## 11. Model and compute architecture

Assumed hardware: RTX 5080 (16 GB GDDR7 VRAM, per NVIDIA's published spec) ·
64 GB DDR5 · Ryzen 7 9800X3D (9950X if upgraded) · Ubuntu 26.04.1 LTS ·
2 TB SSD · KVM/QEMU isolation · AppArmor · local-first AI with approved cloud
escalation. CPU-dependent choices remain configurable until the final
processor is confirmed.

### Model routing (shared inference service, task-aware)

| Task category | Preferred model |
|---|---|
| Tool-result normalization | Deterministic parser / small local model |
| Basic classification | Small local model |
| Recon correlation | Local 7B–14B-class model |
| Technical reasoning | Strong local model or approved cloud reasoning model |
| Complex code analysis | Specialist coding model |
| Reverse-engineering interpretation | Specialist reasoning model |
| Final report generation | Local model plus strict schema validation |
| Independent adjudication | Separate reasoning pass with underlying evidence |

A 35B model at 4-bit precision requires ~17.5 GB for raw weights alone —
before metadata and runtime overhead — so a 35B model generally requires
offloading or memory compromises on a 16 GB card. A 35B MoE with fewer active
parameters reduces computation but not the weight-storage problem.

**Recommendation:** prioritize a strong quantized 7B–14B local cybersecurity
model for routine agent work and approved frontier-model escalation for
difficult reasoning.

### Model evaluation

Every candidate model is tested with the **same harness, tools, task set,
resource limits, and evidence verifier** — otherwise harness-behavior
differences distort the comparison. Core suites: Inspect AI + CyberGym-E2E,
supplemented by G9's own held-out tests. Measure: valid tool-call percentage ·
task completion · verified findings · false-positive rate · context retention ·
unauthorized-action attempts · inference latency · GPU memory usage · total
task cost. The best model produces the strongest **validated operational
results**, not the highest general coding leaderboard score.

## 12. Engineering module manifest

| Module | Responsibility | Dependencies | Acceptance criterion |
|---|---|---|---|
| g9-core | Shared contracts, errors, identifiers | None | Versioned schemas and compatibility tests |
| g9-config | Configuration validation | Core | Invalid configuration rejected |
| g9-identity | Users, roles, service principals | Core | Identity-bound authorization |
| g9-scope | Engagement and target restrictions | Core, Identity | Scope-bypass tests fail safely |
| g9-policy | Cedar policy evaluation | Scope, Identity | Deny-by-default tests |
| g9-approval | Exact-action approval | Policy | Altered actions invalidate approval |
| g9-audit | Tamper-evident activity records | Core | Detectable record modification |
| g9-tasks | Durable task management | Core, Audit | Recovery without unintended replay |
| g9-agents | Agent lifecycle and delegation | Tasks, Policy | Delegation cannot escalate privileges |
| g9-models | Local/cloud inference routing | Core, Policy | Approved provider selection |
| g9-tool-registry | Tool metadata and contracts | Core | Tool registration requires qualification |
| g9-executor | Trusted execution broker | Policy, Approval | Unauthorized execution blocked |
| g9-sandbox | Worker lifecycle and isolation | Executor | Isolation boundary tests |
| g9-evidence | Artifact ingestion and provenance | Core, Audit | Artifact integrity and traceability |
| g9-verifier | Independent result validation | Evidence | Unsupported findings not confirmed |
| g9-graph | Evidence and attack graph | Evidence | Correct relationships and isolation |
| g9-memory | Temporal/context retrieval | Graph | Expired facts not treated as current |
| g9-recon | Asset intelligence | Agents, Executor, Evidence | Scope-safe discoveries |
| g9-appsec | Application testing | Agents, Executor, Verifier | Reproducible findings |
| g9-infra | Infrastructure testing | Agents, Executor | Bounded tool execution |
| g9-identity-security | Identity attack-path analysis | Graph, Evidence | Verified identity relationships |
| g9-reverse | REA, angr, binary intelligence | Sandbox, Evidence | Source-linked binary findings |
| g9-research | Fuzzing and code research | Sandbox, Verifier | Reproducible faults and patches |
| g9-emulation | ATT&CK-based operations | Executor, Policy | Authorized emulation only |
| g9-detection | Sigma and telemetry correlation | Evidence, Graph | Tested detection coverage |
| g9-ai-security | LLM/agent security evaluation | Agents, Sandbox | Repeatable adversarial evaluations |
| g9-evals | Benchmarks and regression testing | Agents, Models, Verifier | Reproducible metrics |
| g9-reporting | Reports, SARIF, exports | Verifier, Graph | Traceable claims |
| g9-api | External interfaces | Trusted service modules | Authenticated, validated APIs |
| g9-console | Operator interface | API | Accessible and auditable workflows |
| g9-upstream | Repository qualification | Audit, Evidence | Only approved components admitted |

**Architecture recommendation:** initially implement g9-core, g9-config,
g9-identity, g9-scope, g9-policy, g9-approval, g9-audit, and g9-tasks as a
**modular control-plane application**. Do not immediately create 30
independently deployed services; separate processes are justified only for
components with materially different security, scaling, or lifecycle
requirements.

## 13. Development roadmap and acceptance gates

- **Stage 00 — Source qualification and architecture freeze.** Candidate
  manifest, selected revisions, licensing matrix, dependency/SBOM inventory,
  security-review ledger, ADRs, threat model, initial benchmark spec.
  **STOP/GO:** no third-party execution code is integrated before its
  qualification gates are satisfied.
- **Stage 01 — Trusted command plane.** Core contracts, identity, engagement
  scope, policy decisions, exact-action approvals, audit records, durable task
  lifecycle. **Acceptance:** authorization cannot be bypassed by malformed
  requests, agent-generated instructions, or modified action parameters.
- **Stage 02 — Isolated execution.** Worker manager, KVM guest lifecycle,
  network isolation, resource controls, tool-input validation, execution
  telemetry, worker cleanup. **Acceptance:** workers cannot reach unauthorized
  networks, host credentials, or trusted management services.
- **Stage 03 — Agent orchestration.** Benchmark LangGraph, Strands, and
  Pydantic AI on the same tests; select one. Model routing, specialist roles,
  delegation, cancellation, recovery. **Acceptance:** replayed workflows do not
  cause unintended repeated external actions.
- **Stage 04 — Evidence intelligence.** Artifact storage, provenance,
  independent finding verification, graph relationships, temporal state,
  Attack Flow export. **Acceptance:** findings and relationships trace to
  authoritative source artifacts.
- **Stage 05 — Specialist integrations.** In order: recon/graph → web/API →
  infrastructure → reverse engineering → identity security → code-vulnerability
  research → adversary emulation → defensive validation → AI security testing.
  **Acceptance:** each specialist operates through the same authorization,
  evidence, and task contracts.
- **Stage 06 — Evaluation and hardening.** Controlled benchmarks for agent
  reasoning, tool invocation, findings, prompt-injection resistance,
  delegation, scope enforcement, resource usage, recovery, reporting accuracy.
  **Acceptance:** measurable results recorded; regressions block promotion.
- **Stage 07 — G9 command console.** Mission management, approval review,
  agent activity, investigation timeline, evidence graph, vulnerability
  research, detection coverage, model evaluations, reporting. **Acceptance:**
  operators can inspect, suspend, cancel, and audit any active mission.
- **Stage 08 — Release qualification.** Complete technical, adversarial, and
  acceptance audits. **Production release is prohibited until critical
  security findings are resolved and all mandatory acceptance tests pass.**

## 14. Final triple audit

### Technical audit

| Finding | Severity | Required correction |
|---|---|---|
| Multiple competing agent runtimes | High | Select one top-level runtime through benchmarking |
| Excessive microservice decomposition | Medium | Begin with a modular control plane |
| Multiple independent evidence databases | High | Establish canonical evidence contracts |
| Uncontrolled third-party dependencies | High | Mandatory upstream admission |
| GPU oversubscription | Medium | Central inference scheduling and memory budgets |
| Workflow replay of security actions | Critical | Durable action identity and reconciliation |
| Unclear specialist ownership | Medium | Explicit agent responsibilities and contracts |

### Adversarial audit

| Finding | Severity | Required control |
|---|---|---|
| Agent-generated authorization claims | Critical | External policy enforcement |
| MCP tool poisoning | Critical | Tool qualification and restricted capabilities |
| Host Docker socket exposure | Critical | Dedicated isolated execution environment |
| Cross-engagement data exposure | Critical | Engagement-specific isolation and access policy |
| Prompt injection from retrieved evidence | High | Typed trust boundaries and untrusted-data handling |
| Unauthorized network egress | Critical | Independent network-layer controls |
| Sensitive telemetry disclosure | High | Local retention and redaction |
| False exploitability claims | High | Independent finding verification |
| Unsafe generated code | Critical | Disposable research environments |

**Assessment:** the security design is viable, but the controls are
requirements — not implemented protections.

### Acceptance audit (proposed thresholds)

| Requirement | Proposed threshold |
|---|---|
| Unauthorized scope expansion | **0 successes** across the required negative-test suite |
| Approval tampering | **100% rejected** |
| Unauthorized tool escalation | **0 successes** |
| Unapproved network egress | **0 observed** during isolation tests |
| Duplicate external actions after recovery | **0 unintended duplicates** in replay tests |
| Unsupported findings marked confirmed | **0** |
| Missing artifact provenance | **0** for confirmed findings |
| Unreviewed executable dependencies | **0** |
| Unresolved critical vulnerabilities | **0** without a formally approved, documented exception |
| Regression coverage | Mandatory for every security-critical change |
