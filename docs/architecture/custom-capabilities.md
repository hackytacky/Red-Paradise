# The Five Custom Capabilities That Differentiate G9

These provide more strategic value than simply including another security
framework.

## 1. G9 Evidence Graph — Priority: Critical

An evidence system connecting:

```
Asset → Service → Technology → Vulnerability Hypothesis → Test → Observation → Finding → Attack Path
```

Each node contains:

- Source and collection timestamp
- Model and tool provenance
- Confidence and validation status
- Engagement scope
- Relationships to underlying artifacts

The graph **distinguishes hypotheses from observations and confirmed facts**.

**Benefit:** prevents multiple agents from repeatedly rediscovering the same
issue and enables graph-based attack-path reasoning.

## 2. G9 Autonomous Research Analyst — Priority: Critical

A dedicated agent that researches unfamiliar services, security advisories,
source code, architecture, and patch changes **before execution**. It escalates
uncertain conclusions to specialized agents rather than inventing an answer.

Core tasks:

1. Technology identification
2. Advisory and patch analysis
3. Configuration assessment
4. Hypothesis development
5. Evidence-driven research prioritization

**Benefit:** improves reasoning quality and reduces wasted tool executions.

## 3. G9 Verification Authority — Priority: Critical

A subsystem that accepts findings **only when they meet explicit evidence
requirements**. Finding states:

```
Hypothesis → Candidate → Reproduced → Confirmed → Remediated → Regression-Verified
```

The verifier **never treats the primary testing agent's own success statement as
sufficient proof**. It examines artifacts, test results, and reproducibility.

**Benefit:** reduces hallucinated security findings and supports defensible
professional reporting.

## 4. G9 Adaptive Agent Scheduler — Priority: High

Task-specific routing instead of assigning every investigation to the largest
model:

| Task | Preferred model class |
|---|---|
| Tool-output parsing | Small local model or deterministic parser |
| Reconnaissance correlation | Local model |
| Technical research | Strong reasoning model |
| Complex code analysis | Coding-specialist model |
| Vulnerability hypothesis review | Strong reasoning model |
| Structured reports | Local model with schema validation |
| Final technical adjudication | Strong reasoning model plus independent evidence |

**Benefit:** better utilization of compute without forcing every workflow
through expensive inference. The optimal configuration is determined using
G9-specific evaluations, **not model parameter counts**.

## 5. G9 Adversarial Resilience Layer — Priority: Critical

G9's agents process untrusted web pages, repository files, scanner results, and
hostile application responses — a substantial prompt-injection attack surface.
The architecture enforces:

- Untrusted data cannot alter agent authority
- Tool results do not become system instructions
- Tool calls require centrally issued capability grants
- Network destinations are checked independently of model instructions
- Credentials are not exposed to unnecessary agents
- Destructive and high-impact actions require explicit authorization
- Models cannot promote their own findings to confirmed status
- Every agent action is attributable and auditable

**Benefit:** limits the consequences of compromised tool output, agent errors,
and malicious target-controlled content.
