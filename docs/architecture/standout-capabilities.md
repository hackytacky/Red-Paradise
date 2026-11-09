# Standout Capabilities — the four areas competitors lack

Most AI pentest agents test and report. G9 additionally does four things that
no shortlisted competitor (PentAGI, RedAmon, Strix, XBOW-class demos) covers
together. All four are implemented as tested engines in this repo.

| # | Capability | Why competitors lack it | Engine | Tests |
|---|---|---|---|---|
| ① | **Defense Cell** — attack-to-detection correlation | They test the target; they never measure the *defender's* visibility | `src/lib/defenseCell.js` | coverage matrix with explicit gaps; purple replay where a loud chain running undetected is a headline finding |
| ② | **AI Security Studio** — LLM/RAG/MCP/agent red teaming | Conventional pentest agents do not test AI systems at all | `src/lib/aiRedTeam.js` | per-ingest-path injection corpus; code-enforced control functions; regression gate blocks control changes that fail the corpus |
| ③ | **Research Loop** — Mantis-style zero-day pipeline | Bug finders lack a disciplined research methodology (hypothesis → critique → reproduce → patch-diff) | `src/lib/researchLoop.js` | escalation-instead-of-invention on low confidence; PoC plan + deterministic PoV required; staged patch checks (fault stops AND functional tests pass); zero-day CVE discipline |
| ④ | **Advisory Watch** — 24/7 continuous mode | They run once; G9 watches continuously | `src/lib/advisoryWatch.js` | technology inventory matching; automatic rescan queuing; dedupe; unmatched advisories recorded without action |

## How they compose with the rest of G9

- The Defense Cell consumes **verified chains** from the evidence graph and its
  replays are the purple-team package shipped with every report.
- The AI Security Studio is the HYDRA-AI specialist's engine; its corpus runs
  are preserved (transcripts, target config, expected/observed) so improvement
  is *measured*, not asserted.
- The Research Loop is the ARGUS/vulnerability-researcher engine; its reported
  tasks feed the Verification Authority — the researcher never self-certifies.
- The Advisory Watch drives the 24/7 mission doctrine: METIS ingests, the
  watch matches against the inventory, and queued rescans re-enter the normal
  gated pipeline (they never bypass it).

## Honest boundary

These engines implement the *methodology and gating*. Actual detection
telemetry ingestion (Sigma rule deployment), live AI-target testing, real
fuzzing campaigns, and advisory feeds are Stage-05 integrations on the G9
host — the engines define the contracts those integrations implement.
