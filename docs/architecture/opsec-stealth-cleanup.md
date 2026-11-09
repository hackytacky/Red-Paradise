# OPSEC Subsystem — Stealth, Privacy, Anonymity, No Traces

**Owner:** HYPNOS (T2 Oversight) — the OPSEC guardian agent. Skill:
[`skills/opsec-stealth-cleanup/SKILL.md`](../skills/opsec-stealth-cleanup/SKILL.md).
Engine: `src/lib/opsecGuardian.js` (tested).

This subsystem wraps **every chain step and every pre-execution action** in
stealth/privacy/anonymity enforcement, and owns the engagement close gate so
testing leaves no traces.

## Pre-action stealth gate

Every action is noise-classified (`silent / low / medium / loud`) and checked
against the Phase-0 OPSEC plan before dispatch:

- Exceeding the phase's noise ceiling → **hold**
- Unplanned phase → **hold** (Phase 0 OPSEC plan incomplete)
- Declared intent drifting to louder noise → **hold**
- Operator identifiers in the action → **hold** (anonymity violation)
- Unencrypted evidence store → **hold** (RoE evidence-handling violation)

Loud noise is permitted where planned — with the explicit note that the blue
team *should* detect it; silence during a loud phase is itself a headline
detection finding (purple-team doctrine).

## Operator privacy and anonymity

- Identifier scanning of every tool-call payload: emails, phone numbers,
  personal handles, and name-like tokens are blocked before dispatch.
- Red tier runs local models only — no external LLM calls carry engagement
  context.
- Egress only through the engagement's network policy (VM-layer enforcement,
  non-HTTP protocols included).

## No-traces cleanup ledger

- Every artifact (session cookies, persistence markers, dropped binaries,
  logs, temp files) is recorded **at creation** in the artifact ledger.
- Cleanup transitions: `present → removed | handed-over | retained-per-roe`
  (retention requires an explicit RoE citation and reviewer).
- The **close gate blocks engagement close** while any artifact is `present`;
  the cleanup manifest lists exactly what remains and where.
- The cleanup package ships to the defenders with the report.

## Relationship to the rest of G9

The stealth gate runs **before** the policy engine's scope checks feed the
execution broker: preference → admission → grant → policy → **stealth gate** →
action spec → tripwire scan → broker. The artifact ledger is populated by the
execution broker's result collector, and the close gate consumes it at
Stage-07 mission close.
