---
name: opsec-stealth-cleanup
description: "OPSEC tradecraft for authorized red-team and pentest engagements: per-phase stealth planning, operator privacy and anonymity, and no-traces cleanup. Load before any chain step, pre-execution action, or engagement close."
allowed-tools: Read Write
metadata:
  subdomain: opsec
  when_to_use: "stealth planning, noise classification, detectability, OPSEC plan, anonymity, identifier hygiene, artifact ledger, cleanup manifest, no traces, engagement close gate, evidence encryption"
  tags: opsec, stealth, anonymity, privacy, cleanup, anti-forensics, tradecraft
  upstream_ref: "G9 security-playbooks elite-standards + redteam-pentest methodology (OPSEC plan, cleanup manifest), adapted for the HYPNOS guardian"
---

# OPSEC — Stealth, Privacy, Anonymity, No Traces

HYPNOS owns this skill. It applies to **every chain step and every
pre-execution action**, and it owns the engagement close gate.

## Operating rules (non-negotiable)

1. **Authorization first.** This skill operates only inside a signed RoE.
   Stealth is engagement tradecraft, never a scope expansion.
2. **Stealth vs. speed is a decision, not a habit.** Loud-and-fast validates
   detection (the blue team should catch you — if they don't, *that* is a
   headline finding); stealth simulates a real adversary. Decide per phase,
   declare per action, document per chain link.
3. **Assume the target is monitored.** Execute so the blue team could have
   caught the engagement — otherwise it proves nothing about their detection.
4. **Operator anonymity.** No personal identifiers (emails, phones, handles,
   names) in any tool argument, artifact, or target-facing traffic. Red tier
   runs local models only; no external LLM calls leak engagement context.
5. **Evidence encrypted at rest.** Contemporaneous, hashed, replayable —
   destroyed or handed over per contract at close.
6. **No traces after testing.** Every artifact is recorded in the ledger at
   creation. Engagement close is blocked until the cleanup manifest verifies
   every artifact is removed, handed over, or explicitly retained per RoE.

## Noise classification (per action)

| Class | Detectability | Meaning |
|---|---|---|
| silent | 0 | passive — no packets on target |
| low | 1 | scoped, slow, rate-limited, inside normal traffic patterns |
| medium | 2 | active scanning — should be visible to a competent blue team |
| loud | 3 | exploit-grade noise — detection expected; silence is a finding |

## Pre-action gate (every chain step)

Before dispatch, each action declares: noise class, phase, declared intent.
The gate holds any action that: exceeds the phase's OPSEC-plan noise ceiling,
belongs to an unplanned phase, drifts from declared intent to louder noise,
contains operator identifiers, or runs against an unencrypted evidence store.

## Cleanup discipline

- Record artifacts **at creation** (session cookies, persistence markers,
  dropped binaries, logs, temp files) — contemporaneous, never reconstructed.
- Removal is verified, not assumed: each artifact transitions
  `present → removed | handed-over | retained-per-roe`.
- Retention requires an explicit RoE citation and reviewer.
- The close gate refuses to close while any artifact is `present`.
- The cleanup package ships to blue with the report: what was placed, where,
  and confirmation of removal (Decepticon-style cleanup manifest).
