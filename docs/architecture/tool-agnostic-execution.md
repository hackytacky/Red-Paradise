# Tool-Agnostic Pentest Execution — Priority 1 Doctrine

**Priority 1: red team and pentest execution.** Specialist agents may use
**any pentest tool available — on GitHub or anywhere else — when they decide it
is the most useful tool for the task.** The arsenal is open; execution is not.

## The two-sided rule

1. **Open arsenal (agent freedom of tool choice):** no tool is excluded because
   it is external, niche, or newly discovered. Task-driven selection
   (`recommendForTask`) matches the agent's need (protocols + capability class)
   against the registry and surfaces unqualified candidates for admission —
   it never silently installs or executes them.
2. **Gated execution (system enforcement):** a tool executes only through the
   full pipeline:

```
agent prefers tool X
  → registry: one-time recorded admission (pinned revision, license,
    protocol surface, sandbox class, residual risks) — qualified or rejected
  → capability grant per engagement (agents never hold tools directly)
  → policy engine: deny-by-default (engagement/RoE, principal, per-target
    scope, grant membership, sandbox class, approval binding, self-
    authorization refusal) with precise deny reasons
  → action spec: canonicalized, digest-bound approval; tamper invalidates
  → tripwire scan: canaries, injection, encoded payloads, scope hosts
  → execution broker: sandbox class enforced; OUTCOME_UNKNOWN reconciliation
  → evidence graph: provenance-tagged observation → verification authority
```

## Why admission is not bureaucracy

The upstream-admission rule exists precisely so the arsenal can be *maximally
open*: any tool can be added quickly through a recorded, reviewable decision
instead of either (a) blocking useful tools or (b) letting agents execute
arbitrary unvetted binaries. Admission is one decision per tool, amortized
across every later call; the per-call cost is the same deny-by-default gate for
every tool regardless of origin.

## Implemented engines

| Engine | File | Contract |
|---|---|---|
| Universal Tool Registry | `src/lib/toolRegistry.js` | register any tool (source, license, protocols, capability class, sandbox class); admission review with pinned revision; per-engagement capability grants; task-driven recommendation with admission candidates |
| Policy Engine (PDP) | `src/lib/policyEngine.js` | Cedar-style deny-by-default; seven checks; precise deny reasons; recorded decisions; agent self-authorization always denied |

Both are exercised live in the `/arsenal` view: qualify or reject the unvetted
fuzzer, then send requests through the policy gate (try an out-of-scope target,
an ungranted tool, or the self-authorization checkbox — each denies with its
exact reason).
