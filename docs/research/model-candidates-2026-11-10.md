# Model Candidate Deep Review — Operator Shortlist (Nov 10, 2026)

Per-model review of the operator's 11 candidates, ranked for G9
SPECTRE roles on a 16GB RTX 5080. All facts from the live model cards
fetched 2026-11-10; community-claim numbers are developer-reported.

## Verdict table

| # | Model | Size @Q4_K_M | Fits 16GB? | G9 role | Rank |
|---|---|---|---|---|---|
| 1+11 | **empero Qwythos-9B-Claude-Mythos-5-1M** (hackoffice quants; huihui = abliterated variant of the SAME weights) | 5.2 GB (+MTP 5.5) | ✓ easily | **MISSION PLANNER (main brain)** | **#1** |
| 5 | **xtools-at Qwen3.5-4B-Qwensploit-CyberSecurity** | 2.7 GB | ✓ trivially | **CYBER SPECIALIST (analysis/triage)** | **#2** |
| 8 | **huihui DeepSeek-V4.1-Flash-1017 abliterated** | ~1–2 GB | ✓ trivially | **FAST BRAIN (high-volume triage)** | **#3** |
| 2/3 | xtools-at DeepSeek-V4-Pro-Qwen3.5-9B-heretic (mradermacher i1 = same weights, imatrix quants) | ~5.5 GB | ✓ | reasoning fallback | #4 |
| 9 | MrPentaxide HackerAI-Pro-Agent-8B | ~4.9 GB | ✓ | not recommended | #5 |
| 10 | mradermacher ZFusionAI_Hacker | unverified | ? | unvetted — skip | #6 |
| 4 | huihui Qwen3.6-35B-A3B-Claude-4.7-Opus abliterated MTP | ~20 GB | ✗ | would be the deep analyst on 24GB+ | excluded (VRAM) |
| 6 | IsValorum Qwen3.8-35B-A3B-Distill MTP APEX | ~20 GB | ✗ | same | excluded (VRAM) |
| 7 | Blackfrost Qwen3.8-27B abliterated | ~16.4 GB | ✗ (no KV headroom) | same | excluded (VRAM) |

## Deep review, per model

### #1 — Qwythos-9B-Claude-Mythos-5-1M (11: hackoffice quants · 1: huihui abliterated)
Both repos are quantizations of the SAME upstream: `empero-ai/
Qwythos-9B-Claude-Mythos-5-1M` (Qwen3.5-9B base, 500M tokens of Claude
Mythos/Fable reasoning traces, full-parameter post-train). The card
documents — with eval transcripts — **native function calling**
(Qwen3.5 tool-call blocks), **7/7 source-cited correct answers in a
tool-use harness including 4/4 fixes of closed-book failures**,
+34 MMLU / +30 gsm8k-strict over base, **1M context (YaRN)**, MTP
draft-speculation GGUFs (faster decode), vision tower inherited from
base, Apache-2.0. The huihui variant additionally removes refusal
directions (abliteration). **Why #1 for G9:** the planner's exact job
is "read state → emit one typed tool call" — native function calling
plus demonstrated self-correction-with-tools is precisely that skill,
at 5.2GB with 1M context for long mission histories. Caveat: it's a
reasoning model (opens with a think block; the agent parses the final
JSON — our planner already handles arbitrary preamble before JSON
only if we strip; verify think-block handling on first run) and avoid
temperature ≤0.3 (loops) — our planner sends temperature 0, so set 0.6
at the server or adjust the planner default for this brain.

### #2 — Qwen3.5-4B-Qwensploit-CyberSecurity (xtools-at)
The only candidate with **documented, sourced cyber/red-team
training**: LoRA on 7,000 examples (CyberSec-Reasoning-Premium 33%,
RedTeam-Premium 34%, Mythos + Qwen3.8-Max distills 33%), Apache-2.0,
comes in 2B/4B/9B. 2.7GB at Q4. The card is honest about limits
("performance on real-world security tasks not independently
established"). **Why #2:** the specialist brain for scan-output
analysis, vulnerability reasoning, and triage — cheap enough to keep
co-resident with the planner, purpose-aligned enough to matter. The
9B sibling is the upgrade path.

### #3 — DeepSeek-V4.1-Flash-1017 abliterated (huihui)
2B params, 262K context, ~1–2GB quant, 65k downloads/mo, llama.cpp
native. **Why #3:** the fast brain — near-instant triage of
high-volume candidates/events where planner-grade reasoning is
overkill and latency matters. Not a decision-maker; a sorter.

### #4 — DeepSeek-V4-Pro-Qwen3.5-9B-heretic (xtools-at; mradermacher i1 = identical weights)
A DeepSeek-V4-Pro reasoning distill onto Qwen3.5-9B, heretic-style
uncensoring. Fits at ~5.5GB. Solid reasoning fallback if Qwythos
misbehaves — but no documented function calling, so it slots as
fallback, not primary. The mradermacher i1 repo adds imatrix quants
of the same weights — pick either, not both.

### #5 — HackerAI-Pro-Agent-8B (MrPentaxide/Yalkurt)
Llama-3-8B base finetune, single Q4_K_M, thin card (no evals, no
dataset documentation). Agent-oriented branding, but a generation
older (Llama-3 vs Qwen3.5) and dominated by Qwythos on every axis we
care about. Skip unless it surprises in testing.

### #6 — ZFusionAI_Hacker (mradermacher quants)
Merge-shop derivative with no card detail available; size and training
unverified. Fails the model-admission discipline (unvetted provenance)
until documented. Skip.

### Excluded on VRAM (would rank high on a 24GB+ card)
- **Qwen3.6-35B-A3B-Claude-4.7-Opus abliterated MTP** (#4): 36B MoE,
  3B active (fast decode), Claude-Opus reasoning distill, MTP — the
  strongest brain on the list, but ~20GB at Q4; no 16GB fit with KV
  cache. On a future 24GB+ GPU this becomes the deep analyst.
- **IsValorum Qwen3.8-35B-A3B-Distill MTP APEX V2.1** (#6): same class,
  same exclusion.
- **Blackfrost Qwen3.8-27B abliterated** (#7): dense 27B, ~16.4GB at
  Q4 — loads but leaves zero KV-cache headroom. Not viable.

## The G9 brain stack (all three co-resident ≈ 9–10GB of 16GB)

| Role | Brain | Endpoint env | Why |
|---|---|---|---|
| PLANNER | Qwythos-9B (MTP Q4_K_M) | `G9_LLM_ENDPOINT` | native function calling, tool self-correction, 1M ctx |
| SPECIALIST | Qwensploit-4B | `G9_LLM_SPECIALIST_ENDPOINT` | documented cyber/red-team training; scan-output analysis, triage |
| FAST | DeepSeek-V4.1-Flash-1017 | `G9_LLM_FAST_ENDPOINT` | 2B, near-instant bulk triage |
| FALLBACK | DeepSeek-V4-Pro-9B-heretic | `G9_LLM_FALLBACK_ENDPOINT` | reasoning backup if the planner brain fails |

Failover chain: planner → fallback (automatic, recorded in the event
stream). Specialist and fast brains are role-addressable for
analysis/triage tasks. Every brain: loopback-only llama-server
(OpenAI-compatible), HF revision recorded at admission, same gates
regardless of which brain answers.

## Doctrine note

Three uncensored/abliterated brains behind deny-by-default policy,
RoE scoping, budget, and the Verification Authority is exactly the
intended architecture: capability lives in the model, enforcement
stays in the code. The abliteration is for *reliability of technical
answers*, not safety — safety is not the model's job in G9.
