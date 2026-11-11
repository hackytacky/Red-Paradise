# Cybersecurity AI Models — Deep Research Review (November 10, 2026)

Sources: live web research (Alias Robotics, Vals AI, llm-stats, BenchLM,
arXiv 2601.14614 / 2605.28334 / 2604.17159 / CyberCertBench, HF model
cards, OWASP/nhimg open-weight security guides). Numbers are as
published by their creators unless noted; treat as developer-reported
until independently reproduced. This review is for G9 SPECTRE planning.

## 1. The frontier (closed, gated — NOT locally runnable)

| Model | Cyber standing (as published) | Access |
|---|---|---|
| **Gemini 4 Carbon** (Google, Oct 28 '26) | #1 Artificial Analysis Index (59); SOTA cyber results inside a general model; cyber results forced a gated rollout | API, gated |
| **GPT-6 Cyber** (OpenAI) | Purpose-built security model, rated **Critical**, approved-customer program only | gated |
| **Claude Mythos Preview** (Anthropic) | Leads CyBench at 1.000 on llm-stats (narrow board) | API |
| **GPT-6 Sol / Gemini 4 Argon** | CyberBench v1.1 (bug finding/patching): ~78% each, behind "Wonder" (80.4%) | API |
| **alias3** (Alias Robotics) | **Leads Cybench pass@3 at 85%** (early 2026) ahead of Opus 4.6, GPT-5.5, Gemini 3; sovereign on-prem product (CSI suite) | commercial on-prem |

**Reading:** frontier cyber capability has consolidated into closed,
gated models. None of these run on a 16GB card. This is exactly why
G9's doctrine (enforcement outside the model, local models on red
tier) is the right architecture: the local ceiling is lower, so the
gates — not the model — must be load-bearing. They are.

## 2. Locally runnable open cyber models (the G9 shortlist)

| Model | Base | Why it matters | 16GB fit |
|---|---|---|---|
| **DeepHat-V1-7B** (formerly WhiteRabbitNeo lineage, now Kindo) | 7-8B | The flagship dedicated open cyber model lineage; WRN-V3 (8B, Jun 2025) was its peak open release; offensive+defensive training corpus | ✓ easily |
| **WhiteRabbitNeo-V3** (8B) | 8B | Last full open release of the WRN lineage before DeepHat went commercial (v2 30B is Kindo commercial) | ✓ easily |
| **gewsefa/pentest-v2** | Qwen3-8B LoRA | Trained on GTFOBins/HackTricks/HTB/PayloadsAllThings; **100% on its GTFOBins action benchmark vs ~25% base Qwen3-8B** | ✓ easily |
| **alias3-micro** (Alias Robotics) | 4B transformer | Purpose-built cyber transformer; interesting steering research (emotion-direction steering ±1.6–2.1pp on cybench); availability/license to verify before use | ✓ trivially |
| **Qwen3.6 / Qwen3.8-27B, Gemma 4 12B** (general) | — | Not cyber-tuned, but the strongest general local planners; Gemma 4 12B is the current "16GB laptop" pick | ✓ (12B) / ✗ (27B ≈ 24GB) |
| **RavenX-CyberAgent-35B-A3B** | Qwen MoE | Cyber-agent merge, 745K training pairs — 20.7GB at Q4 | ✗ too big |

**Skipped honestly:** the ~27-model uncensored field (DeepHat v2 30B,
CYBER-FROST-3.8 180B, GLM-5.3-cyber MoE, various abliterations) —
either exceed 16GB at usable precision or are community merges with
unvetted provenance (see §4).

## 3. Benchmark landscape (what "good" means now)

- **CyBench** (40→90 pro CTF tasks): the OWASP exploit-generation
  whitepaper's benchmark; US/UK AISI's only open-source cyber benchmark
  for pre-deployment tests. Top agents now exceed 80% — **saturating**.
- **NYU CTF Bench** (200 CSAW challenges): frontier models still fail
  the hard categories (pwn, forensics); multi-agent scaffolds
  (D-CIPHER) beat single agents by ~6%.
- **CAIBench / Dynamic Cyber Ranges** (Alias, 2026): the successor
  direction — CTFs are saturated and contamination-prone, so they
  built ranges with **AI defenders**: attacker success drops from
  ~100% to 0–55%. Measured, adversarial, dynamic.
- **CyberBench v1.1** (Vals AI): finding + patching security bugs.
- **CyberCertBench** (2026): cert-knowledge MCQA with a
  Proposer-Verifier explanation framework.
- **CyberGym**: vulnerable codebase + description → autonomous
  analysis-to-weaponized-PoC; CSI suite does this end-to-end.
- **Agent-attack resistance** (Lakera IPI, Gray Swan): how well the
  LLM inside an agent resists prompt exfiltration, injection, tool
  manipulation — the AI-security axis G9's aiRedTeam engine mirrors.

**Implication for G9:** our Stage-06 instinct was right and is now
the field's direction — static benchmarks saturate and contaminate;
**measured, dynamic, ground-truth evaluation** is the standard that
matters. G9's lab-plane eval (recall/FP-rejection/gate-integrity
against planted weaknesses) is a small instance of exactly this.

## 4. Risks the research surfaced (relevant to G9 doctrine)

1. **Open-weight supply chain** (OWASP LLM03:2025; nhimg guide Oct
   2026): the risk is not the base models from major labs but
   **community derivatives** — malicious LoRA adapters, model merging
   that bypasses review, and GGUF conversion services abused for code
   injection. Models are "binary black boxes"; static inspection
   offers little assurance. → *G9 action: treat model downloads like
   tool admission — record the HF revision/commit hash at "admission",
   prefer upstream org repos over community merges, pin the same way
   we pin container digests.*
2. **vLLM server exposure**: `--api-key` only protects `/v1`, `/v2`,
   `/inference`, `/cohere` path prefixes; other endpoints are
   unauthenticated. → *G9 action: keep vLLM loopback-only (our
   existing posture); never rely on `--api-key` alone.*
3. **Abliteration arms race**: community "uncensored" derivatives
   remove refusal directions; extended-refusal fine-tuning (arXiv
   2505.19056) limits the damage. For G9 this is irrelevant to safety
   (gates enforce) but relevant to **reliability** — abliterated
   merges often degrade JSON/tool-calling discipline, which is what
   our planner actually needs.
4. **CTF benchmark contamination**: static scores are inflated;
   relative comparisons hold. Never quote a static benchmark score as
   a capability claim — only measured runs on our own harness.

## 5. G9 recommendation (unchanged conclusion, now evidence-backed)

- **Planner brain (local, 16GB):** DeepHat-V1-7B / WhiteRabbitNeo-V3
  (domain-aligned) with **Qwen3-family 8–14B as the JSON-discipline
  fallback** — exactly the split we already built into the planner
  seam.
- **Specialist reasoning:** pentest-v2 for command/next-probe
  reasoning; alias3-micro worth a look once license is verified.
- **Never** treat any of them as the safety boundary — the research
  confirms the frontier is closed and gated, the local tier is
  community-grade, and the supply chain is the weak point. G9's
  code-enforced gates, RoE scoping, and Verification Authority remain
  the actual security architecture.
- **Next benchmark step for G9:** adopt the dynamic-range direction —
  extend the lab plane with an AI-defended target (our defenseCell
  engine already models purple replay) so "loud chain undetected =
  finding" becomes measurable against an active defender, not just a
  static target.
