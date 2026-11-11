# G9 SPECTRE — Engineering Handoff

**For:** the next engineer/agent (Claude) picking up this codebase.
**Repo:** `hackytacky/Red-Paradise` (single `main` branch; the owner pulls from `main` directly).
**State as of this handoff:** 266 backend tests / 110 frontend tests pass; build green; full stack verified running on the owner's G9 host (Ubuntu, Docker + KVM).

---

## 1. What this is

G9 SPECTRE / RED-OPS is an **autonomous red-team control plane**: an agent (deterministic rulebook or a local LLM) proposes one typed action per step; deterministic code gates, executes, collects evidence, and verifies. The owner runs it against **authorized targets only**, under a signed RoE.

**Read first:** `README.md`, `docs/architecture/g9-spectre-v3.md` (architecture), `docs/architecture/first-real-pentest.md` (operator runbook), `docs/architecture/isolation-decision.md` (container vs KVM doctrine).

## 2. Doctrine — load-bearing, do not weaken

These are enforced in code with tests, not prompts. Any change that softens them is a regression:

1. **No signed RoE → red-tier locked.** `RealMission.__init__` raises rather than constructing. Never add a path around it.
2. **Scope is the ONLY source of targets.** Targets come from the engagement record; planner proposals outside scope are refused at the agent boundary AND the policy gate. The gates enforce what the operator declares — the operator supplies its truth.
3. **The model proposes, the code disposes.** LLM output is one strict-JSON typed action `{tool, target, args, reason}`; unknown tool / out-of-scope target / raw shell / malformed JSON all refuse with a recorded reason. Never let an LLM compose shell strings — typed MCP contracts (`backend/g9_backend/mcp/contract.py`) are the boundary.
4. **Candidates until reproduced.** Tool output enters the evidence graph as `candidate`; only the deterministic Verification Authority promotes to `reproduced` on independent re-probe. No scanner, collector, or agent confirms its own finding.
5. **Credentials are env-var NAMES, never values.** Adapters pass names to `build_command(env_var_names=[...])`; values expand inside the container. Secrets never appear in argv, the ledger, or logs.
6. **Remote-exec commands are a code allowlist** (`REMOTE_EXEC_ALLOWLIST` in `backend/g9_backend/tools/offensive_adapters.py`). Never free-form.
7. **Hostile-research workloads are never containerized.** `build_command` refuses `hostile-research-vm`; those route to the KVM worker (`KvmWorkerManager` — currently honest `NotImplementedError`). responder/ntlmrelayx/metasploit-class stay KVM until Stage 02.
8. **Everything loopback.** Backend `127.0.0.1:8700`, UI `127.0.0.1:5173`, CORS allows only those two UI origins. Never expose a public port.

## 3. Architecture map (where things live)

```
backend/g9_backend/
  api.py                  FastAPI surface. Lab endpoints (/lab/*), engagement
                          endpoints (/engagements/*), arsenal admission,
                          eval/bench/specialists, /brains discovery.
  real_mission.py         RealMission: agent-driven mission against an
                          authorized engagement (policy→budget→autonomy→
                          contract→adapter→hardened container), RealRulebookPlanner,
                          build_call (typed defaults per family), verification.
  agent/__init__.py       Agent loop (propose→gate→execute→observe), RulebookPlanner
                          (lab), LLMPlanner (any OpenAI-compatible endpoint;
                          think-block stripping, adaptive temperature retry,
                          auto-bind to served weights), FallbackPlanner (sticky
                          failover, recorded), agent-boundary validation.
  lab/                    LabMission + in-process flawed target + native adapters
                          (the self-test harness — honest: proves the pipeline,
                          not offensive capability).
  executor/
    invoke_chain.py       invoke_tool: contract→policy→budget→adapter→container.
                          ADAPTERS registry (56 wired). required_sandbox_class
                          derives from the registry entry.
    container_runtime.py  build_command (cap-drop ALL, no-new-privileges, read-only
                          rootfs, pids limit, env-var-NAME passing), execute().
    worker_manager.py     KvmWorkerManager — fails honestly until Stage 02.
    broker.py, state_machine.py, action_spec.py   approval binding, spec digests.
  policy/engine.py        Cedar-style deny-by-default PDP.
  ops/                    engagement_manager, budget_controller (tokens/rate/CIDR/
                          kill switch), autonomy (autonomous|hitl|manual),
                          identity_vault.
  evidence/               EvidenceGraph, ResultCollector (nuclei-style JSONL →
                          candidates only).
  core/audit_ledger.py    hash-chained tamper-evident ledger.
  tools/                  adapters by wave: nmap, web_scanners, recon, wave3, wave4,
                          offensive_adapters (sqlmap, dalfox, commix, ssrfmap, hydra,
                          hashcat, john, kerbrute, impacket suite, certipy),
                          feed_adapters, registry_data (397 tools), registry_admission.
  mcp/contract.py         34 typed tool families. Adding a tool = family entry +
                          adapter + ADAPTERS registration + Dockerfile.
  specialists/, eval/, bench/, intel/, storage/   (Stage 03–06 work)
src/                      React 18 + Vite UI. Views in src/views*.jsx; live API
                          client src/lib/api.js; engines (tested in JS) in src/lib/.
deploy/
  docker-compose.host.yml  lab-target + backend + frontend, all 127.0.0.1-only.
  images/<tool>/Dockerfile 30 locally-built tool images; g9-pin-images.sh builds
                          and digest-pins everything here.
scripts/                   g9-setup-host.sh (Docker+KVM), g9-pin-images.sh,
                          g9-run-host.sh.
docs/architecture/         design docs + first-real-pentest.md (runbook).
docs/research/             cybersecurity model landscape + model candidates.
```

## 4. How to run and verify

```bash
# frontend
npm install && npm test        # 110 tests (src/lib engines)
npm run build

# backend
cd backend && uv run pytest    # 266 tests
uv run uvicorn g9_backend.api:app --port 8700
# full lab mission as tests / live:
uv run pytest tests/test_lab_mission.py
curl -X POST http://127.0.0.1:8700/lab/run     # expect 10 candidates → 10 reproduced

# host (the owner's G9 machine)
./scripts/g9-pin-images.sh
docker compose -f deploy/docker-compose.host.yml up -d --build lab-target backend frontend
```

CI: `.github/workflows/` runs backend pytest + frontend test/build on push/PR.

## 5. Recent history (what just landed)

Chronological, most recent last. Commits on `main`:

1. Lab mission pipeline + native adapters, evidence graph, verification authority, ledger (the measured baseline: 10→10).
2. Mission Console UI: live event stream (`/lab/events`), 1-click quick start, mode switching, approval queue.
3. Agent layer: `Agent` + `RulebookPlanner` + `LLMPlanner` (+ evil-planner tests), wired to live API.
4. Role-based brains (planner/specialist/fast/fallback), `/brains` + `/brains/discover`, adaptive model binding (auto-bind to served weights, think-block stripping, temperature retry) — the build adapts to whatever weights are installed via `G9_LLM_ENDPOINT` etc.
5. Engagement manager (#10) with 1-click quickstart; then **real engagements**: `POST /engagements/create`, `RealMission`, agent-driven missions against authorized targets, Real Engagement UI (`/real`), runbook doc.
6. Host plumbing fixes: backend Dockerfile CMD (comment inside JSON array), CORS for the loopback UI origins, Docker daemon DNS fix on the host (daemon.json `dns`), reverted `--network=host` build steps (BuildKit rejects them; daemon DNS was the real fix).
7. **Offensive waves**: 13 new adapters (sqlmap, dalfox, commix, ssrfmap, hydra, hashcat, john, kerbrute, getnpusers, getuserspnss, secretsdump, wmiexec-psexec, certipy), 12 new contract families, credentials-via-env-NAME, remote-exec allowlist, 14 registry reclassifications kvm→container, 10 new Dockerfiles, planner offensive tiers.

## 6. Known open items (prioritized)

1. **KVM worker (Stage 02)** — the single highest-leverage next build. Unlocks responder, ntlmrelayx, metasploit-class, mimikatz (all currently KVM-class honest-fail via `KvmWorkerManager` NotImplementedError). libvirt/QEMU wiring; a disposable VM snapshot is the boundary for hostile code.
2. **Adapter coverage** — 56 of ~90 contracted tools wired; ~340 registry tools have no contracts yet. Pattern per tool: family entry in `mcp/contract.py` → dispatch in `tools/` → register in `invoke_chain.ADAPTERS` → Dockerfile in `deploy/images/<tool>/` → tests.
3. **Verification Authority v2** — currently deterministic re-probe reproduction; the Stage-05 multi-evidence design is documented but not built.
4. **Orchestrator real runs (#5)** — the LLM planner drives lab + real missions; specialist depth (web/API exploitation chains, RE) grows with adapters.
5. **API hardening + AuthN/AuthZ (#1–2)**, secrets management (#3) — control plane currently relies on loopback binding; no auth on the API.
6. **Native-vs-real comparison mode** (cleanup #3) — lab-native adapters duplicate container-adapter probes; a run-comparison would be a strong correctness test.
7. **Model admission** — record HF repo revisions for the community weights the owner uses (supply-chain note in `docs/research/cybersecurity-models-2026-11.md`).

## 7. Conventions and gotchas

- **Commit style:** detailed bodies, doctrine-first framing, test counts. Push to `main` (owner's established flow; no branch protection).
- **Tests are the contract.** Every engine has unit tests; the lab mission is executable as tests. Run both suites before pushing.
- **Adapters are the only place argv is constructed.** Flags allowlisted; targets only from `spec["target_set"]`; asset paths must be `/opt/assets/...`; hydra = one username per typed action (planner loops).
- **Dockerfiles:** images with their own ENTRYPOINT receive bare tool argv; images whose adapters pass `["sh","-c",...]` (impacket, certipy) must have NO entrypoint. The pin script (`g9-pin-images.sh`) builds everything under `deploy/images/` automatically and records digests in `deploy/pinned/`.
- **The lab run is a self-test harness**, honestly labeled — it proves the pipeline, not offensive capability. Don't oversell it.
- **UI live views fail soft** (`{ok:false}`) when the backend is down — check the backend/container before debugging frontend code.
- **CORS** allows exactly `http://127.0.0.1:5173` and `http://localhost:5173`. If the UI origin changes, update the middleware in `api.py`.
- **Env config:** `~/.g9/env.sh` (host-side, chmod 600) — API keys, `G9_LLM_ENDPOINT`/`G9_LLM_MODEL` (+ SPECIALIST/FAST/FALLBACK roles), `G9_AD_CREDS` for AD credentials. Containers inherit by NAME only.
- **Frontend views** are numbered files (`views1.jsx`…`views12.jsx`); routes and nav in `src/App.jsx`; live API calls go through `src/lib/api.js` (`g9api`).

## 8. Owner context

- Runs everything on a single G9 host (Ubuntu, Docker + KVM + libvirt, 16GB RTX GPU) — local execution only; nothing offloaded to third-party hardware.
- Uses local models (LM Studio / vLLM / llama.cpp, OpenAI-compatible endpoints) as the planner brain; community cyber-tuned weights; the build auto-binds to whatever is served.
- Wants real offensive capability with the governance intact; expects honest boundary statements, not overselling.
- Delivery: commits to `main`, then the owner `git pull`s on the host and rebuilds.
