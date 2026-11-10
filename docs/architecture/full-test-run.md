# Full Test Run — Lab Mode & Host Mode

One click, one command: the entire pipeline executed for real — policy
(deny-by-default) → budget/scope → adapter → REAL execution → evidence
collector → CANDIDATE findings only → deterministic Verification
Authority → tamper-evident report.

## Lab mode (works anywhere — CI, this scaffold, your laptop)

```bash
cd backend && uv run pytest tests/test_lab_mission.py   # the run, as tests
uv run uvicorn g9_backend.api:app --port 8700            # loopback API
curl -X POST http://127.0.0.1:8700/lab/run               # the full run
```

Then open the UI → **Live Run (real)** → `RUN FULL ACTIVE MISSION`.

What runs, honestly labeled:

- **Lab target** (`g9_backend/lab/target.py`): a loopback-only
  (127.0.0.1, ephemeral ports) deliberately flawed service — missing
  security headers, exposed `/.env`, unlisted `/admin`, downloadable
  `/backup.zip`, ancient server banner, no TLS, a second exposed
  debug port.
- **Lab-native adapters** (`g9_backend/lab/native_adapters.py`): the
  SAME typed contracts as the container adapters, executed with
  native Python probes (socket port scan, HTTP probe, header audit,
  allowlisted-path discovery, TLS check). They emit nuclei-compatible
  JSONL, so the existing ResultCollector ingests them through its
  normal path: observations + candidates, never findings.
- **Mission orchestrator** (`g9_backend/lab/mission.py`): phases
  recon → tls → web-audit; every invocation passes policy, budget
  scope, rate, and token charge; every decision lands in the
  hash-chained ledger (optionally durable via the Stage-04 store).
- **Verification Authority**: deterministic code, outside any model —
  every candidate is independently re-probed; promotion to
  `reproduced` happens ONLY on reproduction. A candidate that fails
  re-probe stays a candidate (test-proven with a planted false
  positive).

Latest measured run (developer-reported until independently
established): **10 candidates → 10 reproduced** — open ports ×2,
no-TLS, outdated banner, 3 missing security headers, exposed `/.env`,
`/admin`, `/backup.zip`. Ledger verified, 1200 tokens charged.

## Host mode (your G9 host — real Docker, real tools)

```bash
./scripts/g9-pin-images.sh        # admission: pull + digest-pin tool images
./scripts/g9-run-host.sh          # compose up + full run + audit trail
```

`deploy/docker-compose.host.yml` builds the lab target, the control
plane, and the static frontend — **everything binds 127.0.0.1 only**;
no public ports exist. The tool containers (nuclei, httpx, ffuf,
testssl, masscan, …) run through the existing container adapters with
the hardened profile (cap-drop ALL, no-new-privileges, read-only
rootfs, pids limit) once their images are pinned at admission. The KVM
worker (Stage 02) is the remaining host-side piece: hostile-research
workloads route to `KvmWorkerManager`, which still fails honestly
with `NotImplementedError` until the libvirt/QEMU wiring lands.

## Honest boundaries

- Lab-native adapters are real measurements against a real (lab)
  target — they are not nmap/nuclei. On the host, the container
  adapters run the real tools against the same contracts.
- Nothing here has tested a third-party system. The lab target is
  ours; third-party targets require the full admission path (RoE,
  scope, grants) exactly as before.
- Verification here is deterministic re-probing, not the full
  multi-evidence Verification Authority design (Stage 05).
