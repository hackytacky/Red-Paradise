# Isolation Decision — Docker vs. KVM for the G9 Worker Plane

Question raised at Stage 02: *would Docker be better than KVMWorkerManager?*

## Decision

**Hybrid, with KVM as the outer boundary for hostile work. Docker is not the
outer boundary — ever — for hostile artifacts.**

| Worker class | Isolation technology | Why |
|---|---|---|
| Trusted service (policy engine, API, DB access) | Hardened host process | No untrusted content executes here |
| Restricted analysis (parsing, read-only analysis, approved utilities) | **Container** (Docker/Podman, dropped capabilities, scoped/no network, read-only mounts) | Containers win on throughput, snapshot speed, and density; workload is untrusted *data*, not untrusted *code* |
| Hostile research (untrusted binaries, generated PoCs, fuzzing) | **KVM/QEMU VM** (disposable guest) | Hardware isolation: guest kernel ≠ host kernel; container escapes are a real, routinely exploited class |

## Why Docker alone is insufficient as the outer boundary

1. **Shared kernel.** Any container kernel-exploit or namespace-escape lands on
   the host. G9 deliberately runs attacker-controlled binaries and
   LLM-generated PoCs — the exact workload containers are worst at containing.
2. **The project's own adversarial audit lists it.** "Host Docker socket
   exposure — Critical" and "unsafe generated code — disposable research
   environments — Critical" (g9-spectre-v3.md §14). A Docker-based hostile
   worker recreates the first finding by construction.
3. **Privilege surface.** A Docker daemon is root-equivalent on the host; the
   v3.0 rule "no worker accesses the host's unrestricted Docker daemon" exists
   precisely because of this.
4. **Tool reality.** Pentest tools emit raw TCP/UDP/DNS — container network
   policy still has to be enforced outside the container anyway (same as the
   ToolHive finding: HTTP-proxy filtering is not a network boundary).

## Why KVM alone is also suboptimal

Booting a full VM to parse an HTTP response wastes minutes and RAM on a 16 GB
box. Restricted-analysis workloads are the majority of executions; containers
give 10–100× better density there with an acceptable trust boundary because
the *code* is trusted and only the *data* is untrusted.

## What this changes in the code

`g9_backend/executor/worker_manager.py` implements the routing:

- `restricted-analysis` → container profile (dropped capabilities, no new
  privileges, read-only rootfs, scoped network policy reference)
- `hostile-research-vm` → KVM guest profile (disposable, no G9 management
  credentials, minimal inputs)
- **Hard rule, enforced and tested: a hostile-research workload is never
  routable to a container** — the router refuses rather than downgrading
  isolation.

Firecracker/Kata remain the future optimization for hostile-worker density
(v3.0 §2: "use existing Ubuntu/KVM capabilities" first; microVMs later when
throughput justifies the added infrastructure).
