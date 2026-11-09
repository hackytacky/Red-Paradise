"""g9-executor worker plane: hybrid isolation routing.

Decision (docs/architecture/isolation-decision.md): containers for the
restricted-analysis class, KVM for the hostile-research class, host
process for trusted services. HARD RULE: a hostile-research workload
is never routable to a container — the router refuses rather than
downgrading isolation.

Both managers are interfaces with explicit runtimes:
- ContainerWorkerManager: profile is real configuration a Docker/Podman
  deployment applies (dropped capabilities, no-new-privileges, read-only
  rootfs, scoped network). The dispatch stub records intent; wiring the
  real container runtime is Stage-02 integration on the G9 host.
- KvmWorkerManager: guest profile for disposable QEMU guests. Actual
  guest lifecycle raises NotImplementedError — never silently faked.
"""

from __future__ import annotations

from dataclasses import dataclass

CONTAINER_PROFILE = {
    "runtime": "docker|podman",
    "capabilities": "drop=ALL",
    "security_opt": ["no-new-privileges"],
    "read_only_rootfs": True,
    "network": "scoped-egress-policy (enforced OUTSIDE the container)",
    "pid_limit": 64,
    "readonly_mounts_only": True,
}

KVM_GUEST_PROFILE = {
    "hypervisor": "qemu-kvm",
    "guest_kernel": "hardened minimal",
    "disposable": True,
    "credentials": "none — no G9 management credentials reach the guest",
    "inputs": "minimum required for the task",
    "network": "VM-layer egress enforcement (IPv4+IPv6, non-HTTP protocols)",
    "destruction": "on completion or abort — no state reuse",
}


class IsolationError(RuntimeError):
    pass


@dataclass
class WorkerRoute:
    worker_class: str
    technology: str
    profile: dict
    action_id: str
    tool_id: str | None


class ContainerWorkerManager:
    def dispatch(self, action_id: str, tool_id: str | None, spec: dict) -> WorkerRoute:
        return WorkerRoute(
            worker_class="restricted-analysis",
            technology="container",
            profile=CONTAINER_PROFILE,
            action_id=action_id,
            tool_id=tool_id,
        )


class KvmWorkerManager:
    def dispatch(self, action_id: str, tool_id: str | None, spec: dict) -> WorkerRoute:
        if not spec.get("allow_stub", False):
            raise NotImplementedError(
                "KVM guest lifecycle is not implemented in this scaffold — "
                "wire qemu/libvirt on the G9 host (Stage 02); refusing to fake execution"
            )
        return WorkerRoute(
            worker_class="hostile-research-vm",
            technology="kvm",
            profile=KVM_GUEST_PROFILE,
            action_id=action_id,
            tool_id=tool_id,
        )


class WorkerRouter:
    """Routes an action spec to the correct isolation class. The hard
    rule lives here: hostile research NEVER goes to a container."""

    def __init__(self, containers: ContainerWorkerManager, vms: KvmWorkerManager):
        self.containers = containers
        self.vms = vms

    def route(self, spec: dict) -> WorkerRoute:
        sandbox = spec.get("sandbox_profile")
        action_id = spec.get("action_id", "")
        tool_id = spec.get("tool_id")

        if sandbox == "trusted-service":
            raise IsolationError(
                "trusted-service workloads are not dispatched through the worker "
                "plane — they run as hardened host processes"
            )
        if sandbox == "restricted-analysis":
            return self.containers.dispatch(action_id, tool_id, spec)
        if sandbox == "hostile-research-vm":
            # The hard rule: never downgrade hostile work to a container.
            return self.vms.dispatch(action_id, tool_id, spec)
        raise IsolationError(f"unknown sandbox class {sandbox!r} — refuse rather than guess")

    def route_untrusted_binary(self, spec: dict) -> WorkerRoute:
        """Anything flagged untrusted-code is forced to the VM class even
        if a caller mislabeled the sandbox profile."""
        forced = {**spec, "sandbox_profile": "hostile-research-vm"}
        return self.route(forced)
