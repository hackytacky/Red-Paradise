"""g9-executor: real container runtime wiring.

Builds the exact hardened `docker run` command from a validated
action spec + the container profile (isolation-decision.md):
drop=ALL capabilities, no-new-privileges, read-only rootfs, pid
limit, scoped network policy, readonly mounts only.

Execution is honest: `execute()` invokes the real docker CLI via
subprocess. In environments without a Docker daemon (CI, this
scaffold's tests) `build_command()` is fully testable without
running anything — command construction is the contract the G9
host executes.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass

CONTAINER_PROFILE = {
    "capabilities": "drop=ALL",
    "security_opt": ["no-new-privileges"],
    "read_only_rootfs": True,
    "pid_limit": 64,
    "readonly_mounts_only": True,
}


class RuntimeError_(RuntimeError):
    pass


@dataclass
class ContainerCommand:
    argv: list[str]

    def shell(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)


ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def build_command(
    spec: dict, image: str, tool_argv: list[str], env_var_names: list[str] | None = None,
) -> ContainerCommand:
    """Build the hardened docker run command for a RESTRICTED-ANALYSIS
    workload. Refuses hostile-research profiles — those belong to KVM.

    `env_var_names` carries environment variable NAMES only (never
    values): docker inherits each variable from the host environment,
    so secrets like API keys never appear in the command line, the
    audit ledger, or any log."""
    if spec.get("sandbox_profile") == "hostile-research-vm":
        raise RuntimeError_(
            "hostile-research workloads are never containerized — route to the KVM worker"
        )
    if spec.get("sandbox_profile") not in ("restricted-analysis", "trusted-service", None):
        raise RuntimeError_(f"unknown sandbox profile {spec.get('sandbox_profile')!r}")
    # trusted-service: service-CLASS data sources (feeds, intel APIs) still
    # execute as hardened containers — the class describes the source,
    # never a weaker isolation profile

    network_policy = spec.get("network_policy_id", "none")
    for name in env_var_names or []:
        if not ENV_NAME_RE.match(name):
            raise RuntimeError_(
                f"env var name {name!r} is invalid — only NAME (no value) is permitted; "
                "secret values must never enter the command line"
            )
    argv = [
        "docker", "run", "--rm",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--pids-limit", str(CONTAINER_PROFILE["pid_limit"]),
        "--network", network_policy,
        "--memory", f"{spec.get('resource_budget', {}).get('mem_gb', 1)}g",
        "--cpus", str(spec.get("resource_budget", {}).get("cpu", 1)),
    ]
    # working directory mount is the ONLY writable surface, scoped to the action
    argv += ["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"]
    for name in env_var_names or []:
        argv += ["-e", name]
    if spec.get("working_directory"):
        argv += ["-v", f"{spec['working_directory']}:/work:ro"]
    argv += [image, *tool_argv]
    return ContainerCommand(argv=argv)


def execute(cmd: ContainerCommand, timeout_s: int = 300) -> dict:
    """Run the hardened command for real. Requires a Docker daemon."""
    try:
        proc = subprocess.run(
            cmd.argv, capture_output=True, text=True, timeout=timeout_s, check=False,
        )
    except FileNotFoundError:
        raise RuntimeError_("docker CLI not available — install Docker on the G9 host")
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": f"timeout after {timeout_s}s", "stdout": "", "stderr": "", "exit_code": None}
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "reason": "" if proc.returncode == 0 else f"exit {proc.returncode}",
    }
