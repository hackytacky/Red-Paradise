"""g9 tool adapter #1: scoped nmap (restricted-analysis class).

The adapter is the ONLY place raw tool arguments are constructed,
and it constructs them from an already-validated action spec —
never from model prose. Flags are allowlisted; anything outside the
allowlist is refused. Target hosts are taken from the spec's
authorized target_set, never from free-form input.

Flow (wired through the broker): policy → approval-binding →
worker routing → hardened container command.
"""

from __future__ import annotations

from ..executor.container_runtime import ContainerCommand, RuntimeError_, build_command

NMAP_IMAGE = "instrumentisto/nmap:latest"

ALLOWED_FLAGS = {
    "-sS", "-sV", "-sT", "-Pn", "-p", "--top-ports", "-T1", "-T2", "-T3", "-T4",
    "--version", "-v", "-vv",
}
FORBIDDEN_SUBSTRINGS = ("--script", "-iL", "-oX", "-oA", "--datadir")  # script engine + file IO out of profile


def build_nmap_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    flags = args.get("flags", "")
    if not isinstance(flags, str):
        raise RuntimeArgError("flags must be a string")
    tokens = flags.split()
    for tok in tokens:
        if tok not in ALLOWED_FLAGS:
            raise RuntimeArgError(f"flag {tok!r} is not in the scoped allowlist")
        if any(bad in tok for bad in FORBIDDEN_SUBSTRINGS):
            raise RuntimeArgError(f"flag {tok!r} is forbidden in the restricted-analysis profile")
    # targets come ONLY from the authorized target_set
    targets = spec.get("target_set", [])
    if not targets:
        raise RuntimeArgError("no authorized targets in the action spec")
    ports = args.get("ports", "1-1000")
    return [*tokens, "-p", str(ports), *targets]


class RuntimeArgError(ValueError):
    pass


def dispatch(spec: dict) -> ContainerCommand:
    """Full gated dispatch: validate args → build hardened command."""
    argv = build_nmap_argv(spec)
    return build_command(spec, NMAP_IMAGE, argv)
