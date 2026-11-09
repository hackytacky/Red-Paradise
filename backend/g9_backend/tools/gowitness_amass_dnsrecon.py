"""g9 tool adapters: gowitness, amass (passive), dnsrecon."""

from __future__ import annotations

from ..executor.container_runtime import ContainerCommand, build_command
from .web_scanners import AdapterArgError, _flag

GOWITNESS_IMAGE = "lepidge/gowitness:latest"  # pinned at admission
AMASS_IMAGE = "cazzzer/amass:latest"
DNSRECON_IMAGE = "dnsrecon:latest"  # pinned at admission

GOWITNESS_ALLOWED = {"--screenshot-path", "--threads", "--timeout", "--no-banner", "scan"}
AMASS_ALLOWED = {"-passive", "-silent", "-timeout"}
DNSRECON_ALLOWED = {"-t", "-d", "--lifetime", "-n"}


def build_gowitness_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, GOWITNESS_ALLOWED, "gowitness", {"--screenshot-path", "--threads", "--timeout"})
    if positionals:
        raise AdapterArgError("gowitness: positional arguments are not permitted")
    targets = spec.get("target_set", [])
    if not targets:
        raise AdapterArgError("no authorized targets in the action spec")
    urls = [t if t.startswith("http") else f"https://{t}" for t in targets]
    return ["scan", *tokens, *urls]


def dispatch_gowitness(spec: dict) -> ContainerCommand:
    return build_command(spec, GOWITNESS_IMAGE, build_gowitness_argv(spec))


def build_amass_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, AMASS_ALLOWED, "amass", {"-timeout"})
    if positionals:
        raise AdapterArgError("amass: positional arguments are not permitted")
    if "-active" in tokens:
        raise AdapterArgError("amass: -active is not permitted in the passive profile")
    targets = spec.get("target_set", [])
    if not targets:
        raise AdapterArgError("no authorized targets in the action spec")
    return ["enum", "-passive", "-silent", *tokens, "-d", targets[0]]


def dispatch_amass(spec: dict) -> ContainerCommand:
    return build_command(spec, AMASS_IMAGE, build_amass_argv(spec))


def build_dnsrecon_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, DNSRECON_ALLOWED, "dnsrecon", {"-t", "-d", "--lifetime", "-n"})
    if positionals:
        raise AdapterArgError("dnsrecon: positional arguments are not permitted")
    rtypes = args.get("types")
    allowed_types = {"std", "srv", "axfr", "-zone", "generic", "bf"}
    if not isinstance(rtypes, list) or not rtypes:
        raise AdapterArgError("dnsrecon requires record types from the allowlist")
    for rt in rtypes:
        if rt not in {"std", "srv", "generic", "bf"}:
            raise AdapterArgError(f"dnsrecon: record type {rt!r} refused (axfr/zone transfer is not permitted in this profile)")
    targets = spec.get("target_set", [])
    if not targets or len(targets) != 1:
        raise AdapterArgError("dnsrecon queries one authorized domain per action")
    return ["-t", ",".join(rtypes), "-d", targets[0], *tokens]


def dispatch_dnsrecon(spec: dict) -> ContainerCommand:
    return build_command(spec, DNSRECON_IMAGE, build_dnsrecon_argv(spec))
