"""g9 tool adapters: subfinder, masscan, testssl.sh (restricted-analysis).

Same enforced pattern: args only from the validated spec, value-aware
flag allowlists, targets only from target_set. masscan enforces a rate
ceiling from the spec's resource budget — loud scans must be declared
in the OPSEC plan, not smuggled in through flags.
"""

from __future__ import annotations

from ..executor.container_runtime import ContainerCommand, build_command
from .web_scanners import AdapterArgError, _flag

SUBFINDER_IMAGE = "projectdiscovery/subfinder:latest"
MASSCAN_IMAGE = "mnbf9r3cr01/masscan:latest"  # pinned at admission on the G9 host
TESTSSL_IMAGE = "drwetter/testssl.sh:latest"

SUBFINDER_ALLOWED = {"-silent", "-all", "-timeout"}
MASSCAN_ALLOWED = {"-p", "-Pn", "-sS", "--open-only"}  # --rate is NEVER flag-settable: ceiling comes from the resource budget
TESTSSL_ALLOWED = {"-p", "-S", "-P", "--quiet", "--severity", "-t"}


def _domain_targets(spec: dict) -> list[str]:
    targets = spec.get("target_set", [])
    if not targets:
        raise AdapterArgError("no authorized targets in the action spec")
    for t in targets:
        if t.startswith("http"):
            raise AdapterArgError(f"subfinder expects bare domains, got {t!r}")
    return targets


def build_subfinder_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, SUBFINDER_ALLOWED, "subfinder", set())
    if positionals:
        raise AdapterArgError("subfinder: positional arguments are not permitted")
    return ["-silent", *tokens, "-d", *_domain_targets(spec)]


def dispatch_subfinder(spec: dict) -> ContainerCommand:
    return build_command(spec, SUBFINDER_IMAGE, build_subfinder_argv(spec))


def build_masscan_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, MASSCAN_ALLOWED, "masscan", {"-p"})
    if positionals:
        raise AdapterArgError("masscan: positional arguments are not permitted")
    # rate ceiling comes from the resource budget, never from flags
    max_rate = spec.get("resource_budget", {}).get("max_pps", 1000)
    argv = [*tokens, "--rate", str(max_rate), *_domain_targets(spec)]
    return argv


def dispatch_masscan(spec: dict) -> ContainerCommand:
    return build_command(spec, MASSCAN_IMAGE, build_masscan_argv(spec))


def build_testssl_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, TESTSSL_ALLOWED, "testssl", {"-p", "--severity", "-t"})
    if positionals:
        raise AdapterArgError("testssl: positional arguments are not permitted")
    targets = spec.get("target_set", [])
    if not targets:
        raise AdapterArgError("no authorized targets in the action spec")
    if len(targets) != 1:
        raise AdapterArgError("testssl assesses one authorized target per action")
    return ["--quiet", *tokens, targets[0]]


def dispatch_testssl(spec: dict) -> ContainerCommand:
    return build_command(spec, TESTSSL_IMAGE, build_testssl_argv(spec))
