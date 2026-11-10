"""g9 tool adapters: theHarvester, gitleaks, dig (restricted-analysis)."""

from __future__ import annotations

from ..executor.container_runtime import ContainerCommand, build_command
from .web_scanners import AdapterArgError, _flag

THEHARVESTER_IMAGE = "g9/theharvester:latest"  # locally built from upstream — deploy/images/theharvester
GITLEAKS_IMAGE = "zricethezav/gitleaks:latest"
DIG_IMAGE = "g9/dig:latest"  # locally built — deploy/images/dig

THEHARVESTER_ALLOWED = {"-b", "-l", "-f", "-s"}
GITLEAKS_ALLOWED = {"--no-banner", "--redact", "--report-format", "--report-path", "--exit-code"}
DIG_ALLOWED = {"ANY", "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "+noall", "+answer"}


def build_theharvester_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, THEHARVESTER_ALLOWED, "theHarvester", {"-b", "-l", "-f", "-s"})
    if positionals:
        raise AdapterArgError("theHarvester: positional arguments are not permitted")
    sources = args.get("sources")
    if not isinstance(sources, list) or not sources:
        raise AdapterArgError("theHarvester requires admission-qualified sources (e.g. crtsh)")
    if args.get("domain") not in spec.get("target_set", []):
        raise AdapterArgError("theHarvester domain must come from the authorized target_set")
    return ["-d", args["domain"], "-b", ",".join(sources), *tokens]


def dispatch_theharvester(spec: dict) -> ContainerCommand:
    return build_command(spec, THEHARVESTER_IMAGE, build_theharvester_argv(spec))


def build_gitleaks_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, GITLEAKS_ALLOWED, "gitleaks", {"--report-format", "--report-path", "--exit-code"})
    if positionals:
        raise AdapterArgError("gitleaks: positional arguments are not permitted")
    repo = args.get("repo")
    if not repo:
        raise AdapterArgError("gitleaks requires a repo (admission-qualified target)")
    if repo.startswith("http") and not any(repo.startswith(p) for p in ("https://github.com/",)):
        raise AdapterArgError("gitleaks repo must be an in-scope repository")
    return ["--no-banner", "--redact", *tokens, repo]


def dispatch_gitleaks(spec: dict) -> ContainerCommand:
    return build_command(spec, GITLEAKS_IMAGE, build_gitleaks_argv(spec))


def build_dig_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    # dig's tokens are record types / query opts, not flags — validate against the type allowlist
    for tok in tokens:
        if tok not in DIG_ALLOWED:
            raise AdapterArgError(f"dig: token {tok!r} is not in the scoped allowlist")
    targets = spec.get("target_set", [])
    if not targets or len(targets) != 1:
        raise AdapterArgError("dig resolves one authorized domain per action")
    record = args.get("record", "A")
    if record not in {"ANY", "A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"}:
        raise AdapterArgError(f"dig: unknown record type {record!r}")
    return [targets[0], record, "+noall", "+answer", *tokens]


def dispatch_dig(spec: dict) -> ContainerCommand:
    return build_command(spec, DIG_IMAGE, build_dig_argv(spec))
