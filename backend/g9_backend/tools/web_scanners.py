"""g9 tool adapters: httpx, ffuf, nuclei (restricted-analysis class).

Same pattern as the scoped nmap adapter:
- arguments constructed ONLY from the validated action spec
- per-tool flag allowlists; everything else refused
- targets taken ONLY from the authorized target_set
- nuclei output is scanner HYPOTHESIS — never a finding without
  Verification Authority confirmation
"""

from __future__ import annotations

from ..executor.container_runtime import ContainerCommand, build_command

HTTPX_IMAGE = "g9/httpx:latest"  # locally built from upstream — deploy/images/httpx
FFUF_IMAGE = "g9/ffuf:latest"  # locally built from upstream — deploy/images/ffuf
NUCLEI_IMAGE = "projectdiscovery/nuclei:latest"


class AdapterArgError(ValueError):
    pass


def _targets(spec: dict) -> list[str]:
    targets = spec.get("target_set", [])
    if not targets:
        raise AdapterArgError("no authorized targets in the action spec")
    return [t if t.startswith("http") else f"https://{t}" for t in targets]


def _flag(tokens: list[str], allowlist: set[str], tool: str, value_flags: set[str]) -> list[str]:
    """Validate allowlisted flags (value-aware) and return positional args."""
    positionals: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-"):
            if tok not in allowlist:
                raise AdapterArgError(f"{tool}: flag {tok!r} is not in the scoped allowlist")
            if tok in value_flags:
                if i + 1 >= len(tokens):
                    raise AdapterArgError(f"{tool}: flag {tok!r} requires a value")
                i += 1  # consume the value; it is never re-validated as a flag
        else:
            positionals.append(tok)
        i += 1
    return positionals


# ---------------------------------------------------------------- httpx

HTTPX_ALLOWED = {"-sc", "-cl", "-ct", "-title", "-tech-detect", "-follow-redirects", "-silent", "-timeout"}
HTTPX_VALUE_FLAGS = {"-timeout"}


def build_httpx_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, HTTPX_ALLOWED, "httpx", HTTPX_VALUE_FLAGS)
    if positionals:
        raise AdapterArgError("httpx: positional arguments are not permitted — targets come from the spec")
    return ["-silent", *tokens, *_targets(spec)]


def dispatch_httpx(spec: dict) -> ContainerCommand:
    return build_command(spec, HTTPX_IMAGE, build_httpx_argv(spec))


# ---------------------------------------------------------------- ffuf

FFUF_ALLOWED = {"-w", "-mc", "-fc", "-t", "-rate", "-ac", "-recursion", "-recursion-depth"}
FFUF_VALUE_FLAGS = {"-w", "-mc", "-fc", "-t", "-rate", "-recursion-depth"}


def build_ffuf_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, FFUF_ALLOWED, "ffuf", FFUF_VALUE_FLAGS)
    if positionals:
        raise AdapterArgError("ffuf: positional arguments are not permitted — targets come from the spec")
    wordlist = args.get("wordlist")
    if not wordlist:
        raise AdapterArgError("ffuf requires a wordlist (admission-qualified asset)")
    if ".." in wordlist or wordlist.startswith("/etc"):
        raise AdapterArgError("ffuf wordlist path escapes the approved asset directory")
    targets = _targets(spec)
    if len(targets) != 1:
        raise AdapterArgError("ffuf probes one authorized target per action")
    return ["-w", wordlist, *tokens, targets[0]]


def dispatch_ffuf(spec: dict) -> ContainerCommand:
    return build_command(spec, FFUF_IMAGE, build_ffuf_argv(spec))


# ---------------------------------------------------------------- nuclei

NUCLEI_ALLOWED = {"-severity", "-tags", "-t", "-silent", "-nc", "-timeout", "-rl", "-c"}
NUCLEI_VALUE_FLAGS = {"-severity", "-tags", "-t", "-timeout", "-rl", "-c"}


def build_nuclei_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, NUCLEI_ALLOWED, "nuclei", NUCLEI_VALUE_FLAGS)
    if positionals:
        raise AdapterArgError("nuclei: positional arguments are not permitted — targets come from the spec")
    severity = args.get("severity")
    if severity and severity not in {"critical", "high", "medium", "low", "info"}:
        raise AdapterArgError(f"unknown severity filter {severity!r}")
    return ["-silent", "-nc", *tokens, *_targets(spec)]


def dispatch_nuclei(spec: dict) -> ContainerCommand:
    return build_command(spec, NUCLEI_IMAGE, build_nuclei_argv(spec))
