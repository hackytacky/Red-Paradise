"""g9 feed adapters: Shodan, Censys, abuse.ch, AlienVault OTX.

Threat-intel API clients behind the same gated chain as every
scanner: typed MCP call → policy → budget/scope → adapter →
hardened container command. Feed results are HYPOTHESES and
candidate findings only — never verified results.

Secrets never enter the command line: API keys are passed to the
container as environment variable NAMES; docker inherits the
values from the host environment, so no key ever appears in the
command, the audit ledger, or any log.

Targets come only from the authorized target_set (rule 5): each
feed query is scoped to an authorized IP/domain — agents cannot
fish arbitrary internet-wide queries through these adapters.
"""

from __future__ import annotations

from ..executor.container_runtime import ContainerCommand, build_command
from .web_scanners import AdapterArgError

FEED_CLIENT_IMAGE = "g9/feed-client:latest"  # built and pinned at admission on the G9 host

SHODAN_ENV = "SHODAN_API_KEY"
CENSYS_ENV = ["CENSYS_API_ID", "CENSYS_API_SECRET"]
OTX_ENV = "OTX_API_KEY"

ABUSECH_FEEDS = {"urlhaus", "threatfox", "malwarebazaar", "feodo", "sslbl", "yaraify"}
ABUSECH_FEED_ALIASES = {  # intel/sources.py registry ids → adapter feed names
    "abuse-ch": "abuse.ch",
    "feodo-tracker": "feodo",
    "sslbl": "sslbl",
    "abuse-ch-botnet": "threatfox",
}

SHODAN_ALLOWED = {"--history"}
CENSYS_ALLOWED = {"--max-records"}
OTX_ALLOWED = {"--limit", "--section"}


def _single_target(spec: dict, tool: str) -> str:
    targets = spec.get("target_set", [])
    if not targets:
        raise AdapterArgError("no authorized targets in the action spec")
    if len(targets) != 1:
        raise AdapterArgError(f"{tool} queries one authorized target per action")
    return targets[0]


def _flag(tokens: list[str], allowlist: set[str], tool: str, value_flags: set[str]) -> None:
    """Value-aware flag validation for feed adapters (no positionals allowed)."""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok not in allowlist:
            raise AdapterArgError(f"{tool}: flag {tok!r} is not in the scoped allowlist")
        if tok in value_flags:
            if i + 1 >= len(tokens):
                raise AdapterArgError(f"{tool}: flag {tok!r} requires a value")
            i += 1  # consume the value; it is never re-validated as a flag
        i += 1


def build_shodan_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    _flag(tokens, SHODAN_ALLOWED, "shodan", set())
    return ["shodan", "host", _single_target(spec, "shodan"), *tokens]


def dispatch_shodan(spec: dict) -> ContainerCommand:
    return build_command(spec, FEED_CLIENT_IMAGE, build_shodan_argv(spec), env_var_names=[SHODAN_ENV])


def build_censys_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    _flag(tokens, CENSYS_ALLOWED, "censys", {"--max-records"})
    return ["censys", "host", _single_target(spec, "censys"), *tokens]


def dispatch_censys(spec: dict) -> ContainerCommand:
    return build_command(spec, FEED_CLIENT_IMAGE, build_censys_argv(spec), env_var_names=CENSYS_ENV)


def build_abusech_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    feed = args.get("feed")
    if feed not in ABUSECH_FEEDS:
        raise AdapterArgError(
            f"abuse.ch: feed {feed!r} is not in the scoped allowlist "
            f"({', '.join(sorted(ABUSECH_FEEDS))})"
        )
    if (args.get("flags") or "").split():
        raise AdapterArgError("abuse.ch: flags are not permitted on feed queries")
    return ["abusech", "feed", feed, "search", _single_target(spec, "abuse.ch")]


def dispatch_abusech(spec: dict) -> ContainerCommand:
    return build_command(spec, FEED_CLIENT_IMAGE, build_abusech_argv(spec))


def build_otx_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = (args.get("flags") or "").split()
    _flag(tokens, OTX_ALLOWED, "otx", {"--limit", "--section"})
    return ["otx", "indicators", _single_target(spec, "otx"), *tokens]


def dispatch_otx(spec: dict) -> ContainerCommand:
    return build_command(spec, FEED_CLIENT_IMAGE, build_otx_argv(spec), env_var_names=[OTX_ENV])
