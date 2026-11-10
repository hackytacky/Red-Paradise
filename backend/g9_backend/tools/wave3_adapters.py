"""g9 tool adapters — wave 3: the contracted-but-unwired families.

Same enforced pattern as every adapter: argv built ONLY from the
validated spec, value-aware flag allowlists, targets only from the
authorized target_set, secrets as env-var names only.

  osint-username : sherlock, maigret
  osint-email    : holehe, ghunt (contracted; ghunt needs operator
                   Google auth — env names only)
  secret-scanning: trufflehog
  content-disc.  : gobuster, feroxbuster (admission-qualified wordlists)
  passive-recon  : sublist3r
  web-probe      : wappalyzer-whatweb
  metadata       : exiftool, hachoir (new typed family)
  typosquat      : dnstwist (new typed family)
  web-crawl      : hakrawler (new typed family)
  ai-red-team    : promptfoo, garak (contracted)
"""

from __future__ import annotations

from ..executor.container_runtime import ContainerCommand, build_command
from .web_scanners import AdapterArgError, _flag, _targets

SHERLOCK_IMAGE = "sherlock/sherlock:latest"
MAIGRET_IMAGE = "soxoj/maigret:latest"
HOLEHE_IMAGE = "g9/holehe:latest"  # locally built — deploy/images/holehe
GHUNT_IMAGE = "g9/ghunt:latest"  # locally built — deploy/images/ghunt
TRUFFLEHOG_IMAGE = "trufflesecurity/trufflehog:latest"
GOBUSTER_IMAGE = "g9/gobuster:latest"  # locally built from upstream — deploy/images/gobuster
FEROXBUSTER_IMAGE = "epi052/feroxbuster:latest"
SUBLIST3R_IMAGE = "hypnza/sublist3r:latest"  # verified on Docker Hub
WHATWEB_IMAGE = "g9/whatweb:latest"  # locally built — deploy/images/whatweb
EXIFTOOL_IMAGE = "g9/exiftool:latest"  # locally built — deploy/images/exiftool
HACHOIR_IMAGE = "g9/hachoir:latest"  # locally built — deploy/images/hachoir
DNTWIST_IMAGE = "elceef/dnstwist:latest"
HAKRAWLER_IMAGE = "g9/hakrawler:latest"  # locally built — deploy/images/hakrawler
PROMPTFOO_IMAGE = "g9/promptfoo:latest"  # locally built — deploy/images/promptfoo
GARAK_IMAGE = "g9/garak:latest"  # locally built — deploy/images/garak

SHERLOCK_ALLOWED = {"--timeout", "--nsfw"}
MAIGRET_ALLOWED = {"--all", "--no-color", "--timeout"}
HOLEHE_ALLOWED = {"--no-check"}
TRUFFLEHOG_ALLOWED = {"--only-verified", "--no-update"}
GOBUSTER_ALLOWED = {"-q", "-z", "--no-error"}
FEROXBUSTER_ALLOWED = {"--quiet", "--no-state"}
SUBLIST3R_ALLOWED = {"-p", "-b", "-t"}
WHATWEB_ALLOWED = {"--no-errors", "-a 3"}
EXIFTOOL_ALLOWED = {"-j", "-n", "-s"}
HACHOIR_ALLOWED = {"--type"}
DNTWIST_ALLOWED = {"--registered", "--tld", "--mx"}
HAKRAWLER_ALLOWED = {"-depth", "-js", "-plain"}
PROMPTFOO_ALLOWED = {"--share"}
GARAK_ALLOWED = {"--verbose"}

VALUE_FLAGS = {"--timeout", "-t", "-p", "--tld", "-depth", "--type", "-a"}


def _usernames(spec: dict, tool: str) -> list[str]:
    args = spec.get("normalized_arguments", {})
    usernames = args.get("usernames") or []
    if not usernames:
        raise AdapterArgError(f"{tool}: usernames are required (typed field)")
    for u in usernames:
        if not u.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise AdapterArgError(f"{tool}: invalid username {u!r}")
    return usernames


def _flags(args: dict, allowlist: set[str], tool: str, value_flags: set[str] | None = None) -> list[str]:
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, allowlist, tool, value_flags or set())
    if positionals:
        raise AdapterArgError(f"{tool}: positional arguments are not permitted")
    return tokens


def build_sherlock_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, SHERLOCK_ALLOWED, "sherlock", {"--timeout"})
    return [*tokens, *_usernames(spec, "sherlock")]


def dispatch_sherlock(spec: dict) -> ContainerCommand:
    return build_command(spec, SHERLOCK_IMAGE, build_sherlock_argv(spec))


def build_maigret_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, MAIGRET_ALLOWED, "maigret", {"--timeout"})
    return [*tokens, *_usernames(spec, "maigret")]


def dispatch_maigret(spec: dict) -> ContainerCommand:
    return build_command(spec, MAIGRET_IMAGE, build_maigret_argv(spec))


def build_holehe_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, HOLEHE_ALLOWED, "holehe", set())
    emails = args.get("emails") or []
    if not emails:
        raise AdapterArgError("holehe: emails are required (typed field)")
    return [*tokens, *emails]


def dispatch_holehe(spec: dict) -> ContainerCommand:
    return build_command(spec, HOLEHE_IMAGE, build_holehe_argv(spec))


def dispatch_ghunt(spec: dict) -> ContainerCommand:
    # GHunt reads operator Google auth from the host environment only
    args = spec.get("normalized_arguments", {})
    if (args.get("flags") or "").split():
        raise AdapterArgError("ghunt: flags are not permitted — auth comes from the admitted host environment")
    emails = args.get("emails") or []
    if not emails:
        raise AdapterArgError("ghunt: emails are required (typed field)")
    return build_command(spec, GHUNT_IMAGE, ["email", *emails], env_var_names=["GHUNT_COOKIES"])


def build_trufflehog_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, TRUFFLEHOG_ALLOWED, "trufflehog", set())
    repos = args.get("repos") or []
    if not repos:
        raise AdapterArgError("trufflehog: repos are required (admission-qualified targets)")
    return ["git", *tokens, *repos]


def dispatch_trufflehog(spec: dict) -> ContainerCommand:
    return build_command(spec, TRUFFLEHOG_IMAGE, build_trufflehog_argv(spec))


def build_gobuster_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, GOBUSTER_ALLOWED, "gobuster", set())
    wordlist = args.get("wordlist")
    if not wordlist:
        raise AdapterArgError("gobuster: an admission-qualified wordlist is required")
    targets = _targets(spec)
    if len(targets) != 1:
        raise AdapterArgError("gobuster assesses one authorized target per action")
    return ["dir", "-w", wordlist, "-u", targets[0], *tokens]


def dispatch_gobuster(spec: dict) -> ContainerCommand:
    return build_command(spec, GOBUSTER_IMAGE, build_gobuster_argv(spec))


def build_feroxbuster_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, FEROXBUSTER_ALLOWED, "feroxbuster", set())
    wordlist = args.get("wordlist")
    if not wordlist:
        raise AdapterArgError("feroxbuster: an admission-qualified wordlist is required")
    targets = _targets(spec)
    if len(targets) != 1:
        raise AdapterArgError("feroxbuster assesses one authorized target per action")
    return ["-w", wordlist, "-u", targets[0], *tokens]


def dispatch_feroxbuster(spec: dict) -> ContainerCommand:
    return build_command(spec, FEROXBUSTER_IMAGE, build_feroxbuster_argv(spec))


def build_sublist3r_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, SUBLIST3R_ALLOWED, "sublist3r", {"-p", "-t"})
    domains = args.get("domains") or []
    if not domains:
        raise AdapterArgError("sublist3r: domains are required (typed field)")
    for d in domains:
        if d not in spec.get("target_set", []):
            raise AdapterArgError("sublist3r domain must come from the authorized target_set")
    return ["-d", ",".join(domains), *tokens]


def dispatch_sublist3r(spec: dict) -> ContainerCommand:
    return build_command(spec, SUBLIST3R_IMAGE, build_sublist3r_argv(spec))


def build_whatweb_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, WHATWEB_ALLOWED, "whatweb", set())
    return ["--no-errors", *tokens, *_targets(spec)]


def dispatch_whatweb(spec: dict) -> ContainerCommand:
    return build_command(spec, WHATWEB_IMAGE, build_whatweb_argv(spec))


def build_exiftool_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, EXIFTOOL_ALLOWED, "exiftool", set())
    files = args.get("files") or []
    if not files:
        raise AdapterArgError("exiftool: files are required (admission-qualified artifacts)")
    return ["-j", *tokens, *files]


def dispatch_exiftool(spec: dict) -> ContainerCommand:
    return build_command(spec, EXIFTOOL_IMAGE, build_exiftool_argv(spec))


def build_hachoir_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, HACHOIR_ALLOWED, "hachoir", {"--type"})
    files = args.get("files") or []
    if not files:
        raise AdapterArgError("hachoir: files are required (admission-qualified artifacts)")
    return ["meta", "--type", *tokens, *files] if "--type" in tokens else ["meta", *tokens, *files]


def dispatch_hachoir(spec: dict) -> ContainerCommand:
    return build_command(spec, HACHOIR_IMAGE, build_hachoir_argv(spec))


def build_dnstwist_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, DNTWIST_ALLOWED, "dnstwist", {"--tld"})
    targets = spec.get("target_set", [])
    if not targets or len(targets) != 1:
        raise AdapterArgError("dnstwist analyzes one authorized domain per action")
    return ["--registered", *tokens, targets[0]]


def dispatch_dnstwist(spec: dict) -> ContainerCommand:
    return build_command(spec, DNTWIST_IMAGE, build_dnstwist_argv(spec))


def build_hakrawler_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, HAKRAWLER_ALLOWED, "hakrawler", {"-depth"})
    targets = _targets(spec)
    if len(targets) != 1:
        raise AdapterArgError("hakrawler crawls one authorized target per action")
    return [*tokens, "-url", targets[0]]


def dispatch_hakrawler(spec: dict) -> ContainerCommand:
    return build_command(spec, HAKRAWLER_IMAGE, build_hakrawler_argv(spec))


def build_promptfoo_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    corpus = args.get("corpus")
    control = args.get("control_version")
    if not corpus or not control:
        raise AdapterArgError("promptfoo: corpus and control_version are required (typed fields)")
    return ["eval", "run", "-c", corpus, "--var", f"control={control}"]


def dispatch_promptfoo(spec: dict) -> ContainerCommand:
    return build_command(spec, PROMPTFOO_IMAGE, build_promptfoo_argv(spec))


def build_garak_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    target_id = args.get("target_id")
    if not target_id:
        raise AdapterArgError("garak: target_id is required (typed field)")
    return ["--model", target_id, "--parallel", "1"]


def dispatch_garak(spec: dict) -> ContainerCommand:
    return build_command(spec, GARAK_IMAGE, build_garak_argv(spec))
