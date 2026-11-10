"""g9 tool adapters — wave 4: the remaining contracted families.

  dast            : owasp-zap (baseline scan), caido
  sbom-scan       : grype-syft, trivy
  directory-query : ldapsearch, windapsearch (read-only filters)
  identity-recon  : bloodhound, sharphound, azurehound (collection only)
  ai-red-team     : pyrit

Same doctrine as every adapter: spec-built argv, value-aware flag
allowlists, targets only from the authorized target_set, read-only
posture enforced where the tool allows it. burp-suite-pro is
license_required and NOT implemented here — a commercial GUI tool
with no container adapter; it stays a registry reference until the
operator records a license and an integration path.
"""

from __future__ import annotations

from ..executor.container_runtime import ContainerCommand, build_command
from .web_scanners import AdapterArgError, _flag

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:latest"
CAIDO_IMAGE = "caido/caido:latest"
GRYPE_IMAGE = "anchore/grype:latest"
SYFT_IMAGE = "anchore/syft:latest"
TRIVY_IMAGE = "aquasec/trivy:latest"
LDAPSEARCH_IMAGE = "bitnami/openldap:latest"
WINDAPSEARCH_IMAGE = "windapsearch:latest"
BLOODHOUND_IMAGE = "bloodhound/bloodhound:latest"
SHARPHOUND_IMAGE = "sharphound:latest"
AZUREHOUND_IMAGE = "azurehound:latest"
PYRIT_IMAGE = "pyrit/pyrit:latest"

ZAP_ALLOWED = {"-cmd", "-quickurl", "-quickout"}
CAIDO_ALLOWED = {"--headless"}
GRYPE_ALLOWED = {"--only-fixed", "--fail-on"}
SYFT_ALLOWED = {"-o", "--scope"}
TRIVY_ALLOWED = {"--severity", "--no-progress", "--exit-code"}
LDAP_ALLOWED = {"-x", "-LLL", "-b"}
WINDAP_ALLOWED = {"--dc-ip"}
BH_ALLOWED = {"-c", "--collection"}
AZUREHOUND_ALLOWED = {"--tenants"}
PYRIT_ALLOWED = {"--batch"}


def _one_target(spec: dict, tool: str) -> str:
    targets = spec.get("target_set", [])
    if not targets or len(targets) != 1:
        raise AdapterArgError(f"{tool} operates on one authorized target per action")
    return targets[0]


def _flags(args: dict, allowlist: set[str], tool: str, value_flags: set[str]) -> list[str]:
    tokens = (args.get("flags") or "").split()
    positionals = _flag(tokens, allowlist, tool, value_flags)
    if positionals:
        raise AdapterArgError(f"{tool}: positional arguments are not permitted")
    return tokens


def build_zap_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    tokens = _flags(args, ZAP_ALLOWED, "owasp-zap", {"-quickurl", "-quickout"})
    return ["-cmd", "-quickurl", _one_target(spec, "owasp-zap"), "-quickout", "/dev/stdout", *tokens]


def dispatch_owasp_zap(spec: dict) -> ContainerCommand:
    return build_command(spec, ZAP_IMAGE, build_zap_argv(spec))


def build_caido_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    profile = args.get("profile")
    if not profile:
        raise AdapterArgError("caido: a scan profile is required (typed field)")
    tokens = _flags(args, CAIDO_ALLOWED, "caido", set())
    return ["--headless", "scan", "--profile", profile, _one_target(spec, "caido"), *tokens]


def dispatch_caido(spec: dict) -> ContainerCommand:
    return build_command(spec, CAIDO_IMAGE, build_caido_argv(spec))


def build_grype_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    image_or_dir = args.get("image_or_dir")
    if not image_or_dir:
        raise AdapterArgError("grype: image_or_dir is required (admission-qualified artifact)")
    tokens = _flags(args, GRYPE_ALLOWED, "grype-syft", {"--fail-on"})
    return [*tokens, image_or_dir]


def dispatch_grype_syft(spec: dict) -> ContainerCommand:
    return build_command(spec, GRYPE_IMAGE, build_grype_argv(spec))


def build_trivy_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    image_or_dir = args.get("image_or_dir")
    if not image_or_dir:
        raise AdapterArgError("trivy: image_or_dir is required (admission-qualified artifact)")
    tokens = _flags(args, TRIVY_ALLOWED, "trivy", {"--severity", "--exit-code"})
    return ["image", "--no-progress", *tokens, image_or_dir]


def dispatch_trivy(spec: dict) -> ContainerCommand:
    return build_command(spec, TRIVY_IMAGE, build_trivy_argv(spec))


def build_ldapsearch_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    server = args.get("server")
    filt = args.get("filter", "(objectClass=*)")
    if not server:
        raise AdapterArgError("ldapsearch: server is required (typed field)")
    if any(w in filt.upper() for w in ("PASSWORD", "USERPASSWORD", "WRITE", "ADD", "DELETE", "MODIFY")):
        raise AdapterArgError("ldapsearch: read-only queries only — credential material and write filters are refused")
    tokens = _flags(args, LDAP_ALLOWED, "ldapsearch", {"-b"})
    return ["-x", "-LLL", "-H", f"ldap://{server}", "-b", "dc=lab,dc=g9,dc=local", filt, *tokens]


def dispatch_ldapsearch(spec: dict) -> ContainerCommand:
    return build_command(spec, LDAPSEARCH_IMAGE, build_ldapsearch_argv(spec))


def build_windapsearch_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    server = args.get("server")
    if not server:
        raise AdapterArgError("windapsearch: server is required (typed field)")
    tokens = _flags(args, WINDAP_ALLOWED, "windapsearch", {"--dc-ip"})
    return ["--dc-ip", server, "-u", "", *tokens] if tokens else ["--dc-ip", server]


def dispatch_windapsearch(spec: dict) -> ContainerCommand:
    return build_command(spec, WINDAPSEARCH_IMAGE, build_windapsearch_argv(spec))


def build_bloodhound_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    collector = args.get("collector", "BloodHound")
    if collector != "BloodHound":
        raise AdapterArgError(f"bloodhound adapter collects with BloodHound only, got {collector!r}")
    tokens = _flags(args, BH_ALLOWED, "bloodhound", {"-c", "--collection"})
    return ["--collection", "Default", *tokens] if "--collection" in tokens else ["--collection", "Default", *tokens]


def dispatch_bloodhound(spec: dict) -> ContainerCommand:
    return build_command(spec, BLOODHOUND_IMAGE, build_bloodhound_argv(spec))


def build_sharphound_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    collector = args.get("collector", "SharpHound")
    if collector != "SharpHound":
        raise AdapterArgError(f"sharphound adapter collects with SharpHound only, got {collector!r}")
    tokens = _flags(args, BH_ALLOWED, "sharphound", {"-c", "--collection"})
    return ["--collection", "Default", *tokens] if "--collection" in tokens else ["--collection", "Default", *tokens]


def dispatch_sharphound(spec: dict) -> ContainerCommand:
    return build_command(spec, SHARPHOUND_IMAGE, build_sharphound_argv(spec))


def build_azurehound_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    collector = args.get("collector", "AzureHound")
    if collector != "AzureHound":
        raise AdapterArgError(f"azurehound adapter collects with AzureHound only, got {collector!r}")
    tokens = _flags(args, AZUREHOUND_ALLOWED, "azurehound", {"--tenants"})
    if "--tenants" not in tokens:
        raise AdapterArgError("azurehound: --tenants (authorized tenant id) is required")
    return [*tokens]


def dispatch_azurehound(spec: dict) -> ContainerCommand:
    return build_command(spec, AZUREHOUND_IMAGE, build_azurehound_argv(spec))


def build_pyrit_argv(spec: dict) -> list[str]:
    args = spec.get("normalized_arguments", {})
    corpus = args.get("corpus")
    control = args.get("control_version")
    if not corpus or not control:
        raise AdapterArgError("pyrit: corpus and control_version are required (typed fields)")
    return ["attack", "-i", corpus, "--var", f"control={control}"]


def dispatch_pyrit(spec: dict) -> ContainerCommand:
    return build_command(spec, PYRIT_IMAGE, build_pyrit_argv(spec))
