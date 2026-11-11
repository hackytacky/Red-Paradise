"""g9 offensive adapters: web exploitation, credential attacks, AD
kill-chain (restricted-analysis class, per-action approval).

Doctrine, unchanged:

  - arguments constructed ONLY from the validated action spec; flags
    allowlisted; targets ONLY from the authorized target_set
  - credentials travel as env-var NAMES (host-side secrets in
    ~/.g9/env.sh) - the value never appears in argv, the command
    line, the audit ledger, or any log
  - remote-exec commands come from an allowlist in this file, never
    from model prose
  - output is scanner HYPOTHESIS - candidates until the Verification
    Authority reproduces them

Raw-packet/hostile tools (responder, ntlmrelayx, metasploit-class)
stay KVM-class deliberately: the worker fails honestly until Stage 02.
"""

from __future__ import annotations

import shlex

from ..executor.container_runtime import ContainerCommand, ENV_NAME_RE, build_command


class OffensiveArgError(ValueError):
    pass


def _target(spec: dict) -> str:
    targets = spec.get("target_set", [])
    if not targets:
        raise OffensiveArgError("no authorized targets in the action spec")
    return targets[0]


def _args(spec: dict) -> dict:
    return spec.get("normalized_arguments", {}) or {}


def _creds_env(spec: dict) -> str:
    name = _args(spec).get("credentials_env", "G9_AD_CREDS")
    if not ENV_NAME_RE.match(str(name)):
        raise OffensiveArgError(f"credentials_env {name!r} is not a valid env var NAME")
    return name


# ------------------------------------------------- wave 1: web exploits

SQLMAP_IMAGE = "g9/sqlmap:latest"


def dispatch_sqlmap(spec: dict) -> ContainerCommand:
    a = _args(spec)
    target = _target(spec)
    if "params" in a:
        target = target + "?" + str(a["params"])
    risk = str(a.get("risk", "1"))
    level = str(a.get("level", "1"))
    if risk not in {"1", "2", "3"} or level not in {"1", "2", "3", "4", "5"}:
        raise OffensiveArgError("sqlmap risk must be 1-3 and level 1-5")
    argv = ["-u", target, "--batch", "--risk", risk, "--level", level,
            "--output-dir=/tmp/sqlmap", "--random-agent"]
    return build_command(spec, SQLMAP_IMAGE, argv)


DALFOX_IMAGE = "g9/dalfox:latest"


def dispatch_dalfox(spec: dict) -> ContainerCommand:
    target = _target(spec)
    a = _args(spec)
    if "params" in a:
        target = target + "?" + str(a["params"])
    argv = ["url", target, "--blind", "--skip-mining-utils"]
    return build_command(spec, DALFOX_IMAGE, argv)


COMMIX_IMAGE = "g9/commix:latest"


def dispatch_commix(spec: dict) -> ContainerCommand:
    a = _args(spec)
    target = _target(spec)
    if "param" in a:
        target = target + "?" + str(a["param"]) + "=commix-marker"
    argv = ["--url", target, "--batch", "--level=3"]
    return build_command(spec, COMMIX_IMAGE, argv)


SSRFMAP_IMAGE = "g9/ssrfmap:latest"


def dispatch_ssrfmap(spec: dict) -> ContainerCommand:
    a = _args(spec)
    target = _target(spec)
    param = str(a.get("param", ""))
    if not param:
        raise OffensiveArgError("ssrfmap requires the vulnerable param")
    argv = ["-u", f"{target}?{param}=ssrfmarker", "-p", param, "-m", "handler", "-v"]
    return build_command(spec, SSRFMAP_IMAGE, argv)


# --------------------------------------------- wave 2: credential attacks

HYDRA_IMAGE = "g9/hydra:latest"


def dispatch_hydra(spec: dict) -> ContainerCommand:
    a = _args(spec)
    usernames = a.get("usernames") or []
    if len(usernames) != 1:
        raise OffensiveArgError("hydra: exactly one username per typed action - the planner loops per user")
    service = str(a.get("service", ""))
    if not service.replace("-", "").replace("_", "").isalnum():
        raise OffensiveArgError(f"hydra: invalid service {service!r}")
    wordlist = str(a.get("wordlist", ""))
    if not wordlist.startswith("/opt/assets/"):
        raise OffensiveArgError("hydra: wordlist must be an admission-qualified asset under /opt/assets/")
    argv = ["-l", str(usernames[0]), "-P", wordlist, "-t", "4", "-W", "1",
            _target(spec), service]
    return build_command(spec, HYDRA_IMAGE, argv)


HASHCAT_IMAGE = "g9/hashcat:latest"


def dispatch_hashcat(spec: dict) -> ContainerCommand:
    a = _args(spec)
    hashes_file = str(a.get("hashes_file", ""))
    mode = str(a.get("mode", ""))
    if not hashes_file.startswith("/opt/assets/"):
        raise OffensiveArgError("hashcat: hashes must be an admission-qualified artifact under /opt/assets/")
    if not mode.isdigit():
        raise OffensiveArgError("hashcat: mode must be a numeric hash mode")
    argv = ["-m", mode, hashes_file, "/opt/assets/wordlist.txt", "--potfile-disable"]
    return build_command(spec, HASHCAT_IMAGE, argv)


JOHN_IMAGE = "g9/john:latest"


def dispatch_john(spec: dict) -> ContainerCommand:
    a = _args(spec)
    hashes_file = str(a.get("hashes_file", ""))
    if not hashes_file.startswith("/opt/assets/"):
        raise OffensiveArgError("john: hashes must be an admission-qualified artifact under /opt/assets/")
    argv = [hashes_file, "--wordlist=/opt/assets/wordlist.txt", "--no-log"]
    return build_command(spec, JOHN_IMAGE, argv)


KERBRUTE_IMAGE = "g9/kerbrute:latest"


def dispatch_kerbrute(spec: dict) -> ContainerCommand:
    a = _args(spec)
    domain = str(a.get("domain", ""))
    users_file = str(a.get("users_file", ""))
    if not domain or not users_file.startswith("/opt/assets/"):
        raise OffensiveArgError("kerbrute: domain and an admission-qualified users_file are required")
    argv = ["userenum", "--dc", _target(spec), "-d", domain, users_file]
    return build_command(spec, KERBRUTE_IMAGE, argv)


IMPACKET_IMAGE = "g9/impacket:latest"  # one image serves the impacket suite


def dispatch_getnpusers(spec: dict) -> ContainerCommand:
    a = _args(spec)
    domain = str(a.get("domain", ""))
    users_file = str(a.get("users_file", ""))
    if not domain or not users_file.startswith("/opt/assets/"):
        raise OffensiveArgError("getnpusers: domain and an admission-qualified users_file are required")
    env = _creds_env(spec)
    argv = ["sh", "-c",
            f'GetNPUsers.py -dc-ip {shlex.quote(_target(spec))} -usersfile {shlex.quote(users_file)} '
            f'-no-pass "${env}" 2>&1']
    return build_command(spec, IMPACKET_IMAGE, argv, env_var_names=[env])


def dispatch_getuserspnss(spec: dict) -> ContainerCommand:
    a = _args(spec)
    domain = str(a.get("domain", ""))
    if not domain:
        raise OffensiveArgError("getuserspnss: domain is required")
    env = _creds_env(spec)
    out = str(a.get("output_format", "hashcat"))
    argv = ["sh", "-c",
            f'GetUserSPNs.py -dc-ip {shlex.quote(_target(spec))} -request -outputformat {shlex.quote(out)} '
            f'"${env}" 2>&1']
    return build_command(spec, IMPACKET_IMAGE, argv, env_var_names=[env])


def dispatch_secretsdump(spec: dict) -> ContainerCommand:
    env = _creds_env(spec)
    target = _target(spec)
    argv = ["sh", "-c", f'secretsdump.py -dc-ip {shlex.quote(target)} "${env}"@{shlex.quote(target)} 2>&1']
    return build_command(spec, IMPACKET_IMAGE, argv, env_var_names=[env])


# allowlisted remote-exec commands - the ONLY commands wmiexec/psexec
# may run; never free-form, never model prose
REMOTE_EXEC_ALLOWLIST = {
    "whoami": "whoami",
    "hostname": "hostname",
    "ipconfig": "ipconfig /all",
    "systeminfo": "systeminfo",
}


def dispatch_wmiexec_psexec(spec: dict) -> ContainerCommand:
    a = _args(spec)
    technique = str(a.get("technique", ""))
    command_id = str(a.get("command_id", ""))
    if technique not in {"wmiexec", "psexec"}:
        raise OffensiveArgError("wmiexec-psexec: technique must be wmiexec|psexec")
    if command_id not in REMOTE_EXEC_ALLOWLIST:
        raise OffensiveArgError(
            f"command_id {command_id!r} is not in the remote-exec allowlist {sorted(REMOTE_EXEC_ALLOWLIST)}"
        )
    env = _creds_env(spec)
    target = _target(spec)
    cmd = REMOTE_EXEC_ALLOWLIST[command_id]
    argv = ["sh", "-c", f'{technique}.py "${env}"@{shlex.quote(target)} {shlex.quote(cmd)} 2>&1']
    return build_command(spec, IMPACKET_IMAGE, argv, env_var_names=[env])


CERTIPY_IMAGE = "g9/certipy:latest"


def dispatch_certipy(spec: dict) -> ContainerCommand:
    env = _creds_env(spec)
    target = _target(spec)
    # split "domain\\user:pass" inside the container - the secret never
    # touches the command line
    argv = ["sh", "-c",
            f'u="${{{env}%:*}}"; p="${{{env}#*:}}"; '
            f'certipy find -dc-ip {shlex.quote(target)} -u "$u" -p "$p" -stdout 2>&1']
    return build_command(spec, CERTIPY_IMAGE, argv, env_var_names=[env])
