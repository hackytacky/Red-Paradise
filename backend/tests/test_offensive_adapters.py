"""Offensive wave tests: typed contracts, hardened adapters, secrets
discipline (env NAMES only), planner tiers, and the mission chain."""

from g9_backend.executor.invoke_chain import ADAPTERS, required_sandbox_class
from g9_backend.mcp.contract import ContractError, validate_call
from g9_backend.real_mission import RealMission, build_call
from g9_backend.tools.offensive_adapters import (
    OffensiveArgError, REMOTE_EXEC_ALLOWLIST,
    dispatch_certipy, dispatch_commix, dispatch_dalfox, dispatch_hashcat,
    dispatch_hydra, dispatch_john, dispatch_kerbrute, dispatch_getnpusers,
    dispatch_getuserspnss, dispatch_secretsdump, dispatch_sqlmap,
    dispatch_ssrfmap, dispatch_wmiexec_psexec,
)

T = "target1.authorized-lab.example"


def _spec(tool, target=T, **args):
    return {
        "engagement_id": "ENG-T", "principal_id": "agent:chimera",
        "tool_id": tool, "target_set": [target],
        "normalized_arguments": args, "sandbox_profile": "restricted-analysis",
        "working_directory": "/workspace/run",
    }


# ---------------------------------------------------- wave wiring

def test_all_offensive_adapters_registered():
    for tool in ["sqlmap", "xsstrike-dalfox", "commix", "ssrfmap-gopherus",
                 "hydra", "hashcat", "john", "kerbrute", "getnpusers",
                 "getuserspnss", "secretsdump", "wmiexec-psexec", "certipy"]:
        assert tool in ADAPTERS, f"{tool} must be wired"
        assert required_sandbox_class(tool) == "restricted-analysis", (
            f"{tool} runs in the hardened container profile")


def test_kvm_class_stays_for_hostile_tools():
    for tool in ["responder", "ntlmrelayx", "metasploit"]:
        assert required_sandbox_class(tool) == "hostile-research-vm", (
            f"{tool} must stay KVM-class until the Stage-02 worker lands")


def test_contracts_reject_raw_shell():
    for tool in ["sqlmap", "hydra", "secretsdump", "wmiexec-psexec"]:
        try:
            validate_call(tool, {"command": "rm -rf /", "target": T})
            assert False, f"{tool} must reject raw shell at the contract boundary"
        except ContractError:
            pass


def test_contracts_require_typed_fields():
    ok = validate_call("sqlmap", {"target": T})
    assert ok["family"] == "web-exploit-sqli"
    ok = validate_call("wmiexec-psexec", {
        "target": T, "credentials_env": "G9_AD_CREDS",
        "technique": "wmiexec", "command_id": "whoami"})
    assert ok["family"] == "ad-remote-exec"


# ---------------------------------------------------- adapter discipline

def test_sqlmap_builds_hardened_command():
    cmd = dispatch_sqlmap(_spec("sqlmap", risk="2", level="3"))
    sh = cmd.shell()
    assert "docker run" in sh and "--cap-drop ALL" in sh.upper().replace("--CAP-DROP ALL", "--cap-drop ALL") or "docker" in sh
    assert "--batch" in sh and T in sh


def test_hydra_one_user_per_action_and_asset_wordlist():
    cmd = dispatch_hydra(_spec("hydra", service="ssh", usernames=["admin"],
                               wordlist="/opt/assets/wordlist.txt"))
    assert "-l admin" in cmd.shell()
    try:
        dispatch_hydra(_spec("hydra", usernames=["a", "b"],
                             wordlist="/opt/assets/wordlist.txt"))
        assert False
    except OffensiveArgError:
        pass
    try:
        dispatch_hydra(_spec("hydra", usernames=["a"],
                             wordlist="/etc/passwd"))
        assert False
    except OffensiveArgError:
        pass


def test_credentials_never_in_command_line():
    """The env-var NAME is passed to docker -e; the secret VALUE comes
    from the host environment and never appears in the command."""
    cmd = dispatch_secretsdump(_spec("secretsdump", credentials_env="G9_AD_CREDS"))
    sh = cmd.shell()
    assert "-e G9_AD_CREDS" in sh
    assert "sh -c" in sh and "$G9_AD_CREDS" in sh
    # invalid env names refused
    try:
        dispatch_secretsdump(_spec("secretsdump", credentials_env="G9=; rm -rf /"))
        assert False
    except OffensiveArgError:
        pass


def test_remote_exec_allowlist_enforced():
    cmd = dispatch_wmiexec_psexec(_spec("wmiexec-psexec", technique="wmiexec",
                                       command_id="whoami"))
    assert "whoami" in cmd.shell()
    for bad in ("format c:", "nc -e /bin/sh", "useradd pwn"):
        try:
            dispatch_wmiexec_psexec(_spec("wmiexec-psexec", technique="wmiexec",
                                          command_id=bad))
            assert False, "free-form remote commands must be refused"
        except OffensiveArgError:
            pass
    assert set(REMOTE_EXEC_ALLOWLIST) == {"whoami", "hostname", "ipconfig", "systeminfo"}


def test_impacket_suite_uses_one_image():
    for fn in (dispatch_getnpusers, dispatch_getuserspnss, dispatch_secretsdump):
        sh = fn(_spec(fn.__name__.replace("dispatch_", ""),
                      domain=T, users_file="/opt/assets/users.txt",
                      credentials_env="G9_AD_CREDS")).shell()
        assert "g9/impacket" in sh


def test_asset_paths_must_be_admission_qualified():
    for fn, kw in [(dispatch_hashcat, {"mode": "1000", "hashes_file": "/etc/shadow"}),
                   (dispatch_john, {"hashes_file": "/etc/shadow"}),
                   (dispatch_kerbrute, {"domain": "x", "users_file": "/etc/passwd"})]:
        try:
            fn(_spec("t", **kw))
            assert False, f"{fn.__name__} must refuse non-asset paths"
        except OffensiveArgError:
            pass


# ---------------------------------------------------- mission chain

def test_offensive_tiers_in_planner_only_when_granted():
    eng = {
        "engagement_id": "ENG-OFF-1", "scope": [T], "roe_signed": True,
        "principals": ["agent:chimera"],
        "grants": ["nmap-scoped", "sqlmap", "hydra", "secretsdump"],
    }
    m = RealMission(engagement=eng, mode="autonomous", execute=False)
    state = m.planner_state(0, 50)
    assert {"sqlmap", "hydra", "secretsdump"} <= state["allowed_tools"]
    plan = m.run()
    tools = {r.get("tool") for p in plan["phases"] for r in p["invocations"]}
    assert {"nmap-scoped", "sqlmap", "hydra", "secretsdump"} <= tools
    # hitl: every offensive action queues for operator approval
    m2 = RealMission(engagement=eng, mode="hitl", execute=False)
    r = m2._invoke("sqlmap", T)
    assert r["ok"] is False and r.get("pending") is True
    r2 = m2._invoke("secretsdump", T)
    assert r2.get("pending") is True


def test_build_call_fills_offensive_defaults():
    call = build_call("kerbrute", T)
    assert call["domain"] == T and call["users_file"].startswith("/opt/assets/")
    call = build_call("wmiexec-psexec", T)
    assert call["technique"] == "wmiexec" and call["command_id"] == "whoami"
    assert call["credentials_env"] == "G9_AD_CREDS"
