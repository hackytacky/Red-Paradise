import pytest

from g9_backend.tools.registry_admission import (
    AdmissionError, admit, required_proofs, summary, validate_registry,
)
from g9_backend.tools.registry_data import by_id


class TestRegistryIntegrity:
    def test_every_entry_valid_and_unique(self):
        entries = validate_registry()
        assert len(entries) > 100  # the operator-approved arsenal

    def test_key_entries_present(self):
        for rid in ["masscan", "subfinder", "spiderfoot", "metasploit", "cobalt-strike",
                    "brute-ratel-c4", "mimikatz", "impacket", "bloodhound",
                    "gitleaks", "trufflehog", "wazuh", "suricata", "shodan", "dehashed",
                    "evilginx2", "modlishka", "ghidra", "sqlmap", "hydra", "hashcat",
                    "john", "aircrack-ng", "mitmproxy", "ettercap", "beef", "merlin",
                    "pacu", "atomic-red-team", "promptfoo", "garak", "pyrit", "deepeval"]:
            assert by_id(rid) is not None, f"missing {rid}"

    def test_unknown_id_rejected(self):
        with pytest.raises(AdmissionError):
            required_proofs("not-a-tool")


class TestAdmissionGates:
    def test_standard_tool_admits_with_no_extra_proofs(self):
        r = admit("subfinder", {})
        assert r["ok"] and r["result"] == "qualified"

    def test_separate_authorization_required(self):
        for rid in ["metasploit", "evilginx2", "modlishka", "mimikatz", "ettercap", "mitmproxy", "beef", "sqlmap"]:
            r = admit(rid, {})
            assert not r["ok"], f"{rid} admitted without separate RoE addendum"
            assert "separate_roe_addendum" in r["reason"]
            r2 = admit(rid, {"separate_roe_addendum": "RoE-addendum-2026-11"})
            assert r2["ok"], f"{rid} refused with addendum: {r2}"

    def test_commercial_c2_requires_valid_license(self):
        for rid in ["cobalt-strike", "brute-ratel-c4"]:
            r = admit(rid, {"separate_roe_addendum": "x"})
            assert not r["ok"] and "valid_license_on_record" in r["reason"]
            r2 = admit(rid, {"separate_roe_addendum": "x", "valid_license_on_record": "license-#CS-xxxx", "lab_enclave_attested": "redlab"})
            assert r2["ok"]

    def test_breach_data_requires_legal_review(self):
        for rid in ["dehashed", "intelligencex", "national-breach-db", "hudsonrock"]:
            r = admit(rid, {})
            assert not r["ok"] and "legal_review_on_record" in r["reason"]

    def test_facial_recognition_gated(self):
        r = admit("search4faces", {})
        assert not r["ok"]
        assert "legal_review_on_record" in r["reason"] or "separate_roe_addendum" in r["reason"]

    def test_unverified_never_admitted_automatically(self):
        r = admit("onion-pet-proxy", {})
        assert not r["ok"]
        assert "UNVERIFIED" in r["reason"] or "manual safety review" in r["reason"]
        s = summary()
        assert "onion-pet-proxy" in s["never_admitted_automatically"]
        # even with all other proofs, the manual override is explicit
        r2 = admit("onion-pet-proxy", {"legal_review_on_record": "reviewed"})
        assert not r2["ok"]

    def test_summary_counts(self):
        s = summary()
        assert s["total"] > 100
        assert s["by_sandbox"]["kvm"] >= 25  # hostile-research class is large
        assert s["by_flag"]["separate_auth"] >= 20
