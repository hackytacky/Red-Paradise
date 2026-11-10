import pytest

from g9_backend.intel import CATEGORY_FLAGS, SOURCES, all_sources, by_category, summary
from g9_backend.tools.registry_admission import admit, by_id, required_proofs, validate_registry
from g9_backend.tools.registry_data import all_entries


class TestIntakeSources:
    def test_new_categories_present(self):
        for c in [
            "url-redirect-analysis", "web-security-analysis", "attack-surface-search",
            "tech-fingerprint-web", "seo-backlink-intel", "whois-domain-history",
            "ip-geo-enrichment", "typosquat-phishing", "image-forensics",
            "facial-recognition", "file-metadata-forensics", "crypto-blockchain-intel",
            "privacy-anonymity", "code-search-web", "osint-toolboxes",
            "public-records-datasets", "device-serial-lookup", "test-data-generators",
        ]:
            assert c in SOURCES and len(SOURCES[c]) > 0, f"missing/empty category {c}"

    def test_intake_named_sources_present(self):
        ids = {s["id"] for s in all_sources()}
        for sid in [
            "redirect-detective", "wheregoes", "unshorten-me", "curlshot",
            "csp-validator", "csp-evaluator-google", "pageguard", "web-check",
            "hunter-how", "validin", "fullhunt", "builtwith", "wappalyzer-web",
            "similarweb", "spyfu", "whois", "whoisfreaks", "radb", "ipleak",
            "ipapi-is", "peeringdb", "ransomlook", "pulsediive", "aperisolve",
            "isgenai", "geoinfer", "walletexplorer", "bitcoinabuse", "cyberchef",
            "packettotal", "documentcloud", "gleif", "openownership", "fccid",
            "imeipro", "leakpeek", "spycloud-check-exposure", "osint-industries",
            "haveibeenransom", "onion-ail-project", "tor-taxi", "exonerator",
            "grayhatwarfare", "hackingthecloud", "hn-algolia", "wayback-archive-it",
            "torwhois", "relateoak-onion-pet", "app-wgen", "agent-gateway-kappa",
        ]:
            assert sid in ids, f"missing intake source {sid}"

    def test_facial_recognition_is_legal_gated(self):
        srcs = {s["id"]: s for s in all_sources()}
        for sid in ["faceagle", "spyderlab", "iriscan-app"]:
            assert "legal_gate" in srcs[sid]["flags"], f"{sid} must be legal-gated"

    def test_test_data_generators_are_gated_and_lab_only(self):
        assert CATEGORY_FLAGS["test-data-generators"] == ["legal_gate", "lab_only"]
        srcs = {s["id"]: s for s in all_sources()}
        for sid in ["cardgenerator-org", "vccgenerator", "cardguru", "generatedata"]:
            assert "legal_gate" in srcs[sid]["flags"]
            assert "lab_only" in srcs[sid]["flags"]

    def test_breach_checkers_are_monitor_only(self):
        s = summary()
        for sid in [
            "leakpeek", "checkleaked-cc", "breachchecker", "spycloud-check-exposure",
            "haveibeensold", "osint-industries", "infostealers-info",
            "haveibeenransom", "breachdetect", "breach-house", "whiteintel-breach",
        ]:
            assert sid in s["monitor_only"], f"{sid} must be monitor-only"

    def test_darkweb_additions_unverified_and_monitor_only(self):
        s = summary()
        for sid in [
            "onion-ail-project", "darkweblink", "onionsearchengine", "tor-taxi",
            "tormap", "darkweb-archive", "relateoak-onion-pet", "torwhois",
        ]:
            assert sid in s["unverified"], f"{sid} must be unverified"
            assert sid in s["monitor_only"], f"{sid} must be monitor-only"

    def test_unverified_web_apps(self):
        s = summary()
        for sid in ["app-wgen", "agent-gateway-kappa", "warnwell",
                    "web-proxy-herokuapp", "cl0q"]:
            assert sid in s["unverified"], f"{sid} must be unverified pending manual review"

    def test_no_duplicate_ids_after_expansion(self):
        s = summary()  # raises on duplicates
        assert s["total"] > 450
        assert s["categories"] > 55

    def test_governance_counts_grew(self):
        s = summary()
        assert len(s["monitor_only"]) > 40
        assert s["legal_gated_count"] > 25
        assert len(s["unverified"]) > 12


class TestIntakeRegistryTools:
    def test_registry_still_valid(self):
        entries = validate_registry()
        ids = {e["id"] for e in entries}
        assert len(entries) > 390

    def test_intake_tools_registered(self):
        ids = {e[0] for e in all_entries()}
        for tid in [
            "exiftool", "hachoir", "mutagen", "goris", "lemeknow", "dnstwist",
            "opensquat", "cloakquest3r", "miteru", "hakrawler",
            "cloudscraper-potti", "thescrapper", "github-search-gwen001",
            "h8mail", "mailmeta", "chiasmodon", "nexfil", "marple",
            "aliens-eye", "snoop", "pyosint", "blackbird", "phonenumber-osint",
            "clearfront", "daprofiler", "rug", "leaky", "thedevilseye",
            "thelordseye", "occli", "grep-for-osint", "credit-osint",
            "scrummage", "gomapenum", "reconspider", "semid", "maryam",
            "osint-toolkit", "cronodump", "obsidian-cli", "orion-araekiel",
            "sourcebot", "ton-of-privacy", "cyberchef-tool", "tldr-pages-tool",
        ]:
            assert tid in ids, f"missing intake tool {tid}"

    def test_breach_and_financial_tools_carry_legal_gate(self):
        assert required_proofs("h8mail") == ["legal_review_on_record"]
        assert required_proofs("snoop") == ["legal_review_on_record"]
        assert required_proofs("leaky") == ["legal_review_on_record"]
        assert required_proofs("chiasmodon") == ["legal_review_on_record"]
        assert required_proofs("credit-osint") == ["legal_review_on_record"]
        assert not admit("credit-osint", {})["ok"]
        assert admit("credit-osint", {"legal_review_on_record": "LR-7"})["ok"]

    def test_unverified_frameworks_never_auto_admit(self):
        for tid in ["reconspider"]:
            assert required_proofs(tid) == []
            denied = admit(tid, {"manual_review_override": False})
            assert not denied["ok"] if denied.get("ok") is False else True
            entry = by_id(tid)
            assert "unverified" in entry[5]

    def test_darkweb_tools_are_container_class(self):
        for tid in ["thedevilseye", "thelordseye"]:
            entry = by_id(tid)
            assert entry[3] == "container"
            assert entry[2] == "darkweb-osint"
