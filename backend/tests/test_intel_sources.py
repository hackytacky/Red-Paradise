import pytest

from g9_backend.intel import SOURCES, CATEGORY_FLAGS, all_sources, by_category, summary


class TestIntelRegistry:
    def test_all_operator_categories_present(self):
        required = [
            "threat-intel-feed", "vuln-db", "malware", "osint-attack-surface",
            "dns-cert-passive", "code-registries", "leak-breach", "underground",
            "ransomware-tracking", "cloud-container-saas", "ics-ot", "mobile",
            "firmware-iot", "crypto-blockchain", "geospatial-satellite",
            "corporate-legal-financial", "people-social-identity",
            "email-phone-domain-reputation", "academic-research",
            "government-cert-regulatory", "frameworks-standards-controls",
            "honeypots-sinkholes-scans", "bug-bounty-disclosure", "dark-web",
            "apt-tracking", "job-tech-fingerprinting", "ct-takeover",
            "git-secret-scanning", "bgp-routing", "asn-ip-enrichment",
            "threat-hunting-yara-sigma", "malware-config-extractors",
            "c2-trackers", "botnet-tracking", "telecom-fraud", "data-brokers",
            "sanctions-pep", "shipping-aviation-maritime", "radio-sdr-rf",
            "wireless-wardriving", "webcam-exposure", "internet-wide-scans",
            "archive", "search-engines", "pastebin-alternatives",
            "stealer-logs", "iab-listings", "telegram-discord",
        ]
        for c in required:
            assert c in SOURCES and len(SOURCES[c]) > 0, f"missing/empty category {c}"

    def test_named_sources_present(self):
        ids = {s["id"] for s in all_sources()}
        for sid in ["shodan", "censys", "zoomeye", "fofa", "quake-360", "binaryedge",
                    "netlas", "criminalip", "onyphe", "greynoise", "leakix",
                    "malwarebazaar", "urlhaus", "threatfox", "yaraify", "virustotal",
                    "hybrid-analysis", "joe-sandbox", "any-run", "triage", "malshare",
                    "thezoo", "vx-underground", "malpedia", "virusshare", "cape",
                    "unpack-me", "feodo-tracker", "sslbl", "c2-tracker", "maltrail",
                    "ransomware-live", "id-ransomware", "no-more-ransom", "coveware",
                    "ecrime-ch", "ransomwatch", "phishtank", "openphish", "urlscan-io",
                    "abuseipdb", "alienvault-otx", "misp", "spamhaus", "securitytrails",
                    "passivetotal", "farsight-dnsdb", "viewdns", "dnslytics", "robtex",
                    "hackertarget", "crt-sh", "certspotter", "merklemap", "chaos-pd",
                    "rapid7-sonar-subs", "bufferover", "ripe-ris", "routeviews",
                    "bgpstream", "bgpmon", "he-bgp", "sigma-hq", "pysigma",
                    "nvd", "cve-org", "cisa-kev", "epss", "vulncheck", "vulners",
                    "cvedetails", "exploit-db", "packet-storm", "gh-advisories", "osv",
                    "snyk-vulndb", "retirejs", "attack", "d3fend", "atlas", "capec",
                    "cwe", "sans-isc", "dshield", "honeydb", "t-pot",
                    "project-honeypot", "shadowserver", "wigle", "wayback",
                    "archive-today", "common-crawl", "hibp", "chainalysis", "elliptic",
                    "opensanctions", "marinetraffic", "flightradar24", "adsbexchange",
                    "androzoo", "opencorporates", "sec-edgar", "pipl", "spokeo"]:
            assert sid in ids, f"missing source {sid}"

    def test_governance_flags_auto_applied(self):
        s = summary()
        for sid in ["stealer-log-indexes", "iab-monitoring", "breach-compilations",
                    "xss-is", "exploit-in", "breachforums", "ransomware-leak-sites"]:
            assert sid in s["monitor_only"], f"{sid} must be monitor-only"
        assert s["legal_gated_count"] >= 15
        for sid in ["dread", "torch", "dark-fail", "onion-indexes", "ransomware-leak-sites", "doxbin"]:
            assert sid in s["unverified"], f"{sid} must be unverified"

    def test_no_duplicates_and_counts(self):
        s = summary()
        assert s["total"] > 230
        assert s["categories"] >= 48
        counts = by_category()
        assert counts["malware"] >= 19
        assert counts["vuln-db"] >= 16
        assert counts["code-registries"] >= 18

    def test_category_flag_map_covers_sensitive_categories(self):
        for cat in ["leak-breach", "underground", "dark-web", "stealer-logs",
                    "iab-listings", "ransomware-leaks", "data-brokers"]:
            assert cat in CATEGORY_FLAGS
