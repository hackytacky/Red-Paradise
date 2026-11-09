"""G9 Intelligence Source Registry — categorized data sources.

Organized by the operator's category list. Governance is automatic:
sensitive categories (breach data, stealer logs, IAB listings,
underground forums, dark web) carry LEGAL_GATE + MONITOR_ONLY —
they are recorded as monitoring targets for metadata-level CTI
(lawful, per RoE); the platform never acquires or possesses the
underlying data. Tor-hidden sources default UNVERIFIED.

Entry: (id, name, access, note)
"""

from __future__ import annotations

FREE = "free"
COMMERCIAL = "commercial"
API = "api"
WEB = "web"
TOR = "tor"

# Category → mandatory flags
# Per-source overrides (id -> extra flags)
EXTRA_FLAGS = {
    "ransomware-leak-sites": ["unverified"],  # Tor mirrors: manual verification
    "intelx": ["legal_gate"],
    "doxbin": ["unverified"],
    "dread": ["unverified"],
    "ramp": ["unverified"],
}

CATEGORY_FLAGS = {
    "leak-breach": ["legal_gate", "monitor_only"],
    "underground": ["legal_gate", "monitor_only"],
    "dark-web": ["legal_gate", "unverified", "monitor_only"],
    "stealer-logs": ["legal_gate", "monitor_only"],
    "iab-listings": ["legal_gate", "monitor_only"],
    "ransomware-leaks": ["legal_gate", "monitor_only"],
    "data-brokers": ["legal_gate"],
    "telecom-fraud": ["legal_gate", "monitor_only"],
    "ransomware-tracking": ["legal_gate", "monitor_only"],
    "phishing": [],
    "webcam-exposure": ["legal_gate"],
}

SOURCES: dict[str, list[tuple[str, str, str, str]]] = {
    "threat-intel-feed": [
        ("misp", "MISP feeds & CIRCL", FREE, "open threat sharing"),
        ("alienvault-otx", "AlienVault OTX", FREE, "pulse feeds"),
        ("abuse-ch", "abuse.ch (all feeds)", FREE, "URLhaus/ThreatFox/MalwareBazaar/Feodo/SSLBL/YARAify"),
        ("cisa-ais", "CISA AIS", FREE, "automated indicator sharing"),
        ("team-cymru", "Team Cymru pure signals", FREE, "botnet infrastructure"),
        ("shadowserver", "Shadowserver reports", FREE, ""),
        ("greynoise", "GreyNoise", FREM := COMMERCIAL, "internet scanner classification"),
        ("recorded-future", "Recorded Future", COMMERCIAL, ""),
        ("mandiant-advintel", "Mandiant Advantage Threat Intelligence", COMMERCIAL, ""),
        ("flashpoint", "Flashpoint", COMMERCIAL, "underground coverage"),
        ("intel471", "Intel 471", COMMERCIAL, ""),
        ("digital-shadows", "Digital Shadows SearchLight", COMMERCIAL, ""),
        ("crowdstrike-falcon-intel", "CrowdStrike Falcon Intelligence", COMMERCIAL, ""),
        ("ibm-xforce", "IBM X-Force Exchange", FREM, "free tier + commercial"),
        ("spamhaus", "Spamhaus (SBL/XBL/PBL/DROP)", FREE, ""),
        ("anomali", "Anomali ThreatStream", COMMERCIAL, ""),
        ("sekoia", "SEKOIA.IO intelligence", COMMERCIAL, ""),
    ],
    "vuln-db": [
        ("nvd", "NVD (NIST)", FREE, "authoritative enrichment"),
        ("cve-org", "CVE.org / MITRE CVE", FREE, ""),
        ("cisa-kev", "CISA KEV catalog", FREE, "known-exploited — priority queue"),
        ("epss", "EPSS (FIRST)", FREE, "exploitation probability scoring"),
        ("vulncheck", "VulnCheck", COMMERCIAL, "KEV++ enrichment"),
        ("vulners", "Vulners", FREM, ""),
        ("cvedetails", "CVEDetails", FREM, ""),
        ("exploit-db", "Exploit-DB", FREE, "local mirror"),
        ("packet-storm", "Packet Storm Security", FREM, ""),
        ("gh-advisories", "GitHub Advisories", FREE, ""),
        ("osv", "OSV.dev", FREE, "package-scoped vulns"),
        ("snyk-vulndb", "Snyk Vulnerability Database", FREM, ""),
        ("retirejs", "Retire.js", FREE, "JS dependency rot"),
        ("zdi", "Zero Day Initiative", FREM, "pre-disclosure research"),
        ("patchdb", "Trend Micro Patch DB", FREM, ""),
        ("oscp", "Open Source Vulnerability reports (GitHub sec-lab)", FREE, ""),
    ],
    "malware": [
        ("malwarebazaar", "MalwareBazaar", FREE, ""),
        ("urlhaus", "URLhaus", FREE, ""),
        ("threatfox", "ThreatFox", FREE, "IOC exchange"),
        ("yaraify", "YARAify", FREE, ""),
        ("virustotal", "VirusTotal", COMMERCIAL, "API tier"),
        ("hybrid-analysis", "Hybrid Analysis (Payload Security)", FREM, ""),
        ("joe-sandbox", "Joe Sandbox", COMMERCIAL, ""),
        ("any-run", "ANY.RUN", FREM, "interactive sandbox"),
        ("triage", "tria.ge (Hatching)", FREM, ""),
        ("malshare", "MalShare", FREE, "sample repository"),
        ("thezoo", "theZoo", FREE, "live malware repository — lab only"),
        ("vx-underground", "vx-underground", FREE, "sample archive — lab only"),
        ("malpedia", "Malpedia", FREE, "actor/family library"),
        ("das-malwerk", "Das Malwerk", FREE, ""),
        ("contagio", "Contagio (m.10090?) dump", FREE, "historical samples"),
        ("virusshare", "VirusShare", FREE, "repository"),
        ("cape", "CAPE Sandbox", FREE, "config extraction"),
        ("unpack-me", "Unpac.me", FREM, "unpacking service"),
        ("malsub", "MalSub / malware aggregator", FREM, ""),
    ],
    "osint-attack-surface": [
        ("shodan", "Shodan", COMMERCIAL, "internet-wide scan"),
        ("censys", "Censys", COMMERCIAL, ""),
        ("zoomeye", "ZoomEye", FREM, ""),
        ("fofa", "FOFA", FREM, ""),
        ("quake-360", "Quake (360)", FREM, ""),
        ("binaryedge", "BinaryEdge", FREM, ""),
        ("netlas", "Netlas", FREM, ""),
        ("criminalip", "Criminal IP", FREM, ""),
        ("onyphe", "Onyphe", FREM, ""),
        ("leakix", "LeakIX", FREM, "exposed-service discovery"),
        ("intelx", "IntelligenceX", COMMERCIAL, "legal_gate: archive/breach data review"),
        ("wigle", "WiGLE", FREM, "wardriving database"),
    ],
    "dns-cert-passive": [
        ("securitytrails", "SecurityTrails", COMMERCIAL, "passive DNS"),
        ("passivetotal", "PassiveTotal (Microsoft/RiskIQ)", COMMERCIAL, ""),
        ("farsight-dnsdb", "Farsight DNSDB", COMMERCIAL, "passive DNS authority"),
        ("viewdns", "ViewDNS.info", FREM, ""),
        ("dnslytics", "DNSlytics", FREM, ""),
        ("robtex", "Robtex", FREM, ""),
        ("hackertarget", "HackerTarget", FREM, ""),
        ("crt-sh", "crt.sh", FREE, "certificate transparency"),
        ("certspotter", "Cert Spotter (SSLMate)", FREM, ""),
        ("censys-certs", "Censys certificates", COMMERCIAL, ""),
        ("merklemap", "Merklemap", FREM, "CT search"),
        ("dnsdumpster", "DNSDumpster", FREM, ""),
        ("chaos-pd", "Chaos (ProjectDiscovery)", FREE, "subdomain dataset"),
        ("rapid7-sonar-subs", "Rapid7 Sonar subdomains", FREE, "forward+reverse DNS datasets"),
        ("bufferover", "BufferOver.run", FREM, "DNS dataset"),
        ("google-dns-cache", "Google DNS cache / dig caches", FREE, ""),
    ],
    "code-registries": [
        ("github", "GitHub", FREM, "advisories + dorking + code search"),
        ("gitlab", "GitLab", FREM, ""),
        ("npm", "npm registry", FREE, "supply-chain admission"),
        ("pypi", "PyPI", FREE, ""),
        ("rubygems", "RubyGems", FREE, ""),
        ("packagist", "Packagist", FREE, ""),
        ("crates-io", "crates.io", FREE, ""),
        ("maven-central", "Maven Central", FREE, ""),
        ("nuget", "NuGet", FREE, ""),
        ("go-modules", "Go module proxy", FREE, ""),
        ("docker-hub", "Docker Hub", FREM, "image scanning at admission"),
        ("terraform-registry", "Terraform Registry", FREE, ""),
        ("vscode-marketplace", "VS Code Marketplace", FREE, "extension vetting"),
        ("chrome-web-store", "Chrome Web Store", FREE, "extension vetting"),
        ("wp-plugins", "WordPress plugin directory", FREE, ""),
        ("deps-dev", "deps.dev", FREE, "SBOM/dependency intel"),
        ("spdx", "SPDX", FREE, "SBOM standard"),
        ("cyclonedx", "CycloneDX", FREE, "SBOM standard"),
    ],
    "leak-breach": [
        ("hibp", "Have I Been Pwned", FREM, "breach notification — API is lawful"),
        ("dehashed", "DeHashed", COMMERCIAL, "legal review; RoE-scoped lookups only"),
        ("leakcheck", "LeakCheck", COMMERCIAL, "legal review"),
        ("snusbase", "Snusbase", COMMERCIAL, "legal review; monitor-only posture"),
        ("breach-compilations", "Breach compilation indexes", "reference", "never acquired; metadata monitoring only"),
        ("psbdmp", "psbdmp (pastebin dumps)", FREM, "paste monitoring"),
        ("doxbin", "Doxbin", TOR, "monitor-only; legal review"),
    ],
    "underground": [
        ("xss-is", "XSS.is forum", "reference", "metadata monitoring only; legal review"),
        ("exploit-in", "Exploit.in forum", "reference", "monitor only"),
        ("breachforums", "BreachForums (successors)", "reference", "monitor only"),
        ("cracked-io", "Cracked.io", "reference", "monitor only"),
        ("nulled", "Nulled", "reference", "monitor only"),
        ("dread", "Dread", TOR, "monitor only; unverified mirrors"),
        ("ramp", "RAMP", TOR, "monitor only"),
        ("russian-forums", "Russian-language forums (general)", "reference", "monitor only; analyst vetting"),
    ],
    "ransomware-tracking": [
        ("ransomware-live", "ransomware.live", FREE, "leak-site monitoring index"),
        ("id-ransomware", "ID Ransomware", FREE, ""),
        ("no-more-ransom", "No More Ransom", FREE, "decryptor repository"),
        ("coveware", "Coveware analytics", COMMERCIAL, ""),
        ("ecrime-ch", "eCrime.ch (ETH)", FREE, "academic ransomware tracking"),
        ("ransomwatch", "ransomwatch (threatlab)", FREE, "tooling for leak-site monitoring"),
        ("ransomware-leak-sites", "Ransomware leak sites (Tor)", TOR, "victim-list monitoring only; legal review; never download victim data"),
    ],
    "cloud-container-saas": [
        ("aws-security-bulletins", "AWS security bulletins", FREE, ""),
        ("azure-cve", "Microsoft Azure/365 advisories", FREE, ""),
        ("gcp-advisories", "Google Cloud advisories", FREE, ""),
        ("csp-intel", "CSP threat intel (Wiz/Orca blogs)", FREM, ""),
        ("container-cve-feed", "Container CVE feeds", FREE, "advisory watch integration"),
        ("saas-posture", "SaaS posture intel (SSPM vendors)", COMMERCIAL, ""),
    ],
    "ics-ot": [
        ("ics-cert", "CISA ICS-CERT advisories", FREE, ""),
        ("dragos-ot-cert", "Dragos OT-CERT", FREM, ""),
        ("nozomi-intel", "Nozomi Networks intel center", FREM, ""),
        ("waterfall-intel", "Waterfall Security advisories", FREM, ""),
        ("radiflow-intel", "Radiflow intel", COMMERCIAL, ""),
    ],
    "mobile": [
        ("androzoo", "AndroZoo", FREM, "research APK dataset — license review"),
        ("apkmirror", "APKMirror", FREM, "sample acquisition for analysis"),
        ("apkpure", "APKPure", FREM, ""),
        ("vt-mobile", "VirusTotal mobile", COMMERCIAL, ""),
        ("google-play-security", "Google Play Security Reward/Advisories", FREE, ""),
        ("apple-security", "Apple security advisories", FREE, ""),
    ],
    "firmware-iot": [
        ("firmware-repo", "Firmware analysis datasets (FirmAE etc.)", FREE, "lab research"),
        ("iot-vulndb", "IoT CVE feeds (CVEdetails slices)", FREM, ""),
        ("fcc-id", "FCC ID database", FREE, "device/RF intel"),
        ("zigbee-alliance", "IoT protocol registries", FREE, ""),
    ],
    "crypto-blockchain": [
        ("chainalysis", "Chainalysis", COMMERCIAL, "attribution intel"),
        ("elliptic", "Elliptic", COMMERCIAL, ""),
        ("trm-labs", "TRM Labs", COMMERCIAL, ""),
        ("blockchair", "Blockchair", FREM, "open explorer"),
        ("etherscan", "Etherscan", FREE, ""),
        ("bitcoinabuse", "BitcoinAbuse.com", FREE, "abuse-tagged addresses"),
        ("scam-databases", "Crypto scam address databases", FREE, ""),
    ],
    "geospatial-satellite": [
        ("sentinel-hub", "Sentinel Hub / Copernicus", FREM, ""),
        ("planet-labs", "Planet Labs", COMMERCIAL, ""),
        ("maxar", "Maxar imagery", COMMERCIAL, ""),
        ("nasa-earthdata", "NASA Earthdata", FREE, "already registered"),
        ("google-earth", "Google Earth/Maps", FREE, ""),
        ("openstreetmap", "OpenStreetMap", FREE, ""),
        ("openaip", "OpenAIP / aviation datasets", FREM, ""),
    ],
    "corporate-legal-financial": [
        ("opencorporates", "OpenCorporates", FREM, "company registries"),
        ("sec-edgar", "SEC EDGAR", FREE, "filings"),
        ("companies-house", "UK Companies House", FREE, ""),
        ("courtlistener", "CourtListener/RECAP", FREE, "court records"),
        ("trademark-uspto", "USPTO trademark registry", FREE, ""),
        ("sanctions-archives", "Corporate sanctions lists", FREE, ""),
    ],
    "people-social-identity": [
        ("pipl", "Pipl", COMMERCIAL, "data broker — legal review"),
        ("spokeo", "Spokeo", COMMERCIAL, "data broker — legal review"),
        ("truepeoplesearch", "TruePeopleSearch", FREM, "legal review"),
        ("linkedin", "LinkedIn", FREM, "ToS review; org chart intel"),
        ("mastodon-instances", "Mastodon instance registries", FREE, ""),
        ("twitter-x", "X/Twitter", FREM, "ToS review"),
        ("facebook", "Facebook/Meta", FREM, "ToS review"),
        ("instagram-osint", "Instagram", FREM, "ToS review"),
    ],
    "email-phone-domain-reputation": [
        ("abuseipdb", "AbuseIPDB", FREM, ""),
        ("talos-reputation", "Cisco Talos reputation", FREE, ""),
        ("barracuda", "Barracuda Central reputation", FREE, ""),
        ("fortiguard", "FortiGuard web filter lookup", FREE, ""),
        ("brightcloud", "BrightCloud", COMMERCIAL, ""),
        ("surbl", "SURBL", FREM, ""),
        ("urlhaus-rep", "URLhaus (reputation)", FREE, ""),
        ("emailrep", "emailrep.io", FREE, "email risk scoring"),
        ("phone-reputation", "Telecom spam/fraud lookups", FREM, "legal review"),
    ],
    "academic-research": [
        ("arxiv", "arXiv (cryptyc/sec)", FREE, ""),
        ("usenix", "USENIX Security", FREE, "proceedings"),
        ("ndss", "NDSS", FREE, ""),
        ("ieee-sp", "IEEE S&P", FREM, ""),
        ("scholar", "Google Scholar", FREE, ""),
        ("acm-ccs", "ACM CCS", FREM, ""),
    ],
    "government-cert-regulatory": [
        ("us-cert", "US-CERT/CISA", FREE, ""),
        ("enisa", "ENISA", FREE, ""),
        ("ncsc-uk", "NCSC UK", FREE, ""),
        ("cert-eu", "CERT-EU", FREE, ""),
        ("bsi", "BSI (Germany)", FREM, ""),
        ("ncc", "national CERTs (registry)", FREE, ""),
        ("gdpr-reg", "Regulatory registries", FREE, ""),
    ],
    "frameworks-standards-controls": [
        ("attack", "MITRE ATT&CK", FREE, "STIX bundle"),
        ("d3fend", "MITRE D3FEND", FREE, ""),
        ("atlas", "MITRE ATLAS (AI)", FREE, ""),
        ("capec", "MITRE CAPEC", FREE, ""),
        ("cwe", "MITRE CWE", FREE, ""),
        ("cis-controls", "CIS Critical Security Controls", FREM, ""),
        ("nist-csf", "NIST CSF", FREE, ""),
        ("iso-27001", "ISO 27001", "standard", "license for full text"),
    ],
    "honeypots-sinkholes-scans": [
        ("sans-isc", "SANS ISC", FREE, ""),
        ("dshield", "DShield", FREE, ""),
        ("honeydb", "HoneyDB", FREM, ""),
        ("t-pot", "T-Pot honeypot platform", FREE, "own telemetry"),
        ("project-honeypot", "Project Honey Pot", FREE, ""),
        ("shadowserver-scans", "Shadowserver scan data", FREE, ""),
        ("internet-census", "Internet Census datasets", FREE, "historical"),
        ("rapid7-sonar", "Rapid7 Open Data (Sonar)", FREE, "scan datasets"),
    ],
    "bug-bounty-disclosure": [
        ("hackerone", "HackerOne", FREM, "public disclosures"),
        ("bugcrowd", "Bugcrowd", FREM, ""),
        ("intigriti", "Intigriti", FREM, ""),
        ("yeswehack", "YesWeHack", FREM, ""),
        ("huntr", "huntr.com", FREM, "open-source disclosures"),
        ("gh-security-lab", "GitHub Security Lab", FREE, "research"),
    ],
    "dark-web": [
        ("ahmia", "Ahmia (Tor search)", FREE, "indexed Tor metadata"),
        ("torch", "Torch (Tor search)", TOR, "unverified"),
        ("dark-fail", "dark.fail (mirror verification)", TOR, "unverified"),
        ("onion-indexes", "Tor onion indexes", TOR, "unverified; manual review"),
        ("i2p-ecosystem", "I2P eepsite indexes", "reference", "unverified; manual review"),
    ],
    "apt-tracking": [
        ("aptnotes", "APTnotes", FREE, "campaign archive"),
        ("mitre-groups", "MITRE ATT&CK Groups", FREE, ""),
        ("yara-rules-repo", "YARA Rules (community repos)", FREE, ""),
        ("threat-actor-lib", "Threat actor libraries (SEKOIA/Malpedia)", FREM, ""),
        ("unit42-reports", "Unit42 reports", FREE, ""),
        ("securelist", "Kaspersky Securelist", FREE, ""),
        ("welivesecurity", "WeLiveSecurity", FREE, ""),
    ],
    "job-tech-fingerprinting": [
        ("job-boards", "Job boards (LinkedIn/Indeed)", FREM, "stack intel"),
        ("wappalyzer", "Wappalyzer", FREM, ""),
        ("stackoverflow", "StackOverflow/StackExchange", FREE, "org tech questions"),
        ("shodan-banners", "Shodan banner data", COMMERCIAL, ""),
    ],
    "ct-takeover": [
        ("crt-sh-takeover", "CT-based subdomain discovery", FREE, "crt.sh"),
        ("can-i-takeover", "Can I Take Over XYZ", FREE, "takeover fingerprints"),
        ("dnstake", "dnstake (takeover)", FREE, ""),
    ],
    "git-secret-scanning": [
        ("github-dorking", "GitHub dorking corpora", FREE, ""),
        ("trufflehog-datasets", "Trufflehog verified-leak datasets", FREE, "reference"),
        ("public-leak-repos", "Public leak repositories", "reference", "legal review; metadata only"),
    ],
    "bgp-routing": [
        ("ripe-ris", "RIPE RIS", FREE, ""),
        ("routeviews", "RouteViews", FREE, ""),
        ("bgpstream", "BGPStream (CAIDA)", FREE, "live hijack detection"),
        ("bgpmon", "BGPmon (OpenDNS)", FREM, ""),
        ("he-bgp", "Hurricane Electric BGP toolkit", FREE, ""),
        ("cidr-report", "The CIDR Report", FREE, ""),
        ("grip", "GRIP (bgpkit)", FREE, ""),
    ],
    "asn-ip-enrichment": [
        ("ipinfo", "IPinfo", FREM, ""),
        ("maxmind", "MaxMind", FREM, "geo/ASN"),
        ("ip2location", "IP2Location", FREM, ""),
        ("bgp-he-asn", "bgp.he.net ASN lookup", FREE, ""),
        ("ipdata", "ipdata.co", FREM, ""),
    ],
    "threat-hunting-yara-sigma": [
        ("sigma-hq", "Sigma HQ rules", FREE, ""),
        ("pysigma", "pySigma backends", FREE, ""),
        ("yara-community", "YARA community rule sets", FREE, ""),
        ("elastic-detections", "Elastic detection rules", FREE, ""),
        ("soc-prime", "SOC Prime (Uncoder)", FREM, ""),
        ("chronicle-detections", "Google Chronicle YARA-L", COMMERCIAL, ""),
    ],
    "malware-config-extractors": [
        ("cape-extractors", "CAPE config extractors", FREE, ""),
        ("mwcp", "MWCP (Google parser framework)", FREE, ""),
        ("maco", "Maco parser framework", FREE, ""),
        ("rat-configs", "RAT config decoder corpora", FREE, "lab use"),
    ],
    "c2-trackers": [
        ("feodo-tracker", "Feodo Tracker (abuse.ch)", FREE, ""),
        ("sslbl", "SSL Blacklist (abuse.ch)", FREE, ""),
        ("c2-tracker", "C2-Tracker (tccontre)", FREE, ""),
        ("maltrail", "Maltrail", FREE, ""),
        ("cs-beacon-tracker", "Cobalt Strike beacon trackers", FREM, "emulation defense"),
    ],
    "botnet-tracking": [
        ("abuse-ch-botnet", "abuse.ch botnet feeds", FREE, ""),
        ("malware-must-die", "Malware Must Die", "reference", "historical"),
        ("netlab-360", "Netlab 360 (360)", FREM, ""),
    ],
    "telecom-fraud": [
        ("sim-swap-intel", "SIM-swap fraud intel", COMMERCIAL, "legal review; monitor only"),
        ("telecom-fraud-db", "Telecom fraud databases (CFCA-type)", COMMERCIAL, "legal review"),
    ],
    "data-brokers": [
        ("radaris", "Radaris", COMMERCIAL, "legal review"),
        ("beenverified", "BeenVerified", COMMERCIAL, "legal review"),
        ("whitepages", "Whitepages", COMMERCIAL, "legal review"),
        ("192-com", "192.com", FREM, "legal review"),
    ],
    "sanctions-pep": [
        ("ofac-sdn", "OFAC SDN list", FREE, ""),
        ("eu-sanctions", "EU consolidated sanctions", FREE, ""),
        ("un-sanctions", "UN Security Council consolidates list", FREE, ""),
        ("opensanctions", "OpenSanctions", FREM, "PEP + sanctions"),
        ("worldbank-debarred", "World Bank debarred list", FREE, ""),
    ],
    "shipping-aviation-maritime": [
        ("marinetraffic", "MarineTraffic", FREM, "AIS"),
        ("vesselfinder", "VesselFinder", FREM, "AIS"),
        ("flightradar24", "FlightRadar24", FREM, ""),
        ("adsbexchange", "ADS-B Exchange", FREM, "unfiltered"),
        ("opensky", "OpenSky Network", FREM, ""),
        ("flightaware", "FlightAware", FREM, ""),
    ],
    "radio-sdr-rf": [
        ("sigidwiki", "SigIDWiki", FREE, "signal identification"),
        ("frequency-db", "Frequency assignment databases", FREM, "radio-law compliance"),
        ("websdr", "WebSDR network", FREE, ""),
        ("rtl-sdr-community", "RTL-SDR community datasets", FREE, ""),
    ],
    "wireless-wardriving": [
        ("wigle-wireless", "WiGLE wireless", FREM, "registered above; wardriving authority"),
        ("opensignal", "OpenSignal", FREM, "coverage data"),
        ("wifimap", "WiFi mapping projects", FREM, ""),
    ],
    "webcam-exposure": [
        ("insecam", "Insecam", "reference", "privacy/legal review; metadata only"),
        ("shodan-webcams", "Shodan/Censys webcam queries", COMMERCIAL, "via registered APIs"),
        ("ipvm-maps", "IPVM camera maps", FREM, "registered above"),
    ],
    "internet-wide-scans": [
        ("censys-datasets", "Censys datasets", COMMERCIAL, ""),
        ("rapid7-sonar-data", "Rapid7 Open Data", FREE, ""),
        ("internet-census-2012", "Internet Census 2012", FREE, "historical"),
        ("shadowserver-datasets", "Shadowserver datasets", FREE, ""),
    ],
    "archive": [
        ("wayback", "Wayback Machine", FREE, ""),
        ("archive-today", "archive.today", FREM, ""),
        ("common-crawl", "Common Crawl", FREE, "bulk corpus"),
        ("google-cache", "Google cache", FREE, ""),
        ("webcache-indexes", "Web archive indexes", FREE, ""),
    ],
    "search-engines": [
        ("google", "Google", FREE, "dorking corpora"),
        ("bing", "Bing", FREE, ""),
        ("yandex", "Yandex", FREE, ""),
        ("baidu", "Baidu", FREE, ""),
        ("duckduckgo", "DuckDuckGo", FREE, ""),
        ("startpage", "Startpage", FREE, ""),
        ("searx", "Searx instances", FREE, ""),
    ],
    "pastebin-alternatives": [
        ("pastebin", "Pastebin", FREM, "paste monitoring"),
        ("ghostbin", "Ghostbin (successors)", "reference", "monitor only"),
        ("paste-sites", "Paste-site corpora", "reference", "monitor only"),
    ],
    "phishing": [
        ("phishtank", "PhishTank", FREE, ""),
        ("openphish", "OpenPhish", FREM, ""),
        ("urlscan-io", "urlscan.io", FREM, "scan/search corpus"),
        ("phishstats", "PhishStats", FREE, ""),
        ("apwg", "APWG eCrime feeds", FREM, ""),
    ],
    "phishing": [
        ("phishtank", "PhishTank", FREE, ""),
        ("openphish", "OpenPhish", FREM, ""),
        ("urlscan-io", "urlscan.io", FREM, "scan/search corpus"),
        ("phishstats", "PhishStats", FREE, ""),
        ("apwg", "APWG eCrime feeds", FREM, ""),
    ],
    "stealer-logs": [
        ("stealer-log-indexes", "Stealer log indexes (RedLine/Raccoon etc.)", "reference",
         "MONITOR-ONLY: victim-notification/law-enforcement cooperation posture; never acquire or possess; legal review mandatory"),
    ],
    "iab-listings": [
        ("iab-monitoring", "Initial access broker listings", "reference",
         "MONITOR-ONLY: price/actor metadata tracking for defensive intel; never transact; legal review mandatory"),
    ],
    "telegram-discord": [
        ("telegram-channels", "Telegram CTI channels", FREM, "ToS review; monitor only"),
        ("telegram-osint-tools", "Telegram OSINT tooling", FREM, "ToS review"),
        ("discord-discovery", "Discord server discovery", FREM, "ToS review"),
        ("discord-osint", "Discord OSINT tooling", FREM, "ToS review"),
    ],
}


def all_sources() -> list[dict]:
    out: list[dict] = []
    for category, entries in SOURCES.items():
        for (sid, name, access, note) in entries:
            flags = list(CATEGORY_FLAGS.get(category, [])) + EXTRA_FLAGS.get(sid, [])
            out.append({"id": sid, "name": name, "category": category, "access": access, "flags": flags, "note": note})
    return out


def by_category() -> dict[str, int]:
    counts: dict[str, int] = {}
    for s in all_sources():
        counts[s["category"]] = counts.get(s["category"], 0) + 1
    return counts


def summary() -> dict:
    sources = all_sources()
    ids = [s["id"] for s in sources]
    if len(ids) != len(set(ids)):
        dupes = {i for i in ids if ids.count(i) > 1}
        raise ValueError(f"duplicate source ids: {sorted(dupes)}")
    monitor_only = [s["id"] for s in sources if "monitor_only" in s["flags"]]
    legal_gated = [s["id"] for s in sources if "legal_gate" in s["flags"]]
    return {
        "total": len(sources),
        "categories": len(SOURCES),
        "monitor_only": monitor_only,
        "legal_gated_count": len(legal_gated),
        "unverified": [s["id"] for s in sources if "unverified" in s["flags"]],
    }
