"""G9 Arsenal Registry — operator-approved candidates for admission.

The operator has approved this arsenal for admission REVIEW. Nothing
here is admitted to grants until its per-entry gates are satisfied:

  standard          → normal Upstream Admission (pinned revision, license)
  separate_auth     → phishing / on-path / human-target techniques require
                      a SEPARATE RoE addendum (per the redteam-pentest
                      methodology: phishing needs separate authorization)
  license_required  → commercial software (C2 frameworks); a valid license
                      must be recorded. Cracked/unlicensed use is prohibited.
  legal_gate        → breach data / facial recognition / archive sources;
                      use per RoE and applicable law, recorded at admission
  lab_only          → never exposed to untrusted networks
  unverified        → not admitted by default; manual safety review required

Each entry: (id, name, category, sandbox_class, access, flags, note)
"""

from __future__ import annotations

SEPARATE_AUTH = "separate_auth"
LICENSE_REQUIRED = "license_required"
LEGAL_GATE = "legal_gate"
LAB_ONLY = "lab_only"
UNVERIFIED = "unverified"

C = "container"          # restricted-analysis worker class
K = "kvm"                # hostile-research worker class
S = "service"            # hardened host service / data source

CONTAINER_RECON = [
    ("testssl", "testssl.sh", "tls-audit", C, "GPL-2.0", [], ""),
    ("nmap-scoped", "nmap (scoped profile)", "network-recon", C, "GPL-2.0", [], "adapter implemented"),
    ("masscan", "masscan", "network-recon", C, "GPL-2.0", [], "rate-limited profile only"),
    ("subfinder", "subfinder", "passive-recon", C, "MIT", [], ""),
    ("sublist3r", "Sublist3r", "passive-recon", C, "GPL-3.0", [], ""),
    ("amass", "amass (passive profile)", "passive-recon", C, "Apache-2.0", [], "passive modes only by default"),
    ("dnsrecon", "dnsrecon", "dns-recon", C, "GPL-3.0", [], ""),
    ("dig", "dig (scoped)", "dns-recon", C, "Mozilla Public License", [], ""),
    ("recon-ng", "recon-ng", "recon-framework", C, "BSD-3-Clause", [], ""),
    ("bbot", "bbot", "recon-framework", C, "GPL-3.0", [], ""),
    ("feroxbuster", "feroxbuster", "content-discovery", C, "MIT", [], ""),
    ("gobuster", "gobuster", "content-discovery", C, "Apache-2.0", [], ""),
    ("nikto", "nikto", "web-scanning", C, "GPL-2.0", [], "scanner hypothesis only"),
    ("s3scanner", "s3scanner", "cloud-recon", C, "MIT", [], ""),
    ("cloud-enum", "cloud_enum", "cloud-recon", C, "GPL-3.0", [], ""),
    ("cloudbrute", "CloudBrute", "cloud-recon", C, "MIT", [], ""),
    ("spoofcheck", "spoofcheck", "email-recon", C, "MIT", [], ""),
    ("gowitness", "gowitness", "screenshot-recon", C, "Apache-2.0", [], ""),
    ("searchsploit", "searchsploit / exploit-db", "exploit-intel", C, "GPL-2.0", [], "offline DB — reference data"),
    ("bloodhound", "BloodHound CE (collector)", "identity-recon", C, "Apache-2.0", [], "collection only; analysis in the evidence graph"),
    ("cve-bin-tool", "CVE bin tool", "dependency-intel", C, "Apache-2.0", [], ""),
    ("vulnx", "vulnx", "web-scanning", C, "MIT", [], ""),
    ("lfitester", "LFITester", "web-scanning", C, "GPL-3.0", [], "LFI validation"),
]

OSINT_TOOLS = [
    ("spiderfoot", "SpiderFoot", "osint", C, "MIT", [], ""),
    ("maigret", "maigret", "osint-username", C, "MIT", [], ""),
    ("sherlock", "sherlock", "osint-username", C, "MIT", [], ""),
    ("holehe", "holehe", "osint-email", C, "MIT", [], ""),
    ("theharvester", "theHarvester", "osint", C, "GPL-2.0", [], ""),
    ("osintgram", "Osintgram", "osint-social", C, "MIT", [LEGAL_GATE], "platform ToS review at admission"),
    ("ghunt", "GHunt", "osint-email", C, "MIT", [LEGAL_GATE], "platform ToS review at admission"),
    ("osgint", "osgint", "osint-social", C, "GPL-3.0", [LEGAL_GATE], ""),
    ("gallery-dl", "gallery-dl", "osint-media", C, "GPL-2.0", [LEGAL_GATE], ""),
    ("wikit", "wikit", "osint-wikipedia", C, "MIT", [], ""),
    ("sn0int", "sn0int", "osint-framework", C, "GPL-3.0", [], ""),
    ("minesight", "MineSight", "osint", C, "unknown", [UNVERIFIED], "license review at admission"),
    ("slackpirate", "SlackPirate", "osint-workspace", C, "MIT", [SEPARATE_AUTH], "requires explicit workspace authorization"),
    ("0xdork", "0xdork", "osint-dorking", C, "MIT", [], ""),
    ("reconftw", "reconftw", "recon-framework", C, "GPL-3.0", [], "wrapper — dependency admission cascades"),
    ("prot1ntelligence", "Prot1ntelligence", "osint", C, "GPL-3.0", [], ""),
    ("masto", "Masto", "osint-social", C, "MIT", [], ""),
    ("hackingtool", "hackingtool (z4nzu)", "tool-wrapper", C, "MIT", [UNVERIFIED], "wrapper — every wrapped tool admits separately"),
]

# Operator intake expansion (build request): installable OSINT tools
# from the operator's supplied list. Same admission gates as the rest
# of the registry; licenses marked "open-source" need verification at
# admission before qualification.
INTAKE_TOOLS = [
    ("exiftool", "ExifTool", "metadata-forensics", C, "GPL-1.0+", [], "read/strip EXIF/metadata"),
    ("hachoir", "hachoir", "metadata-forensics", C, "GPL-2.0", [], "binary metadata parsing"),
    ("mutagen", "mutagen", "metadata-forensics", C, "GPL-2.0", [], "audio metadata"),
    ("goris", "goris", "metadata-forensics", C, "MIT", [], "Google reverse image search CLI"),
    ("lemeknow", "lemeknow", "file-identification", C, "MIT", [], "file magic identification"),
    ("dnstwist", "dnstwist", "domain-intel", C, "Apache-2.0", [], "typosquat/domain permutation"),
    ("opensquat", "openSquat", "domain-intel", C, "GPL-3.0", [], "domain squatting/phishing monitoring"),
    ("cloakquest3r", "CloakQuest3r", "domain-intel", C, "MIT", [], "real-IP discovery behind CDN/Cloudflare"),
    ("miteru", "miteru", "phishing-intel", C, "MIT", [], "phishing kit discovery"),
    ("hakrawler", "hakrawler", "web-crawl", C, "MIT", [], "JS/endpoint discovery — in-scope targets only"),
    ("cloudscraper-potti", "CloudScraper (jordanpotti)", "cloud-enum", C, "MIT", [], "cloud asset enumeration from TLDs"),
    ("thescrapper", "TheScrapper", "web-scrape", C, "MIT", [], "email/phone/social scraping — ToS review at admission"),
    ("github-search-gwen001", "github-search (gwen001)", "code-search", C, "MIT", [], "GitHub OSINT queries"),
    ("h8mail", "h8mail", "osint-email", C, "MIT", [LEGAL_GATE], "breach-source queries — per RoE and law"),
    ("mailmeta", "mailMeta", "osint-email", C, "MIT", [], "email metadata parsing"),
    ("chiasmodon", "chiasmodon", "osint-email", C, "MIT", [LEGAL_GATE], "email/domain attribution via multiple sources — ToS review"),
    ("nexfil", "nexfil", "osint-username", C, "MIT", [], "username profiling across platforms"),
    ("marple", "marple", "osint-username", C, "MIT", [], "username search by geolocation/time"),
    ("aliens-eye", "Aliens_eye", "osint-username", C, "open-source", [], "username enumeration"),
    ("snoop", "snoop", "osint-username", C, "open-source", [LEGAL_GATE], "searches included leak databases — per RoE and law"),
    ("pyosint", "Pyosint", "osint-username", C, "open-source", [], "username search"),
    ("blackbird", "blackbird", "osint-username", C, "MIT", [], "username/account discovery"),
    ("phonenumber-osint", "PhoneNumber-OSINT", "osint-phone", C, "MIT", [LEGAL_GATE], "phone lookup APIs — ToS review at admission"),
    ("clearfront", "clearfront", "osint-people", C, "MIT", [], "people search aggregation"),
    ("daprofiler", "DaProfiler", "osint-people", C, "GPL-3.0", [], "profile aggregation"),
    ("rug", "rug", "osint-people", C, "MIT", [], "person lookup via breach/phone APIs"),
    ("leaky", "LEAKEY", "osint-people", C, "MIT", [LEGAL_GATE], "email/username via breach APIs — per RoE and law"),
    ("thedevilseye", "thedevilseye", "darkweb-osint", C, "MIT", [], "onion service enumeration — monitor-only posture per dark-web governance"),
    ("thelordseye", "thelordseye", "darkweb-osint", C, "MIT", [], "onion service enumeration — monitor-only posture per dark-web governance"),
    ("occli", "occli", "osint-people", C, "MIT", [], "people search CLI"),
    ("grep-for-osint", "grep_for_osint", "code-search", C, "MIT", [], "grep query collections"),
    ("credit-osint", "Credit-OSINT", "financial-osint", C, "open-source", [LEGAL_GATE], "card/BIN info tooling — legal review at admission; QA/test use only"),
    ("scrummage", "Scrummage", "osint-framework", C, "GPL-3.0", [], "framework — every module admits separately"),
    ("gomapenum", "GoMapEnum", "osint-enum", C, "open-source", [], "user/account enumeration"),
    ("reconspider", "reconspider", "osint-framework", C, "open-source", [UNVERIFIED], "framework — manual review + per-module admission"),
    ("semid", "SEMID", "osint-email", C, "open-source", [], "email enumeration"),
    ("maryam", "Maryam", "osint-framework", C, "open-source", [], "framework — per-module admission"),
    ("osint-toolkit", "OSINT Toolkit (dev-lu)", "osint-framework", C, "open-source", [], "web toolkit — self-hosted"),
    ("cronodump", "cronodump", "data-export", C, "MIT", [], "Aleph export tooling"),
    ("obsidian-cli", "obsidian-cli", "notekeeping", C, "MIT", [], "investigation notekeeping"),
    ("orion-araekiel", "Orion (Araekiel)", "osint-framework", C, "MIT", [], "query framework"),
    ("sourcebot", "SourceBot", "code-search", C, "AGPL-3.0", [], "self-hosted code search"),
    ("ton-of-privacy", "a_TON_of_privacy", "privacy-tradecraft", C, "MIT", [], "privacy/anonymity tradecraft collection"),
    ("cyberchef-tool", "CyberChef", "data-analysis", C, "Apache-2.0", [], "data format analysis"),
    ("tldr-pages-tool", "tldr pages (client)", "reference", C, "MIT", [], "command reference"),
]

SECRET_SCANNING = [
    ("gitleaks", "gitleaks", "secret-scanning", C, "MIT", [], ""),
    ("trufflehog", "trufflehog", "secret-scanning", C, "AGPL-3.0", [LICENSE_REQUIRED], "AGPL gate for commercial integration"),
]

DEFENSE_TELEMETRY = [
    ("wazuh", "Wazuh", "defense-monitoring", S, "GPL-2.0", [], "detection, not enforcement"),
    ("suricata", "Suricata", "defense-monitoring", S, "GPL-2.0", [], "detection, not enforcement"),
    ("wireshark", "Wireshark", "traffic-analysis", C, "GPL-2.0", [], "captured evidence only"),
    ("tshark", "tshark", "traffic-analysis", C, "GPL-2.0", [], "captured evidence only"),
]

KVM_HOSTILE = [
    ("metasploit", "Metasploit Framework", "exploitation", K, "BSD-3-Clause", [SEPARATE_AUTH], "high-impact: per-action operator approval"),
    ("msfvenom", "msfvenom", "payload-gen", K, "BSD-3-Clause", [SEPARATE_AUTH], "high-impact: per-action approval"),
    ("shellter", "Shellter", "payload-obfuscation", K, "proprietary-freemium", [SEPARATE_AUTH], "AV-evasion: lab/authorized engagements only"),
    ("hydra", "hydra", "credential-attack", K, "AGPL-3.0", [SEPARATE_AUTH, LICENSE_REQUIRED], "online attacks: per-action approval + RoE rate limits"),
    ("hashcat", "hashcat", "credential-cracking", K, "MIT", [], "offline cracking of engagement-collected evidence"),
    ("john", "John the Ripper", "credential-cracking", K, "GPL-2.0", [], "offline cracking of engagement-collected evidence"),
    ("aircrack-ng", "aircrack-ng", "wireless", K, "GPL-2.0", [SEPARATE_AUTH], "wireless testing requires explicit wireless scope"),
    ("ettercap", "ettercap", "on-path", K, "GPL-3.0", [SEPARATE_AUTH], "on-path techniques: separate RoE addendum"),
    ("mitmproxy", "mitmproxy", "on-path", K, "MIT", [SEPARATE_AUTH], "on-path techniques: separate RoE addendum"),
    ("binwalk", "binwalk", "firmware-re", K, "MIT", [], "untrusted firmware images — disposable guests"),
    ("ghidra", "Ghidra (headless, scoped API)", "reverse-engineering", K, "Apache-2.0", [], ""),
    ("rea", "REA", "reverse-engineering", K, "review", [], "G9 REA Intelligence Service backend"),
    ("sqlmap", "sqlmap", "web-exploitation", K, "GPL-2.0", [SEPARATE_AUTH], "writes to target DBs: per-action approval"),
    ("mimikatz", "mimikatz (authorized scope only)", "credential-access", K, "CC-BY-4.0", [SEPARATE_AUTH], "in-scope hosts only; evidence handling per RoE"),
    ("impacket", "impacket", "protocol-exploitation", K, "CC-BY-4.0", [SEPARATE_AUTH], "per-action approval"),
    ("lazagne", "LaZagne", "credential-access", K, "GPL-3.0", [SEPARATE_AUTH], "in-scope hosts only"),
    ("pcredz", "PCredz", "credential-access", K, "GPL-3.0", [SEPARATE_AUTH], "captures: separate RoE addendum"),
    ("certify", "Certify", "adcs-abuse", K, "BSD-3-Clause", [SEPARATE_AUTH], "per-action approval"),
    ("coercer", "Coercer", "coercion-testing", K, "GPL-3.0", [SEPARATE_AUTH], "per-action approval"),
    ("snaffler", "Snaffler", "share-discovery", K, "GPL-3.0", [SEPARATE_AUTH], "per-action approval"),
    ("evil-winrm", "evil-winrm", "remote-exec", K, "MIT", [SEPARATE_AUTH], "per-action approval"),
    ("ligolo-ng", "ligolo-ng", "tunneling", K, "GPL-3.0", [SEPARATE_AUTH], "per-action approval"),
    ("pingcastle", "PingCastle", "ad-audit", C, "AGPL-3.0/commercial", [LICENSE_REQUIRED], "read-only audit profile"),
    ("linwinpwn", "linWinPwn", "ad-audit", K, "GPL-3.0", [SEPARATE_AUTH], ""),
    ("beef", "BeEF", "client-attack", K, "Apache-2.0", [SEPARATE_AUTH], "browser exploitation: separate authorization"),
    ("evilginx2", "evilginx2", "phishing-proxy", K, "GPL-3.0", [SEPARATE_AUTH], "phishing: separate RoE addendum mandatory"),
    ("modlishka", "Modlishka", "phishing-proxy", K, "MIT", [SEPARATE_AUTH], "phishing: separate RoE addendum mandatory"),
    ("merlin", "Merlin", "c2", K, "Apache-2.0", [SEPARATE_AUTH, LAB_ONLY], "authorized emulation only"),
    ("redelk", "RedELK", "c2-logging", S, "AGPL-3.0", [], "infrastructure telemetry"),
    ("specterinsight", "SpecterInsight", "c2", K, "commercial", [SEPARATE_AUTH, LICENSE_REQUIRED], "valid license required"),
    ("cs-situational-awareness-bof", "CS-Situational-Awareness-BOF", "post-exploit", K, "Apache-2.0", [SEPARATE_AUTH], "per-action approval"),
    ("pacu", "Pacu", "cloud-exploitation", K, "MIT", [SEPARATE_AUTH], "per-action approval"),
    ("atomic-red-team", "Atomic Red Team", "emulation-library", C, "MIT", [], "controlled technique validation"),
]

C2_COMMERCIAL = [
    ("cobalt-strike", "Cobalt Strike", "c2", K, "commercial", [LICENSE_REQUIRED, SEPARATE_AUTH, LAB_ONLY],
     "VALID LICENSE REQUIRED — cracked/unlicensed use is prohibited and never admitted"),
    ("brute-ratel-c4", "Brute Ratel C4", "c2", K, "commercial", [LICENSE_REQUIRED, SEPARATE_AUTH, LAB_ONLY],
     "VALID LICENSE REQUIRED — cracked/unlicensed use is prohibited and never admitted"),
]

KNOWLEDGE_BASES = [
    ("gtfobins", "GTFOBins", "knowledge-base", S, "MIT", [], "privesc reference"),
    ("lolbas", "LOLBAS", "knowledge-base", S, "MIT", [], "Windows living-off-the-land reference"),
    ("loldrivers", "LOLDrivers", "knowledge-base", S, "MIT", [], "vulnerable-driver reference"),
    ("loobins", "LOOBins", "knowledge-base", S, "MIT", [], "macOS LOL reference"),
    ("wtfbins", "wtfbins", "knowledge-base", S, "MIT", [], ""),
    ("hijacklibs", "HijackLibs", "knowledge-base", S, "MIT", [], "DLL hijacking reference"),
    ("lots-project", "LOTS-Project", "knowledge-base", S, "MIT", [], "living-off-the-land reference"),
    ("cs-community-kit", "Cobalt Strike Community Kit", "knowledge-base", S, "MIT", [], ""),
]

CTI_SOURCES = [
    ("awesome-threat-intel", "awesome-threat-intelligence", "cti", S, "CC-BY-4.0", [], "curated list"),
    ("apt-report", "APT_REPORT", "cti", S, "mixed", [LEGAL_GATE], "report archive"),
    ("deepdarkcti", "deepdarkCTI", "cti", S, "MIT", [], ""),
    ("startme-cti", "start.me CTI portal", "cti", S, "web", [], ""),
    ("hudsonrock", "Hudson Rock threat intel", "cti", S, "commercial", [LEGAL_GATE], "infostealer data — legal review at admission"),
    ("dehashed", "DeHashed", "breach-data", S, "commercial", [LEGAL_GATE], "breach data: per RoE and law; elite-standards credential-exposure rule"),
    ("intelligencex", "IntelligenceX", "breach-data", S, "commercial", [LEGAL_GATE], "breach data: per RoE and law"),
    ("cxsecurity", "cxsecurity.com", "advisory-source", S, "web", [], ""),
    ("shodan", "Shodan", "attack-surface-intel", S, "commercial-api", [], "API key admission"),
    ("censys", "Censys", "attack-surface-intel", S, "commercial-api", [], "API key admission"),
    ("abusech", "abuse.ch feeds", "cti-feed", S, "free-api", [], "URLhaus/ThreatFox/MalwareBazaar/Feodo/SSLBL/YARAify — metadata-level queries only"),
    ("otx", "AlienVault OTX", "cti-feed", S, "free-api", [], "API key admission"),
    ("identity-vault", "Engagement identity vault", "engagement-identity", S, "in-house", [SEPARATE_AUTH], "temp/anonymous identities for operator-registered accounts only; phishing-class purposes need the separate RoE addendum"),
    ("simplelogin", "SimpleLogin (self-hosted alias domain)", "engagement-identity", S, "MIT", [], "operator-owned alias domain required at admission"),
    ("anonaddy", "AnonAddy (self-hosted alias domain)", "engagement-identity", S, "MIT", [], "operator-owned alias domain required at admission"),
    ("tidal-cyber", "Tidal Cyber", "threat-informed-defense", S, "commercial", [], "ATT&CK mapping reference"),
    ("control-validation-compass", "Control Validation Compass", "threat-informed-defense", S, "commercial", [], ""),
]

PLATFORMS = [
    ("ghostwriter", "Ghostwriter", "op-management", S, "BSD-3-Clause", [], "engagement ops platform"),
    ("nemesis", "SpecterOps Nemesis", "evidence-processing", S, "GPL-3.0", [], "study for ingestion/enrichment; not authoritative DB"),
    ("rt-infrastructure-wiki", "Red-Team-Infrastructure-Wiki", "knowledge-base", S, "MIT", [], ""),
    ("red-team-infra", "red-team infrastructure references", "knowledge-base", S, "web", [], ""),
]

AI_RED_TEAM = [
    ("promptfoo", "promptfoo", "ai-red-team", C, "MIT", [], ""),
    ("garak", "garak", "ai-red-team", C, "Apache-2.0", [], ""),
    ("deepeval", "DeepEval", "ai-evaluation", C, "Apache-2.0", [], ""),
    ("pyrit", "PyRIT", "ai-red-team", C, "MIT", [], ""),
    ("fuzzyai", "FuzzyAI", "ai-red-team", C, "MIT", [], ""),
    ("raptor", "raptor (gadievron)", "ai-red-team", C, "MIT", [], ""),
]

G9_FAMILY = [
    ("st3gg", "ST3GG", "g9-family", C, "review", [UNVERIFIED], "operator-authored; manual review"),
    ("clar1t4s", "CL4R1T4S", "g9-family", C, "review", [UNVERIFIED], ""),
    ("t3mp3st", "T3MP3ST", "g9-family", C, "review", [UNVERIFIED], ""),
    ("g0dm0d3", "G0DM0D3", "g9-family", C, "review", [UNVERIFIED], ""),
    ("obl1ter4tus", "OBLITERATUS", "g9-family", C, "review", [UNVERIFIED], ""),
    ("l1b3rt4s", "L1B3RT4S", "g9-family", C, "review", [UNVERIFIED], ""),
    ("v3r1t4s", "V3R1T4S", "g9-family", C, "review", [UNVERIFIED], ""),
    ("p4rs3lt0ngv3", "P4RS3LT0NGV3", "g9-family", C, "review", [UNVERIFIED], ""),
    ("frv1t", "FRV1T", "g9-family", C, "review", [UNVERIFIED], ""),
    ("n4tur4l1s-h1st0r14", "NATURALIS-HISTORIA", "g9-family", C, "review", [UNVERIFIED], ""),
    ("gl4ss", "GL4SS", "g9-family", C, "review", [UNVERIFIED], ""),
    ("fable-showcase", "FABLE-SHOWCASE", "g9-family", C, "review", [UNVERIFIED], ""),
    ("glossopetrae", "GLOSSOPETRAE", "g9-family", C, "review", [UNVERIFIED], ""),
    ("autotemp", "AutoTemp", "g9-family", C, "review", [UNVERIFIED], ""),
]

INTEL_SOURCES_WEB = [
    # OSINT web sources approved for qualification as data sources (not tools)
    ("huntintel", "huntintel.io", "intel-source", S, "web", [], ""),
    ("pizzint", "pizzint.watch", "intel-source", S, "web", [], ""),
    ("worldmonitor", "worldmonitor.app", "intel-source", S, "web", [], ""),
    ("monitor-the-situation", "monitor-the-situation.com", "intel-source", S, "web", [], ""),
    ("openindoor", "openindoor.io", "geo-source", S, "web", [], ""),
    ("raven", "raven", "intel-source", S, "web", [], ""),
    ("poweroutage", "poweroutage.com", "infra-source", S, "web", [], ""),
    ("alltext-nyc", "alltext.nyc", "infra-source", S, "web", [], ""),
    ("streetartcities", "streetartcities.com", "geo-source", S, "web", [], ""),
    ("skydb", "skydb.net", "geo-source", S, "web", [], ""),
    ("sondehub", "sondehub.org", "infra-source", S, "web", [], ""),
    ("camstreamer", "camstreamer live map", "geo-source", S, "web", [LEGAL_GATE], "camera feeds — privacy review"),
    ("ipvm-calculator", "IPVM calculator", "geo-source", S, "web", [], ""),
    ("g-map-extractor", "G Map Extractor", "geo-source", S, "web", [LEGAL_GATE], "platform ToS review"),
    ("gpsvisualizer", "gpsvisualizer.net", "geo-source", S, "web", [], ""),
    ("mapnificent", "mapnificent.net", "geo-source", S, "web", [], ""),
    ("openswitchmaps", "OpenSwitchMaps", "geo-source", S, "web", [], ""),
    ("waze-live-map", "Waze live map", "geo-source", S, "web", [LEGAL_GATE], "platform ToS review"),
    ("opencellid", "opencellid.org", "geo-source", S, "web", [], ""),
    ("cellmapper", "cellmapper.net", "geo-source", S, "web", [], ""),
    ("anyrun", "any.run", "sandbox-analysis", S, "commercial", [], "external sandbox — samples leave the enclave; approval per use"),
    ("geowifi", "geowifi", "geo-source", C, "MIT", [], ""),
    ("infrapedia", "infrapedia.com", "infra-source", S, "web", [], ""),
    ("ooni-explorer", "ooni explorer", "infra-source", S, "web", [], ""),
    ("palimpsest", "palimpsest.info", "intel-source", S, "web", [], ""),
    ("earthkit-agent", "earthkit agent", "geo-source", S, "web", [], ""),
    ("farearth-observer", "farearth observer", "geo-source", S, "web", [], ""),
    ("nasa-earthdata", "NASA earthdata search", "geo-source", S, "web", [], ""),
    ("copernicus-scihub", "Copernicus scihub", "geo-source", S, "web", [], ""),
    ("keyhole", "keyhole.engelsjk.com", "geo-source", S, "web", [], ""),
    ("nato-map", "NATO on the map", "geo-source", S, "web", [], ""),
    ("worldbeyondwar", "worldbeyondwar bases map", "geo-source", S, "web", [], ""),
    ("f4map", "f4map demo", "geo-source", S, "web", [], ""),
    ("flock-network", "flock.network", "geo-source", S, "web", [], ""),
    ("whodidit", "OSM whodidit", "geo-source", S, "web", [], ""),
    ("followeraudit", "followeraudit", "osint-social", S, "commercial", [LEGAL_GATE], "platform ToS review"),
    ("apify-actor", "apify actor u6ppkMWAx2E2MpEuF", "osint-scraping", S, "commercial", [LEGAL_GATE], "ToS review"),
    ("waybackmachine", "Wayback Machine", "intel-source", S, "web", [], ""),
    ("hackertube", "hackertube.org", "intel-source", S, "web", [], ""),
    ("einzzcookie", "einzzcookie.org", "intel-source", S, "web", [], ""),
    ("search4faces", "search4faces", "facial-recognition", S, "commercial", [LEGAL_GATE, SEPARATE_AUTH], "facial recognition — legal + privacy review mandatory"),
    ("pemeyes", "pemeyes", "intel-source", S, "web", [], ""),
    ("national-breach-db", "national public databreach database", "breach-data", S, "web", [LEGAL_GATE], "breach data: per RoE and law"),
    ("4plebs-archive", "archive.4plebs.org", "archive-source", S, "web", [LEGAL_GATE], "content archive — ToS/legal review"),
    ("nzbfriends", "nzbfriends", "archive-source", S, "web", [LEGAL_GATE], ""),
    ("nodehist", "nodehist (fidonet)", "archive-source", S, "web", [], ""),
    ("imginn", "imginn", "osint-social", S, "web", [LEGAL_GATE], "platform ToS review"),
    ("graphtreon", "graphtreon", "osint-financial", S, "web", [], ""),
    ("map-of-github", "map-of-github", "osint-code", S, "MIT", [], ""),
    ("wikipedia-crosslingual", "digitalmethods wikipedia tools", "osint-wikipedia", S, "web", [], ""),
    ("wikiwho", "wikiwho", "osint-wikipedia", S, "web", [], ""),
    ("xboxgamertag", "xboxgamertag.com", "osint-username", S, "web", [], ""),
    ("exportcomments", "exportcomments.com", "osint-scraping", S, "commercial", [LEGAL_GATE], "ToS review"),
    ("thevisualized", "thevisualized.com", "osint-visual", S, "web", [], ""),
    ("whatsapp-checker", "2chat whatsapp checker", "osint-social", S, "web", [LEGAL_GATE], "messenger probing — ToS/privacy review"),
    ("wagpscraper", "WaGpScraper", "osint-social", C, "MIT", [LEGAL_GATE, SEPARATE_AUTH], "messenger scraping — ToS/privacy review"),
    ("google-dorks", "google dorks collections", "osint-dorking", S, "web", [], "taksec/dorkgenius/dorkgpt references"),
    ("snyk-site-scanner", "snyk.io website scanner", "web-scanning", S, "web", [], "external service — data leaves enclave"),
    ("tiny-scan", "tiny-scan.com", "web-scanning", S, "web", [], ""),
    ("ichi-global", "ichi.global", "osint-subdomain", S, "web", [], ""),
    ("sisik-apk-tool", "sisik.eu apk tool", "mobile-analysis", S, "web", [], ""),
    ("extract-pics", "extract.pics", "osint-media", S, "web", [], ""),
    ("cyb-detective-thread-1", "cyb_detective thread 1578772549919559681", "intel-source", S, "web", [], ""),
    ("cyb-detective-thread-2", "cyb_detective thread 1536682540265873408", "intel-source", S, "web", [], ""),
    ("goshs", "goshs", "file-transfer", C, "MIT", [SEPARATE_AUTH], "operator-controlled transfer service only"),
]

UNVERIFIED_SOURCES = [
    ("onion-pet-proxy", "onion.pet Tor proxy (4wbwa6…)", "unverified-source", S, "unknown",
     [UNVERIFIED, LEGAL_GATE],
     "NOT ADMITTED: operator requested heavy verification; Tor hidden-service "
     "proxies are unverified provenance — manual safety + legal review required "
     "before any use; excluded from all automated pipelines by default"),
]


# ---------------------------------------------------------------------------
# Wave 2 additions (operator-approved; repeats skipped — already registered:
# nuclei, sqlmap, pacu, ghostwriter, trufflehog, gitleaks, cobalt-strike,
# hashcat, john, hydra, mimikatz, impacket, lazagne, metasploit, ettercap,
# mitmproxy, aircrack-ng, s3scanner, cloudbrute, semgrep, searchsploit)
# ---------------------------------------------------------------------------

C2_FRAMEWORKS_W2 = [
    ("mythic", "Mythic", "c2", K, "BSD-3-Clause", [SEPARATE_AUTH, LAB_ONLY], "open C2 framework; per-action approval"),
    ("sliver", "Sliver", "c2", K, "BSD-3-Clause", [SEPARATE_AUTH, LAB_ONLY], "implant framework; per-action approval"),
    ("empire-starkiller", "Empire + Starkiller", "c2", K, "BSD-3-Clause", [SEPARATE_AUTH, LAB_ONLY], "per-action approval"),
    ("havoc", "Havoc", "c2", K, "BSD-3-Clause", [SEPARATE_AUTH, LAB_ONLY], "per-action approval"),
    ("nighthawk", "Nighthawk", "c2", K, "commercial", [SEPARATE_AUTH, LICENSE_REQUIRED, LAB_ONLY], "valid license required"),
    ("maktego", "maktego", "unverified-tool", K, "unknown", [UNVERIFIED], "could not identify — manual review"),
    ("naubik", "naubik", "unverified-tool", K, "unknown", [UNVERIFIED], "could not identify — manual review"),
]

POST_EXPLOIT_AD = [
    ("netexec", "NetExec", "post-exploit", K, "BSD-2-Clause", [SEPARATE_AUTH], "per-action approval"),
    ("rubeus", "Rubeus", "kerberos-abuse", K, "GPL-3.0", [SEPARATE_AUTH], ""),
    ("sharphound", "SharpHound", "identity-recon", K, "GPL-3.0", [SEPARATE_AUTH], "collection only"),
    ("azurehound", "AzureHound", "identity-recon", K, "GPL-3.0", [SEPARATE_AUTH], "collection only"),
    ("certipy", "Certipy", "adcs-abuse", K, "MIT", [SEPARATE_AUTH], ""),
    ("inveigh", "Inveigh", "spoofing", K, "GPL-3.0", [SEPARATE_AUTH], "on-path: separate RoE addendum"),
    ("adrecon", "ADRecon", "ad-audit", C, "MIT", [], "read-only audit"),
    ("powersploit", "PowerSploit", "post-exploit", K, "Apache-2.0", [SEPARATE_AUTH], "per-action approval"),
    ("responder", "Responder", "spoofing", K, "GPL-3.0", [SEPARATE_AUTH], "relay chain: separate RoE addendum"),
    ("ntlmrelayx", "ntlmrelayx (impacket)", "relay", K, "CC-BY-4.0", [SEPARATE_AUTH], "relay chain: separate RoE addendum"),
    ("mitm6", "mitm6", "relay", K, "MIT", [SEPARATE_AUTH], "relay chain: separate RoE addendum"),
    ("petitpotam", "PetitPotam", "coercion", K, "MIT", [SEPARATE_AUTH], "coercion primitive: per-action approval"),
    ("printerbug", "PrinterBug", "coercion", K, "MIT", [SEPARATE_AUTH], ""),
    ("coerce-primitives", "Coercer (already registered) + DirCoerce family", "coercion", K, "mixed", [SEPARATE_AUTH], "see coercer entry"),
    ("adcspwn", "ADCSPwn", "escalation", K, "MIT", [SEPARATE_AUTH], ""),
    ("krbrelayup", "KrbRelayUp", "escalation", K, "MIT", [SEPARATE_AUTH], ""),
    ("ldapsearch", "ldapsearch", "directory-query", C, "OpenLDAP", [], "read-only queries"),
    ("windapsearch", "windapsearch", "directory-query", C, "BSD-3-Clause", [], "read-only queries"),
    ("pygpoabuse", "pyGPOAbuse", "gpo-abuse", K, "MIT", [SEPARATE_AUTH], "per-action approval"),
    ("sharpgpoabuse", "SharpGPOAbuse", "gpo-abuse", K, "MIT", [SEPARATE_AUTH], ""),
    ("dacledit", "dacledit.py", "acl-abuse", K, "MIT", [SEPARATE_AUTH], ""),
    ("bloodyad", "BloodyAD", "acl-abuse", K, "MIT", [SEPARATE_AUTH], ""),
    ("secretsdump", "secretsdump (impacket)", "credential-access", K, "CC-BY-4.0", [SEPARATE_AUTH], "evidence handling per RoE"),
    ("getnpusers", "GetNPUsers (impacket)", "credential-access", K, "CC-BY-4.0", [SEPARATE_AUTH], ""),
    ("getuserspnss", "GetUserSPNs (impacket)", "credential-access", K, "CC-BY-4.0", [SEPARATE_AUTH], ""),
    ("wmiexec-psexec", "wmiexec / psexec (impacket)", "remote-exec", K, "CC-BY-4.0", [SEPARATE_AUTH], "per-action approval"),
    ("pypykatz", "pypykatz", "credential-access", K, "MIT", [SEPARATE_AUTH], "LSASS parsing of engagement evidence"),
    ("kerbrute", "Kerbrute", "credential-spray", K, "GPL-3.0", [SEPARATE_AUTH], "online attacks: per-action approval + rate limits"),
]

TUNNELING_INFRA = [
    ("chisel", "chisel", "tunneling", K, "MIT", [SEPARATE_AUTH], "per-action approval"),
    ("shuttle", "shuttle", "tunneling", K, "unknown", [UNVERIFIED], "manual review"),
    ("veil", "Veil Framework", "payload-gen", K, "AGPL-3.0", [SEPARATE_AUTH, LICENSE_REQUIRED], "AV-evasion: lab/authorized only"),
    ("donut", "donut", "payload-gen", K, "BSD-3-Clause", [SEPARATE_AUTH], ""),
    ("scarecrow", "ScareCrow", "payload-gen", K, "MIT", [SEPARATE_AUTH], ""),
    ("pezor", "PEzor", "payload-gen", K, "MIT", [SEPARATE_AUTH], ""),
    ("freeze", "Freeze", "payload-gen", K, "MIT", [SEPARATE_AUTH], ""),
    ("sigthief", "SigThief", "signature-theft", K, "MIT", [SEPARATE_AUTH], "lab/authorized engagements only"),
    ("limelighter", "LimeLighter", "signature-theft", K, "MIT", [SEPARATE_AUTH], ""),
    ("chimera", "chimera", "payload-obfuscation", K, "GPL-3.0", [SEPARATE_AUTH], ""),
    ("inceptor", "Inceptor", "payload-obfuscation", K, "MIT", [SEPARATE_AUTH], ""),
    ("defendercheck", "DefenderCheck / ThreatCheck", "av-testing", K, "MIT", [LAB_ONLY], "own defensive posture testing"),
    ("pe-bear", "PE-bear / CFF Explorer / LIEF", "binary-surgery", K, "freeware/MIT", [], "LIEF scriptable"),
    ("sharpcollection", "SharpCollection", "payload-library", K, "MIT", [SEPARATE_AUTH, LAB_ONLY], ""),
    ("amsi-bypass-corpus", "AMSI bypass corpus (rotating)", "evasion-corpus", K, "mixed", [SEPARATE_AUTH, LAB_ONLY], "own-lab testing only"),
    ("malleable-profiles", "Malleable C2 / Sliver HTTP profiles", "c2-profiles", K, "mixed", [SEPARATE_AUTH, LAB_ONLY], ""),
    ("proxychains", "proxychains", "tunneling", C, "GPL-3.0", [], ""),
    ("socat-ncat", "socat / ncat", "relay", K, "GPL-2.0/MIT", [SEPARATE_AUTH], "listener setup: per-action approval"),
    ("cloudflared-ngrok", "cloudflared / ngrok external listeners", "tunneling", S, "commercial-terms", [SEPARATE_AUTH], "external exposure: per-action approval + scope note"),
    ("rclone", "rclone (exfil interface)", "exfiltration", K, "MIT", [SEPARATE_AUTH], "exfil tests: named scope authorization required"),
    ("wireguard", "WireGuard", "connectivity", S, "MIT", [], "target connectivity"),
]

SOCIAL_ENGINEERING = [
    ("gophish", "GoPhish", "phishing-platform", K, "MIT", [SEPARATE_AUTH], "phishing: separate RoE addendum mandatory"),
    ("set-toolkit", "Social Engineer Toolkit", "social-engineering", K, "BSD-3-Clause", [SEPARATE_AUTH], "separate RoE addendum mandatory"),
]

WEB_API_TOOLS = [
    ("burp-suite-pro", "Burp Suite Professional (REST API)", "dast", C, "commercial", [LICENSE_REQUIRED], "valid license; REST API is the automation surface"),
    ("caido", "Caido", "dast", C, "commercial", [LICENSE_REQUIRED], "GraphQL API"),
    ("owasp-zap", "OWASP ZAP", "dast", C, "Apache-2.0", [], "headless pipelines"),
    ("invicti", "Invicti", "dast", C, "commercial", [LICENSE_REQUIRED], ""),
    ("nessus", "Nessus", "credentialed-scan", C, "commercial", [LICENSE_REQUIRED], ""),
    ("openvas", "OpenVAS / Greenbone", "credentialed-scan", C, "GPL-2.0", [], ""),
    ("xsstrike-dalfox", "XSStrike / Dalfox", "xss-automation", K, "MIT", [SEPARATE_AUTH], "writes to target apps: per-action approval"),
    ("commix", "Commix", "command-injection", K, "GPL-3.0", [SEPARATE_AUTH], "per-action approval"),
    ("ssrfmap-gopherus", "SSRFmap / Gopherus", "ssrf-exploitation", K, "MIT/GPL-3.0", [SEPARATE_AUTH], "per-action approval"),
    ("jwt-tooling", "jwt_tool / jwt-cracker", "jwt-testing", K, "MIT", [], "engagement-collected tokens only"),
    ("ysoserial", "ysoserial / ysoserial.net / marshalsec", "deserialization", K, "MIT", [SEPARATE_AUTH], "gadget-chain validation in lab first"),
    ("exploit-template-library", "Log4Shell/Spring4Shell-class exploit templates", "exploit-templates", K, "mixed", [SEPARATE_AUTH, LAB_ONLY], "template library, lab validation before engagement use"),
    ("autorize-authmatrix", "autorize / authmatrix (Burp extensions)", "authz-testing", C, "MIT", [], ""),
    ("param-miner", "param-miner", "param-discovery", C, "MIT", [], ""),
    ("arjun", "Arjun", "param-discovery", C, "GPL-3.0", [], ""),
    ("kiterunner", "kiterunner", "api-discovery", C, "GPL-3.0", [], ""),
    ("graphql-cop", "GraphQL Voyager / graphql-cop", "graphql-testing", C, "MIT", [], ""),
    ("waybackurls-gau-katana", "waybackurls / gau / katana", "url-harvest", C, "MIT", [], "passive"),
    ("wappalyzer-whatweb", "Wappalyzer / WhatWeb", "tech-fingerprint", C, "MIT", [], ""),
    ("crt-sh-certstream", "crt.sh API / certstream", "ct-mining", S, "web/api", [], "passive"),
    ("smtp-user-enum-swaks", "smtp-user-enum / swaks", "smtp-recon", K, "GPL-2.0/MIT", [SEPARATE_AUTH], "mail infrastructure: rate-limited, per RoE"),
    ("enum4linux-rpcclient", "enum4linux-ng / rpcclient", "smb-rpc-recon", K, "GPL-3.0", [SEPARATE_AUTH], "authenticated enumeration per RoE"),
    ("snmpwalk-onesixtyone", "snmpwalk / onesixtyone", "snmp-recon", C, "BSD/MIT", [], "reads only"),
    ("showmount", "showmount / nfsshell", "nfs-recon", C, "BSD/GPL", [], ""),
    ("alive6-dnsdict6", "alive6 / dnsdict6", "ipv6-recon", C, "GPL-2.0", [], "dual-stack coverage"),
]

CLOUD_K8S = [
    ("scout-suite", "Scout Suite", "cloud-audit", C, "GPL-2.0", [], "machine-readable output"),
    ("microburst", "MicroBurst", "cloud-recon", K, "MIT", [SEPARATE_AUTH], "per-action approval"),
    ("roadrecon", "ROADrecon", "azure-ad-recon", K, "MIT", [SEPARATE_AUTH], "read-only profile first"),
    ("azure-suite", "Azure-Suite tools", "cloud-recon", K, "MIT", [SEPARATE_AUTH], ""),
    ("cloudgoat", "CloudGoat", "cloud-lab", S, "MIT", [LAB_ONLY], "training lab"),
    ("cloudfox", "CloudFox", "cloud-recon", K, "MIT", [SEPARATE_AUTH], ""),
    ("prowler", "Prowler", "cloud-audit", C, "Apache-2.0", [], "machine-readable output"),
    ("cartography", "Cartography", "cloud-graph", S, "Apache-2.0", [], "asset graph ingestion into the evidence graph"),
    ("kube-hunter", "kube-hunter / kube-bench", "k8s-audit", C, "Apache-2.0", [], ""),
    ("trivy", "Trivy", "container-scan", C, "Apache-2.0", [], ""),
    ("grype-syft", "Grype + Syft", "sbom-scan", C, "Apache-2.0", [], "upstream admission pipeline component"),
    ("peirates-kubeletctl", "Peirates / kubeletctl", "k8s-exploitation", K, "Apache-2.0/MIT", [SEPARATE_AUTH], "in-cluster: per-action approval"),
    ("deepce-cdk", "Deepce / CDK", "container-escape", K, "MIT", [SEPARATE_AUTH, LAB_ONLY], "escape testing: lab + authorized only"),
    ("docker-api-abuse", "Docker API abuse technique", "technique", S, "n/a", [SEPARATE_AUTH, LAB_ONLY], "documented technique; never against host daemon"),
    ("imds-abuse", "IMDS abuse technique (169.254.169.254)", "technique", S, "n/a", [SEPARATE_AUTH], "SSRF-to-credential chains per RoE"),
    ("checkov-tfsec-terrascan", "checkov / tfsec / terrascan", "iac-scan", C, "Apache-2.0/MIT", [], ""),
    ("codeql", "CodeQL", "sast", C, "custom/MIT", [], "source-available targets"),
    ("retirejs-npm-audit", "Retire.js / npm audit", "js-dependency-rot", C, "MIT", [], ""),
    ("nvd-cvemap", "NVD API + cvemap", "vuln-enrichment", S, "web/api", [], ""),
    ("attck-stix", "ATT&CK STIX bundle", "knowledge-base", S, "Apache-2.0", [], "technique tagging"),
]

CREDENTIAL_ATTACKS = [
    ("pack-mangling", "PACK / hashcat rule sets", "wordlist-gen", C, "GPL-3.0", [], ""),
    ("cewl-mentalist-cupp", "CeWL / Mentalist / CUPP", "wordlist-gen", C, "GPL-3.0/MIT", [], ""),
    ("haiti", "haiti", "hash-id", C, "MIT", [], "agent routing aid"),
    ("cracking-pipeline", "Responder→cracking handoff pipeline", "pipeline", K, "n/a", [SEPARATE_AUTH], "engagement evidence only"),
    ("sharpweb", "SharpWeb", "local-secret-harvest", K, "GPL-3.0", [SEPARATE_AUTH], "in-scope hosts only"),
    ("dpapi", "DPAPI extraction", "credential-access", K, "n/a", [SEPARATE_AUTH], "engagement evidence only"),
]

WIRELESS_MOBILE_HARDWARE = [
    ("kismet", "Kismet", "wireless-recon", K, "GPL-3.0", [SEPARATE_AUTH], "wireless scope required"),
    ("hcxdumptool", "hcxdumptool / hcxtools", "wireless-capture", K, "MIT", [SEPARATE_AUTH], "wireless scope required"),
    ("wifi-coconut", "WiFi Coconut", "wireless-capture", K, "commercial", [SEPARATE_AUTH, LICENSE_REQUIRED], ""),
    ("bettercap", "bettercap", "on-path", K, "GPL-3.0", [SEPARATE_AUTH], "Wi-Fi/BLE: separate RoE addendum"),
    ("mobsf", "MobSF", "mobile-analysis", C, "GPL-3.0", [], "API-driven"),
    ("frida-objection", "Frida / objection", "mobile-instrumentation", K, "MIT", [SEPARATE_AUTH], "owned/authorized devices only"),
    ("apktool-jadx", "apktool / jadx", "mobile-re", C, "Apache-2.0", [], ""),
    ("drozer", "Drozer", "mobile-exploitation", K, "BSD-3-Clause", [SEPARATE_AUTH], "owned/authorized devices only"),
    ("adb-ideviceinstaller", "adb / ideviceinstaller", "device-control", C, "Apache-2.0/LGPL", [SEPARATE_AUTH], "owned devices only"),
    ("hackrf-rtlsdr-proxmark", "HackRF / RTL-SDR / Proxmark3", "rf-rfid-hardware", K, "mixed", [SEPARATE_AUTH, LAB_ONLY], "hardware-in-loop; legal compliance (radio law) mandatory"),
    ("saleae", "Saleae / logic analyzers", "signal-capture", K, "commercial", [LAB_ONLY], ""),
]

REPORTING_PLATFORMS = [
    ("dradis", "Dradis / PentestCollab / SysReptor", "reporting", S, "commercial/AGPL", [LICENSE_REQUIRED], "AGPL/commercial review"),
    ("faraday", "Faraday", "reporting", S, "AGPL-3.0/commercial", [LICENSE_REQUIRED], ""),
    ("osmedeus-rengine", "Osmedeus / reNgine", "orchestration", C, "MIT/GPL-3.0", [], "workflow engines; dependency admission cascades"),
]

KNOWLEDGE_CORPORA = [
    ("hacktricks", "HackTricks (local clone)", "knowledge-base", S, "CC-BY-4.0", [], "primary agent knowledge corpus"),
    ("payloadsallthethings", "PayloadsAllTheThings", "knowledge-base", S, "MIT", [], ""),
    ("seclists", "SecLists wordlists", "knowledge-base", S, "MIT", [], "mounted read-only"),
    ("cyberchef", "CyberChef", "encode-decode", S, "Apache-2.0", [], ""),
    ("wadcoms", "WADComs", "knowledge-base", S, "MIT", [], ""),
    ("github-dorking", "GitHub dorking", "osint-dorking", C, "web", [], ""),
]

REGRESSION_LABS = [
    ("dvwa-juiceshop-webgoat", "DVWA / Juice Shop / WebGoat", "web-lab", S, "mixed", [LAB_ONLY], "deterministic CI targets"),
    ("goad", "GOAD (Game of Active Directory)", "ad-lab", S, "MIT", [LAB_ONLY], "best agent AD training ground"),
    ("dreadgoad-adlab", "DreadGOAD / AD-Lab", "ad-lab", S, "mixed", [LAB_ONLY], ""),
    ("kubernetes-goat", "Kubernetes Goat", "k8s-lab", S, "MIT", [LAB_ONLY], ""),
    ("htb-thm-vulnhub", "HackTheBox / TryHackMe / VulnHub", "regression-labs", S, "commercial/ToS", [], "evaluation baselines; ToS review"),
]

OPS_STACK = [
    ("docker-compose", "Docker/Podman + compose", "isolation", S, "Apache-2.0", [], "per-engagement isolation"),
    ("terraform", "Terraform", "lab-provisioning", S, "BUSL-1.2/MPL-2.0", [], "disposable target environments"),
    ("ansible", "Ansible", "lab-provisioning", S, "GPL-3.0", [], ""),
    ("traefik-caddy", "Traefik / Caddy", "reverse-proxy", S, "MIT/Apache-2.0", [], "tool API fronting"),
    ("grafana-prometheus-loki", "Grafana / Prometheus / Loki", "telemetry", S, "AGPL-3.0/Apache-2.0", [LICENSE_REQUIRED], "AGPL gate; run telemetry"),
    ("langfuse-langsmith-phoenix", "Langfuse / LangSmith / Phoenix", "llm-telemetry", S, "mixed", [], "LLM trace + eval"),
    ("opa-rego", "OPA / Rego", "policy", S, "Apache-2.0", [], "scope/guardrail policy enforcement (complements Cedar)"),
    ("vault-sops-age", "Vault / SOPS / age", "secrets", S, "MPL-2.0/Apache-2.0/MIT", [], "secrets at rest"),
]

AGENT_STACK_REFERENCES = [
    ("litellm", "LiteLLM", "model-routing", S, "MIT", [], "routing + fallback"),
    ("vllm-ollama", "vLLM / Ollama", "local-inference", S, "Apache-2.0", [], "air-gapped self-hosted inference"),
    ("temporal", "Temporal", "durable-workflow", S, "MIT", [], "long-running engagements; v3.0 defers adoption until justified"),
    ("openhands-swe-agent", "OpenHands / SWE-agent", "coding-loop-reference", S, "MIT", [], "patterns to copy, not to import blindly"),
    ("crewai-autogen-agno", "CrewAI / AutoGen(archived) / Agno", "agent-reference", S, "mixed", [], "role-team patterns; AutoGen historical only"),
    ("xbow", "XBOW (reference architecture)", "reference", S, "closed", [], "study writeups; not integrable — closed source"),
    ("pentestgpt-benchmark", "PentestGPT benchmark suite", "reference", S, "MIT", [], "evaluation baseline"),
    ("big-sleep", "Big Sleep (reference)", "reference", S, "closed", [], "autonomous vuln-discovery patterns (FFmpeg/ImageMagick findings)"),
    ("aicxx-crs-atlantis", "AIxCC finalist CRS systems (incl. Atlantis)", "reference", S, "mixed", [], "crash-triage + patch-loop patterns; all seven released"),
    ("ai-ops", "AI-OPS", "reference", S, "open", [], "local-LLM copilot with human gates"),
    ("general-analysis", "General Analysis", "reference", S, "closed", [], "agent/RAG/MCP/CI-security patterns"),
    ("nodezero-pentera-hadrian-cobalt", "NodeZero / Pentera / Hadrian / Cobalt Core", "reference", S, "closed/commercial", [], "mine reporting formats + scope models — commercial, reference only"),
]

WAVE2_GROUPS = [C2_FRAMEWORKS_W2, POST_EXPLOIT_AD, TUNNELING_INFRA, SOCIAL_ENGINEERING,
                WEB_API_TOOLS, CLOUD_K8S, CREDENTIAL_ATTACKS, WIRELESS_MOBILE_HARDWARE,
                REPORTING_PLATFORMS, KNOWLEDGE_CORPORA, REGRESSION_LABS, OPS_STACK,
                AGENT_STACK_REFERENCES]



def all_entries():
    groups = [CONTAINER_RECON, OSINT_TOOLS, INTAKE_TOOLS, SECRET_SCANNING, DEFENSE_TELEMETRY,
              KVM_HOSTILE, C2_COMMERCIAL, KNOWLEDGE_BASES, CTI_SOURCES, PLATFORMS,
              AI_RED_TEAM, G9_FAMILY, INTEL_SOURCES_WEB, UNVERIFIED_SOURCES,
              *WAVE2_GROUPS]
    out = []
    for group in groups:
        out.extend(group)
    return out


def by_id(rid: str):
    for e in all_entries():
        if e[0] == rid:
            return e
    return None
