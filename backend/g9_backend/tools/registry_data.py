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


def all_entries():
    groups = [CONTAINER_RECON, OSINT_TOOLS, SECRET_SCANNING, DEFENSE_TELEMETRY,
              KVM_HOSTILE, C2_COMMERCIAL, KNOWLEDGE_BASES, CTI_SOURCES, PLATFORMS,
              AI_RED_TEAM, G9_FAMILY, INTEL_SOURCES_WEB, UNVERIFIED_SOURCES]
    out = []
    for group in groups:
        out.extend(group)
    return out


def by_id(rid: str):
    for e in all_entries():
        if e[0] == rid:
            return e
    return None
