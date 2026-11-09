# Tool Adapter Approval List — the arsenal for operator admission

Every tool below is aligned with the SPECTRE architecture (Tier 1–3 selections
and the specialist-engine decisions). Admission follows the Upstream Admission
Service: pinned revision, license review, protocol surface, sandbox class,
recorded residual risks — then per-call gating through the full pipeline.

Recommended admission order = implementation order (highest value per
engineering hour first).

## Container class — restricted analysis (trusted code, untrusted data)

| # | Tool | Capability | License | Adapter status |
|---|---|---|---|---|
| 1 | **nmap** (scoped profile) | Network/service recon — TCP/UDP sweeps, version pinning | GPL-2.0 | ✅ implemented |
| 2 | **httpx** | Web probing — live hosts, tech fingerprint, status/title | MIT | ✅ implemented (this PR) |
| 3 | **ffuf** | Content discovery — directories, params, vhosts | MIT | ✅ implemented (this PR) |
| 4 | **nuclei** | Template-driven scanning — known-CVE triage (scanner hypotheses only; every hit hand-confirmed before it becomes a finding) | MIT | ✅ implemented (this PR) |
| 5 | subfinder | Passive subdomain enumeration | MIT | next batch |
| 6 | testssl.sh | TLS configuration audit | GPL-3.0 | next batch |
| 7 | Semgrep | Deterministic static analysis (supply-chain + source review) | LGPL-2.1 | next batch |
| 8 | Joern | Code-property-graph source analysis (vuln research) | Apache-2.0 | next batch |
| 9 | Syft + OSV-Scanner + Grype | SBOM generation + known-vuln screening (upstream admission pipeline itself) | Apache-2.0 / Apache-2.0 / Apache-2.0 | next batch |
| 10 | BloodHound CE (collector) | Identity-graph collection (analysis runs in the evidence graph) | Apache-2.0 | next batch |

## KVM class — hostile research (untrusted code: disposable guests only)

| # | Tool | Capability | License | Notes |
|---|---|---|---|---|
| 11 | **AFL++** | Coverage-guided fuzzing | AGPL-3.0 (license gate for commercial use — recorded residual risk) | fuzzing coordinator |
| 12 | **angr** | Symbolic execution, binary analysis | BSD-2-Clause | RE specialist backend |
| 13 | **Ghidra** (headless) | RE — decompile/xrefs via scoped API, never ambient shell | Apache-2.0 | TALOS backend |
| 14 | Metasploit-framework | Exploit execution — high-impact class: per-action operator approval always | BSD-3-Clause | red tier, loud phases only |
| 15 | CALDERA | ATT&CK adversary emulation | Apache-2.0 | **lab enclave only — never exposed to untrusted networks** (upstream warning) |

## AI Security Studio class

| # | Tool | Capability | License |
|---|---|---|---|
| 16 | PyRIT | Adaptive multi-turn AI red teaming | MIT |
| 17 | Promptfoo | Prompt/RAG/agent regression evaluation | MIT |
| 18 | Garak | Broad LLM vulnerability probing | Apache-2.0 |
| 19 | AgentDojo | Agent injection/tool-use benchmarking | MIT |

## Standing rules (unchanged)

- Admission is one recorded decision per tool; **per-call gating never changes**.
- Scanner output is hypothesis; only the Verification Authority confirms.
- Metasploit/CALDERA-class tools are high-impact: exact-action operator
  approval on every dispatch, loud phases only where the OPSEC plan declares
  them.
- AFL++ AGPL residual risk recorded at admission; commercial integration
  requires the license review.
