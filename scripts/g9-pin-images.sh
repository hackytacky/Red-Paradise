#!/usr/bin/env bash
# Admission step: pull every tool image and PIN it by digest.
# :latest is never used in a real engagement — this script records
# the digest the operator admits, so the hardened command builds run
# against exactly what was reviewed.
#
# NOTE: the list is generated from the adapter image constants. Some
# names are placeholders pending admission — a pull failure prints
# WARN and skips; the operator replaces those with the vetted image
# (or builds it locally) before qualifying the tool.
set -euo pipefail

IMAGES=(
  "aboul3la/sublist3r"
  "anchore/grype"
  "anchore/syft"
  "aquasec/trivy"
  "azurehound"
  "bitnami/openldap"
  "bloodhound/bloodhound"
  "caido/caido"
  "cazzzer/amass"
  "dnsrecon"
  "drwetter/testssl.sh"
  "elceef/dnstwist"
  "epi052/feroxbuster"
  "exiftool/exiftool"
  "ffuf/ffuf"
  "garak/garak"
  "ghcr.io/zaproxy/zaproxy"
  "gobuster/gobuster"
  "hachoir/hachoir"
  "hakluke/hakrawler"
  "holehe/holehe"
  "lepidge/gowitness"
  "mnbf9r3cr01/masscan"
  "mxrch/ghunt"
  "projectdiscovery/nuclei"
  "projectdiscovery/subfinder"
  "promptfoo/promptfoo"
  "pyrit/pyrit"
  "secureideas/httpx"
  "sharphound"
  "sherlock/sherlock"
  "soxoj/maigret"
  "trufflesecurity/trufflehog"
  "ubuntu/dig"
  "vanhausertheharvester/theharvester"
  "whatweb"
  "windapsearch"
  "zricethezav/gitleaks"
)

mkdir -p deploy/pinned
: > deploy/pinned/images.digests
for img in "${IMAGES[@]}"; do
  digest="$(docker pull "${img}:latest" 2>/dev/null | grep -oP 'Digest: \Ksha256:[a-f0-9]+' | head -1 || true)"
  if [ -n "$digest" ]; then
    echo "${img}@${digest}" | tee -a deploy/pinned/images.digests
  else
    echo "WARN: could not pin ${img} — verify the image name at admission (or build locally: docker build -t ${img} .)" >&2
  fi
done
echo "Digests recorded in deploy/pinned/images.digests — operator reviews and admits these."
