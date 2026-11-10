#!/usr/bin/env bash
# Admission step: pull every tool image and PIN it by digest.
# :latest is never used in a real engagement — this script records
# the digest the operator admits, so the hardened command builds run
# against exactly what was reviewed.
set -euo pipefail

IMAGES=(
  "projectdiscovery/nuclei"
  "projectdiscovery/subfinder"
  "secureideas/httpx"
  "ffuf/ffuf"
  "mnbf9r3cr01/masscan"
  "drwetter/testssl.sh"
  "vanhausertheharvester/theharvester"
  "zricethezav/gitleaks"
  "ubuntu/dig"
)

mkdir -p deploy/pinned
: > deploy/pinned/images.digests
for img in "${IMAGES[@]}"; do
  digest="$(docker pull "${img}:latest" 2>/dev/null | grep -oP 'Digest: \Ksha256:[a-f0-9]+' | head -1 || true)"
  if [ -n "$digest" ]; then
    echo "${img}@${digest}" | tee -a deploy/pinned/images.digests
  else
    echo "WARN: could not pin ${img} — is Docker running?" >&2
  fi
done
echo "Digests recorded in deploy/pinned/images.digests — operator reviews and admits these."
