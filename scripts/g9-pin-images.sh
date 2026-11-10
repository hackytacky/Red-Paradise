#!/usr/bin/env bash
# Admission step: pull remote images and BUILD local images, pinning
# every one by digest. :latest is never used in a real engagement —
# this script records the digest the operator admits, so the hardened
# command builds run against exactly what was reviewed.
#
# Local images (deploy/images/<tool>/Dockerfile) are built with the
# source vendored by the operator (see each Dockerfile's header note);
# the build is offline after vendoring.
set -euo pipefail
cd "$(dirname "$0")/.."

# Remote names verified live on the G9 host (2026-06): the eight that
# failed to pull were moved to LOCAL_IMAGES below and are built from
# upstream source instead.
REMOTE_IMAGES=(
  "projectdiscovery/nuclei"
  "projectdiscovery/subfinder"
  "drwetter/testssl.sh"
  "zricethezav/gitleaks"
  "anchore/grype"
  "aquasec/trivy"
  "ghcr.io/zaproxy/zaproxy"
  "hypnza/sublist3r"
  "trufflesecurity/trufflehog"
  "sherlock/sherlock"
  "soxoj/maigret"
  "elceef/dnstwist"
  "epi052/feroxbuster"
)

LOCAL_IMAGES=(
  "httpx"
  "ffuf"
  "masscan"
  "theharvester"
  "dig"
  "amass"
  "gowitness"
  "gobuster"
  "whatweb"
  "windapsearch"
  "dnsrecon"
  "exiftool"
  "hachoir"
  "holehe"
  "ghunt"
  "garak"
  "promptfoo"
  "pyrit"
  "azurehound"
  "caido"
)

mkdir -p deploy/pinned
: > deploy/pinned/images.digests

echo "== pulling + pinning remote images =="
for img in "${REMOTE_IMAGES[@]}"; do
  digest="$(docker pull "${img}:latest" 2>/dev/null | grep -oP 'Digest: \Ksha256:[a-f0-9]+' | head -1 || true)"
  if [ -n "$digest" ]; then
    echo "${img}@${digest}" | tee -a deploy/pinned/images.digests
  else
    echo "WARN: could not pin ${img} — verify the image name at admission" >&2
  fi
done

echo "== building + pinning local images (deploy/images/*) =="
for tool in "${LOCAL_IMAGES[@]}"; do
  dir="deploy/images/${tool}"
  if [ ! -f "${dir}/Dockerfile" ]; then
    echo "WARN: no Dockerfile for ${tool} — skipped" >&2
    continue
  fi
  if ! docker build -q -t "g9/${tool}:latest" "$dir" >/dev/null 2>"deploy/pinned/${tool}.build.log"; then
    echo "WARN: build failed for g9/${tool} — see deploy/pinned/${tool}.build.log (vendor the source first: see the Dockerfile header)" >&2
    continue
  fi
  digest="$(docker image inspect "g9/${tool}:latest" --format '{{index .RepoDigests 0}}' 2>/dev/null | grep -oP 'sha256:[a-f0-9]+' || docker image inspect "g9/${tool}:latest" --format '{{.Id}}')"
  echo "g9/${tool}@${digest}" | tee -a deploy/pinned/images.digests
done

echo
echo "Digests recorded in deploy/pinned/images.digests — operator reviews and admits these."
