#!/usr/bin/env bash
# G9 full test run — HOST mode (real Docker, real tool containers).
#
# Prereqs (admission, one time):
#   ./scripts/g9-pin-images.sh   # pull + digest-pin every tool image
#
# Usage:
#   ./scripts/g9-run-host.sh            # lab-target run (safe)
#   G9_TARGET=lab-target ./scripts/g9-run-host.sh
#
# The run goes through the same gated chain: typed MCP contract →
# policy (deny-by-default) → budget/scope → container adapter →
# hardened docker run (cap-drop ALL, no-new-privileges, read-only
# rootfs) → evidence collector → candidates only → verification.
set -euo pipefail
cd "$(dirname "$0")/.."

G9_TARGET="${G9_TARGET:-lab-target}"
COMPOSE="docker compose -f deploy/docker-compose.host.yml"

echo "== G9 host-mode full test run =="
echo "target: ${G9_TARGET} (compose-internal; never a public host)"

$COMPOSE up -d --build lab-target backend

echo "== waiting for the control plane =="
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8700/lab/arsenal >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "== full active mission =="
curl -s -X POST http://127.0.0.1:8700/lab/run | python3 -m json.tool

echo
echo "== tamper-evident audit trail =="
curl -s http://127.0.0.1:8700/audit | python3 -m json.tool | head -40

echo
echo "UI: http://127.0.0.1:5173  (Live Run view)"
echo "Honest boundary: lab-native adapters prove the pipeline; the"
echo "container adapters (nmap/nuclei/...) run on THIS host with real"
echo "tools once images are pinned at admission."
