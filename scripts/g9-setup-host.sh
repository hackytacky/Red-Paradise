#!/usr/bin/env bash
# G9 host setup — Docker + KVM on Ubuntu (24.04/22.04).
# Idempotent: safe to re-run. Run with sudo, then log out/in for the
# docker group to take effect.
#
# Doctrine: Docker = restricted-analysis worker class; KVM = the
# hostile-research outer boundary. Both run ON the G9 host — nothing
# is offloaded to third-party hardware.
set -euo pipefail

echo "== [1/5] Docker Engine =="
apt-get update
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

echo "== [2/5] docker group (log out/in after this script) =="
groupadd -f docker
usermod -aG docker "${SUDO_USER:-$USER}"

echo "== [3/5] KVM + libvirt =="
# qemu-kvm is a real package on 22.04/24.04 but a virtual package on
# 26.04+ — fall back to qemu-system-x86 when apt has no candidate.
if apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst cpu-checker; then
  :
else
  echo "qemu-kvm unavailable (virtual package) — installing qemu-system-x86 instead"
  apt-get install -y qemu-system-x86 libvirt-daemon-system libvirt-clients bridge-utils virtinst cpu-checker
fi
systemctl enable --now libvirtd

echo "== [4/5] KVM hardware check =="
if kvm-ok 2>/dev/null | grep -q "KVM acceleration can be used"; then
  echo "OK: KVM acceleration available"
else
  echo "WARN: KVM not available — enable VT-x/AMD-V in BIOS (Docker-only operation still works; hostile-research stages stay blocked, which is correct doctrine)"
fi
ls -l /dev/kvm 2>/dev/null || true

echo "== [5/5] default network for VMs =="
virsh net-start default 2>/dev/null || true
virsh net-autostart default 2>/dev/null || true

echo
echo "Done. Next:"
echo "  1. log out and back in (docker group)"
echo "  2. ./scripts/g9-pin-images.sh        # admission: pull + build + pin every image"
echo "  3. ./scripts/g9-run-host.sh          # the full test run"
