# Host Setup — Docker + KVM on the G9 Host (Ubuntu)

Everything runs ON your machine. Docker containers share your kernel
(restricted analysis); KVM VMs get their own kernel (hostile
research). Nothing is offloaded to third-party hardware — red-tier
doctrine: local execution only.

## One-shot

```bash
sudo ./scripts/g9-setup-host.sh
# log out and back in (docker group), then:
./scripts/g9-pin-images.sh   # admission: pull remote + build local + pin by digest
./scripts/g9-run-host.sh     # the full test run
```

## What the setup script does, step by step

**1. Docker Engine** (restricted-analysis worker class)
```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

**2. Non-root docker** (log out/in afterwards)
```bash
sudo groupadd -f docker && sudo usermod -aG docker $USER
```

**3. KVM + libvirt** (hostile-research outer boundary)
```bash
sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst cpu-checker
sudo systemctl enable --now libvirtd
```

**4. Verify hardware virtualization**
```bash
kvm-ok          # must say "KVM acceleration can be used" (enable VT-x/AMD-V in BIOS otherwise)
ls -l /dev/kvm
```

**5. Default VM network**
```bash
sudo virsh net-start default && sudo virsh net-autostart default
```

## Do you need KVM/VMs at all?

- **For the full test run** (lab target + real tools): **no — Docker
  alone is the prescribed boundary for restricted analysis.**
- **For hostile research** (untrusted code, malware config
  extraction, live exploit samples): **yes, mandatory** — a container
  is not a security boundary against hostile code (kernel
  escape surface); a disposable VM snapshot is. Until the KVM worker
  lands (Stage 02), `KvmWorkerManager` fails honestly, and hostile
  work simply does not run.

## Image admission (`g9-pin-images.sh`)

- **Remote images** (21): pulled and digest-pinned — nuclei, subfinder,
  httpx, ffuf, masscan, testssl, theHarvester, gitleaks, dig, grype,
  trivy, zaproxy, sublist3r (`hypnza/sublist3r` — verified), amass,
  gowitness, trufflehog, sherlock, maigret, dnstwist, gobuster,
  feroxbuster
- **Local builds** (12): whatweb, windapsearch, dnsrecon, exiftool,
  hachoir, holehe, ghunt, garak, promptfoo, pyrit, azurehound, caido —
  Dockerfiles in `deploy/images/<tool>/`. Three of them need the
  operator to vendor source first (exiftool tarball, GHunt repo clone,
  pyrit repo clone, azurehound repo clone, caido release tarball) —
  each Dockerfile header says exactly what to place where. This is
  deliberate: the operator builds from reviewed source, never from a
  mystery image.

## API keys (host-side only)

Copy `deploy/env.example` → `~/.g9/env.sh`, `chmod 600`, fill in.
Source it before the backend runs; containers inherit values by env
NAME only. **Rotate any key ever shared in plaintext** (chat, email,
tickets). GHunt has no API key: vendor the repo at the admitted
revision into `deploy/images/ghunt/GHunt/` and export your Google
auth per the GHunt docs.
