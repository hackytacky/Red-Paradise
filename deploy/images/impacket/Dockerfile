# impacket suite (secretsdump, GetNPUsers, GetUserSPNs, wmiexec,
# psexec) — one image, pip-installed; the digest pin at admission
# records the exact build. No ENTRYPOINT: the adapters pass
# ["sh","-c","<tool> ..."] so credentials expand from env inside the
# container and never appear on the command line.
FROM python:3.12-slim
RUN pip install --no-cache-dir impacket
WORKDIR /opt/assets
