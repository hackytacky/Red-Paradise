# dnsrecon — locally built (no official upstream image).
# Unpinned pip: the digest pin at admission records the exact build.
FROM python:3.12-slim
RUN pip install --no-cache-dir dnsrecon
ENTRYPOINT ["dnsrecon"]
