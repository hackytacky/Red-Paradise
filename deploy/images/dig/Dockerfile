# dig (scoped) — dnsutils from Debian; no upstream container exists
FROM debian:bookworm-slim
RUN --network=host apt-get update && apt-get install -y --no-install-recommends dnsutils && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["dig"]
