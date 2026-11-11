# john (John the Ripper, jumbo) — distro package; the digest pin at
# admission records the exact build.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends john && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["john"]
