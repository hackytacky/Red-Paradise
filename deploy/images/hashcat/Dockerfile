# hashcat — distro package; the digest pin at admission records the
# exact build.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends hashcat && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["hashcat"]
