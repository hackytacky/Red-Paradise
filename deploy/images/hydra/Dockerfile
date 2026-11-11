# hydra — distro package (thc-hydra); the digest pin at admission
# records the exact build.
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends hydra && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["hydra"]
