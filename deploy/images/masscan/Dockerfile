# masscan — built from upstream source via codeload tarball (git clone
# proved unreliable in-container). The digest pin at admission records
# the exact source that built.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpcap-dev curl && \
    curl -fsSL https://codeload.github.com/robertdavidgraham/masscan/tar.gz/refs/heads/master | tar xz -C /opt && \
    cd /opt/masscan-master && make -j4 && cp bin/masscan /masscan
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /masscan /usr/local/bin/masscan
ENTRYPOINT ["masscan"]
