# masscan — built from upstream source at the admitted rev.
# The adapter enforces the rate ceiling from the resource budget; this
# build is the scanner itself (cap-drop ALL at runtime regardless).
FROM debian:bookworm-slim AS build
ARG MASSCAN_REV=1.3.2
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpcap-dev git && \
    git clone --depth 1 --branch ${MASSCAN_REV} https://github.com/robertdavidgraham/masscan.git /src && \
    cd /src && make -j4 && cp bin/masscan /masscan
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /masscan /usr/local/bin/masscan
ENTRYPOINT ["masscan"]
