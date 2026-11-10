# Caido — freemium web proxy, built from the upstream release pinned
# by the operator at admission; the instance is authenticated on first
# run by the operator.
FROM debian:bookworm-slim
ARG CAIDO_VERSION=0.35.0
ARG CAIDO_ARCH=x86_64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    curl -fsSL -o /tmp/caido.tar.gz \
    https://github.com/caido/caido/releases/download/v${CAIDO_VERSION}/caido-v${CAIDO_VERSION}-${CAIDO_ARCH}-unknown-linux-gnu.tar.gz && \
    tar -xzf /tmp/caido.tar.gz -C /usr/local/bin && rm /tmp/caido.tar.gz
ENTRYPOINT ["caido"]
