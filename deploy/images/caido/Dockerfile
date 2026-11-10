# Caido — freemium web proxy. The operator downloads the pinned release
# tarball from the upstream releases page, verifies it, and places
# caido.tar.gz in this directory before building; the instance is
# authenticated on first run by the operator.
FROM debian:bookworm-slim
COPY caido.tar.gz /tmp/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    tar -xzf /tmp/caido.tar.gz -C /usr/local/bin && rm /tmp/caido.tar.gz
ENTRYPOINT ["caido"]
