# httpx (projectdiscovery) — built from upstream source at the admitted rev
FROM golang:1.24-alpine AS build
ARG HTTPX_REV=v1.7.1
RUN apk add --no-cache git && \
    git clone --depth 1 --branch ${HTTPX_REV} https://github.com/projectdiscovery/httpx.git /src && \
    cd /src && go build -o /httpx ./cmd/httpx/
FROM alpine:3.20
COPY --from=build /httpx /usr/local/bin/httpx
ENTRYPOINT ["httpx"]
