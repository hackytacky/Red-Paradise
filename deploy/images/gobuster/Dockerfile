# gobuster — built from upstream source at the admitted rev
FROM golang:1.24-alpine AS build
ARG GOBUSTER_REV=3.6.0
RUN apk add --no-cache git && \
    git clone --depth 1 --branch v${GOBUSTER_REV} https://github.com/OJ/gobuster.git /src && \
    cd /src && go build -o /gobuster ./cmd/gobuster/
FROM alpine:3.20
COPY --from=build /gobuster /usr/local/bin/gobuster
ENTRYPOINT ["gobuster"]
