# kerbrute — official upstream Go binary release; the digest pin at
# admission records the exact build.
FROM alpine:3.20
RUN apk add --no-cache curl && \
    curl -fsSL -o /usr/local/bin/kerbrute \
      https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 && \
    chmod +x /usr/local/bin/kerbrute
ENTRYPOINT ["kerbrute"]
