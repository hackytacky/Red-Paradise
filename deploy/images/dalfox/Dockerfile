# dalfox (XSS scanner; the xsstrike-dalfox adapter's executable side) —
# official upstream binary release, pinned by the digest at admission.
FROM alpine:3.20
RUN apk add --no-cache curl && \
    curl -fsSL -o /usr/local/bin/dalfox \
      https://github.com/hahwul/dalfox/releases/latest/download/dalfox_linux_amd64 && \
    chmod +x /usr/local/bin/dalfox
ENTRYPOINT ["dalfox"]
