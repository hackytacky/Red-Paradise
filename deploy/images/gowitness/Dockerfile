# gowitness — built from upstream via codeload tarball (tag clones
# failed in-container); chromium ships in the runtime stage.
FROM golang:1.24-alpine AS build
RUN apk add --no-cache curl && \
    curl -fsSL https://codeload.github.com/sensepost/gowitness/tar.gz/refs/heads/main | tar xz -C /opt && \
    cd /opt/gowitness-main && go build -o /gowitness ./cmd/gowitness/
FROM alpine:3.20
RUN apk add --no-cache chromium nss freetype harfbuzz ttf-freefont
ENV GOWITNESS_CHROME_PATH=/usr/bin/chromium-browser
COPY --from=build /gowitness /usr/local/bin/gowitness
ENTRYPOINT ["gowitness"]
