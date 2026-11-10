# gowitness — built from upstream source at the admitted rev
FROM golang:1.24-alpine AS build
ARG GOWITNESS_REV=3.0.2
RUN apk add --no-cache git chromium && \
    git clone --depth 1 --branch v${GOWITNESS_REV} https://github.com/sensepost/gowitness.git /src && \
    cd /src && go build -o /gowitness ./cmd/gowitness/
FROM alpine:3.20
RUN apk add --no-cache chromium nss freetype freetype-dev harfbuzz ttf-freefont
ENV GOWITNESS_CHROME_PATH=/usr/bin/chromium-browser
COPY --from=build /gowitness /usr/local/bin/gowitness
ENTRYPOINT ["gowitness"]
