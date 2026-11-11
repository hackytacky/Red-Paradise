# ffuf — built from upstream source at the admitted rev
FROM golang:1.24-alpine AS build
ARG FFUF_REV=v2.1.0
RUN apk add --no-cache git && \
    git clone --depth 1 --branch ${FFUF_REV} https://github.com/ffuf/ffuf.git /src && \
    cd /src && go build -o /ffuf .
FROM alpine:3.20
COPY --from=build /ffuf /usr/local/bin/ffuf
ENTRYPOINT ["ffuf"]
