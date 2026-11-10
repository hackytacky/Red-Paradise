# amass (passive profile) — built from upstream source at the admitted rev
FROM golang:1.24-alpine AS build
ARG AMASS_REV=v4.2.5
RUN apk add --no-cache git && \
    git clone --depth 1 --branch ${AMASS_REV} https://github.com/owasp-amass/amass.git /src && \
    cd /src && go build -o /amass ./cmd/amass/
FROM alpine:3.20
COPY --from=build /amass /usr/local/bin/amass
ENTRYPOINT ["amass"]
