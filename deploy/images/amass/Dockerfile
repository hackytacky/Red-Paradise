# amass (passive profile) — built from upstream source at the admitted rev
FROM golang:1.24-alpine AS build
# clone default HEAD: upstream tags are inconsistent; the digest pin
# at admission records the exact source that built
RUN apk add --no-cache git && \
    git clone --depth 1 https://github.com/owasp-amass/amass.git /src && \
    cd /src && go build -o /amass ./cmd/amass/
FROM alpine:3.20
COPY --from=build /amass /usr/local/bin/amass
ENTRYPOINT ["amass"]
