# amass (passive profile) — installed via the Go module proxy
# (go build in-container failed on dependency resolution)
FROM golang:1.24-alpine AS build
RUN --network=host GOBIN=/out go install github.com/owasp-amass/amass/v4@latest
FROM alpine:3.20
COPY --from=build /out/amass /usr/local/bin/amass
ENTRYPOINT ["amass"]
