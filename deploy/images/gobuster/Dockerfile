# gobuster — installed via the Go module proxy
FROM golang:1.24-alpine AS build
RUN GOBIN=/out go install github.com/OJ/gobuster/v3@latest
FROM alpine:3.20
COPY --from=build /out/gobuster /usr/local/bin/gobuster
ENTRYPOINT ["gobuster"]
