# AzureHound — Go collector built from upstream at the admitted rev
FROM golang:1.24-alpine AS build
ARG AZUREHOUND_REV=master
RUN apk add --no-cache git && \
    git clone --depth 1 --branch ${AZUREHOUND_REV} https://github.com/BloodHoundAD/AzureHound.git /src && \
    cd /src && go build -o /azurehound .
FROM alpine:3.20
COPY --from=build /azurehound /usr/local/bin/azurehound
ENTRYPOINT ["azurehound"]
