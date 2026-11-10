# AzureHound — Go collector built from vendored upstream source, rev pinned.
# The operator clones https://github.com/BloodHoundAD/AzureHound.git at the
# admitted revision into this directory before building.
FROM golang:1.24-alpine AS build
COPY AzureHound /src
RUN cd /src && go build -o /azurehound .
FROM alpine:3.20
COPY --from=build /azurehound /usr/local/bin/azurehound
ENTRYPOINT ["azurehound"]
