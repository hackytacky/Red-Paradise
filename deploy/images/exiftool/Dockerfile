# ExifTool — from the Alpine community package (maintained upstream).
# The digest pin at admission records the exact package version built.
FROM alpine:3.20
RUN --network=host apk add --no-cache exiftool
ENTRYPOINT ["exiftool"]
