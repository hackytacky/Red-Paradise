# ExifTool — locally built from the upstream source tarball, version pinned.
# The operator downloads Image-ExifTool-<ver>.tar.gz from exiftool.org,
# verifies the checksum, and places it in this directory before building:
#   curl -fsSL -o exiftool-src.tar.gz https://exiftool.org/Image-ExifTool-13.12.tar.gz
FROM alpine:3.20
COPY exiftool-src.tar.gz /tmp/
RUN apk add --no-cache perl make && \
    tar -xzf /tmp/exiftool-src.tar.gz -C /tmp && \
    cd /tmp/Image-ExifTool-* && perl Makefile.PL && make install && \
    rm -rf /tmp/Image-ExifTool-* /tmp/exiftool-src.tar.gz
ENTRYPOINT ["exiftool"]
