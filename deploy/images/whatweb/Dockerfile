# whatweb — locally built (no official upstream image).
# Unpinned gem: the digest pin at admission records the exact build.
FROM ruby:3.2-slim
RUN gem install whatweb --no-document
ENTRYPOINT ["whatweb"]
