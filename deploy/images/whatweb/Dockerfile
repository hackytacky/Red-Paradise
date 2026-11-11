# whatweb — locally built (no official upstream image); ruby 3.4 for
# current gem requirements. Digest pin records the exact build.
FROM ruby:3.4-slim
RUN --network=host gem install whatweb --no-document
ENTRYPOINT ["whatweb"]
