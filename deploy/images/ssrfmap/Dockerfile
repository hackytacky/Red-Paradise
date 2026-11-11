# ssrfmap — locally built from upstream source (codeload tarball).
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl && \
    curl -fsSL https://codeload.github.com/swisskyrepo/SSRFmap/tar.gz/refs/heads/master | tar xz -C /opt && \
    mv /opt/SSRFmap-master /opt/ssrfmap && cd /opt/ssrfmap && \
    pip install --no-cache-dir -r requirements.txt
WORKDIR /opt/ssrfmap
ENTRYPOINT ["python", "ssrfmap.py"]
