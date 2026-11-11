# commix — locally built from upstream source (codeload tarball).
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl && \
    curl -fsSL https://codeload.github.com/commixproject/commix/tar.gz/refs/heads/master | tar xz -C /opt && \
    mv /opt/commix-master /opt/commix && cd /opt/commix && \
    pip install --no-cache-dir -r requirements.txt
WORKDIR /opt/commix
ENTRYPOINT ["python", "commix.py"]
