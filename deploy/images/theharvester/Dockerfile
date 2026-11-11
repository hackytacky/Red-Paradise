# theHarvester — python:3.11 (its dependency pins predate 3.12);
# requirements layout has changed across versions — try both.
FROM python:3.11-slim
RUN --network=host apt-get update && apt-get install -y --no-install-recommends git curl && \
    curl -fsSL https://codeload.github.com/laramies/theHarvester/tar.gz/refs/heads/master | tar xz -C /opt && \
    mv /opt/theHarvester-master /opt/theharvester && cd /opt/theharvester && \
    (pip install --no-cache-dir -r requirements/base.txt || pip install --no-cache-dir -r requirements.txt)
WORKDIR /opt/theharvester
ENTRYPOINT ["python", "theHarvester.py"]
