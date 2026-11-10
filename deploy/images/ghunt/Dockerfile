# GHunt — built from the upstream repo at the admitted revision.
# Operator Google auth is injected at RUNTIME via the GHUNT_COOKIES
# environment variable (env-NAME-only in the command line, never a value).
FROM python:3.12-slim
ARG GHUNT_REV=master
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 --branch ${GHUNT_REV} https://github.com/mxrch/GHunt.git /opt/ghunt && \
    cd /opt/ghunt && pip install --no-cache-dir -r requirements.txt
WORKDIR /opt/ghunt
ENTRYPOINT ["python", "ghunt.py"]
