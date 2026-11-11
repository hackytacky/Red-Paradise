# GHunt — python:3.11 (its dependency pins predate 3.12).
# Operator Google auth is injected at RUNTIME via the GHUNT_COOKIES
# environment variable (env-NAME-only in the command line, never a value).
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl && \
    curl -fsSL https://codeload.github.com/mxrch/GHunt/tar.gz/refs/heads/main | tar xz -C /opt && \
    mv /opt/GHunt-main /opt/ghunt && cd /opt/ghunt && pip install --no-cache-dir -r requirements.txt
WORKDIR /opt/ghunt
ENTRYPOINT ["python", "ghunt.py"]
