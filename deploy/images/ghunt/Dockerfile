# GHunt — locally built from the upstream repo, rev pinned at admission.
# Operator Google auth is injected at RUNTIME via the GHUNT_COOKIES
# environment variable (env-NAME-only in the command line, never a value).
# The operator clones https://github.com/mxrch/GHunt.git at the admitted
# revision into this directory before building (vendor the source; the
# image build is offline after that).
FROM python:3.12-slim
COPY GHunt /opt/ghunt
RUN cd /opt/ghunt && pip install --no-cache-dir -r requirements.txt
WORKDIR /opt/ghunt
ENTRYPOINT ["python", "ghunt.py"]
