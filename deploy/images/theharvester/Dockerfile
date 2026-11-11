# theHarvester — built from upstream source at the admitted rev
FROM python:3.12-slim
# clone default HEAD; the digest pin at admission records the exact source.
# requirements layout has changed across versions — try both known layouts.
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 https://github.com/laramies/theHarvester.git /opt/theharvester && \
    cd /opt/theharvester && \
    (pip install --no-cache-dir -r requirements/base.txt || pip install --no-cache-dir -r requirements.txt)
WORKDIR /opt/theharvester
ENTRYPOINT ["python", "theHarvester.py"]
