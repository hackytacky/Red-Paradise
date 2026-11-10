# pyrit — legacy WPA/WPA2 audit tool; locally built from vendored source.
# NOTE: upstream is unmaintained (last release 2014) — admission review
# must accept the maintenance posture before qualification.
# The operator clones https://github.com/JPaulMora/pyrit.git at the
# admitted revision into this directory before building.
FROM python:3.12-slim
COPY pyrit /opt/pyrit
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev zlib1g-dev libpcap-dev && \
    cd /opt/pyrit && python setup.py build && python setup.py install
ENTRYPOINT ["pyrit"]
