# pyrit — legacy WPA/WPA2 audit tool, built from upstream at the admitted rev.
# NOTE: upstream is unmaintained (last release 2014) — admission review
# must accept the maintenance posture before qualification.
FROM python:3.12-slim
ARG PYRIT_REV=master
RUN --network=host apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev zlib1g-dev libpcap-dev git && \
    git clone --depth 1 --branch ${PYRIT_REV} https://github.com/JPaulMora/pyrit.git /opt/pyrit && \
    cd /opt/pyrit && python setup.py build && python setup.py install
ENTRYPOINT ["pyrit"]
