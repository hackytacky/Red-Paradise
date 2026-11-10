# theHarvester — built from upstream source at the admitted rev
FROM python:3.12-slim
ARG THEHARVESTER_REV=master
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 --branch ${THEHARVESTER_REV} https://github.com/laramies/theHarvester.git /opt/theharvester && \
    cd /opt/theharvester && pip install --no-cache-dir -r requirements/base.txt
WORKDIR /opt/theharvester
ENTRYPOINT ["python", "theHarvester.py"]
