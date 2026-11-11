# certipy — pip-installed; the digest pin at admission records the
# exact build. No ENTRYPOINT: the adapter passes ["sh","-c",...] so
# credentials expand from env inside the container.
FROM python:3.12-slim
RUN pip install --no-cache-dir certipy-AD
WORKDIR /opt/assets
