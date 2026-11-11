# G9 control plane (FastAPI). Binds 0.0.0.0 INSIDE the container;
# the compose port mapping ("127.0.0.1:8700:8700") enforces the
# loopback-only exposure at the host — the correct layer.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
# --network=host: package fetches use the host's working resolver
# directly, sidestepping the daemon's embedded DNS (127.0.0.11),
# which fails on hosts running systemd-resolved/VPN resolvers.
RUN --network=host pip install --no-cache-dir --retries 10 --timeout 60 fastapi uvicorn pydantic
COPY g9_backend ./g9_backend
EXPOSE 8700
# host compose enforces 127.0.0.1-only exposure
CMD ["python", "-m", "uvicorn", "g9_backend.api:app", "--host", "0.0.0.0", "--port", "8700"]
