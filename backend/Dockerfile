# G9 control plane (FastAPI) — loopback-only on the host.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir fastapi uvicorn pydantic
COPY g9_backend ./g9_backend
EXPOSE 8700
CMD ["python", "-m", "uvicorn", "g9_backend.api:app", "--host", "127.0.0.1", "--port", "8700"]
