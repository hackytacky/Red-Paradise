# Lab target container — the deliberately flawed service for the
# host-mode full test run. Same weakness set as the in-process
# LabTarget (target.py).
FROM python:3.12-slim
WORKDIR /app
COPY server.py .
EXPOSE 8080
CMD ["python", "server.py"]
