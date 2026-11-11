# garak — locally built, pinned at admission
FROM python:3.12-slim
RUN --network=host pip install --no-cache-dir garak==0.12.0
ENTRYPOINT ["garak"]
