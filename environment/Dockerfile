FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build-time package installation requires registry access during docker build.
# Runtime network access is disabled via network_mode = "no-network" in task.toml.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi==0.115.0 \
    pydantic==2.9.2 \
    uvicorn==0.30.6 \
    httpx==0.27.2 \
    pytest==8.3.3

RUN useradd -m -u 1000 -s /bin/bash agent && \
    mkdir -p /workspace /logs/verifier && \
    chown -R agent:agent /workspace

WORKDIR /workspace
COPY --chown=agent:agent workspace/ /workspace/

USER agent
RUN python3 /workspace/scripts/init_sandbox.py
