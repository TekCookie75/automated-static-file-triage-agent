FROM python:3.11-slim

# binary2strings (flare-floss dependency) requires a C++ compiler to build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ \
    && rm -rf /var/lib/apt/lists/*

# Install analysis dependencies.
# flare-floss runs natively on both amd64 and arm64.
RUN pip install --no-cache-dir pefile requests flare-floss

WORKDIR /app
COPY scripts/    /app/
COPY references/ /app/references/

# /samples — bind-mounted read-only by the caller (sample lives here)
# /report  — bind-mounted writable by the caller (all output written here)
ENTRYPOINT ["python", "/app/entrypoint.py"]
