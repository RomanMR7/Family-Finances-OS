# Family Finances OS - Production Dockerfile
# Multi-stage minimal footprint, non-root user, offline-first.

FROM python:3.12-slim AS runtime

# Install curl for reliable healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and launcher
COPY family_finances_os/ /app/family_finances_os/
COPY run_app.py /app/

# Create persistent storage directory with proper ownership
RUN mkdir -p /app/family_finances_os/data && \
    chown -R appuser:appgroup /app

USER appuser

# Expose HTTP Web/API/PWA port and UDP P2P sync beacon port
EXPOSE 8000/tcp
EXPOSE 41234/udp

# Healthcheck monitoring
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/status || exit 1

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FFOS_HOST=0.0.0.0
ENV FFOS_PORT=8000
ENV FFOS_NO_BROWSER=1

CMD ["python", "run_app.py", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]
