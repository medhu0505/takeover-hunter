# syntax=docker/dockerfile:1
#
# Multi-stage build:
#   1. `tools`   compiles the optional Go recon binaries once.
#   2. `runtime` is a slim Python image that runs the app as a non-root user
#      and serves it with gunicorn.
#
# The Go tools are optional at runtime — the app degrades gracefully when a
# binary is absent (see /api/tools). Drop the `tools` stage entirely for a
# minimal image if you supply the recon binaries another way.

# ---------- Stage 1: Go recon tools ----------------------------------------
FROM golang:1.22-bookworm AS tools
ENV GOBIN=/out CGO_ENABLED=0
RUN mkdir -p /out && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest

# ---------- Stage 2: Python runtime ----------------------------------------
FROM python:3.13-slim AS runtime

# Prevent Python from writing .pyc files / buffering stdout.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

# Install Python dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the compiled recon binaries from the build stage.
COPY --from=tools /out/ /usr/local/bin/

# Copy the application source.
COPY takeover_hunter/ ./takeover_hunter/
COPY templates/ ./templates/
COPY wsgi.py app.py ./

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,os,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','5000')).status==200 else sys.exit(1)"

# Production server. Tune workers/threads via env if needed.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers ${WEB_CONCURRENCY:-4} --threads ${WEB_THREADS:-8} --timeout ${WEB_TIMEOUT:-300} wsgi:app"]
