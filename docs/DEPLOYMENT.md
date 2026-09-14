# Deployment

Takeover Hunter is a standard WSGI application. Any platform that runs Python
web apps or Docker containers will host it.

## Production checklist

- [ ] Set a strong `API_KEY` (32+ random bytes) — the API is otherwise open.
- [ ] Keep `ALLOW_PRIVATE_TARGETS=0` (the SSRF guard).
- [ ] Serve behind HTTPS (platform TLS or a reverse proxy).
- [ ] Tune `RATE_LIMIT_REQUESTS` for your expected load.
- [ ] Run with gunicorn, not the Flask dev server.
- [ ] Provide the recon binaries you need on `PATH` (or use the Docker image).

## gunicorn

```bash
gunicorn --bind 0.0.0.0:$PORT \
         --workers ${WEB_CONCURRENCY:-4} \
         --threads ${WEB_THREADS:-8} \
         --timeout ${WEB_TIMEOUT:-300} \
         wsgi:app
```

Scans are I/O-bound and can run for minutes, hence the high `--timeout` and
threaded workers. `WEB_CONCURRENCY` should track available CPU/RAM.

## Docker

```bash
docker build -t takeover-hunter .
docker run -p 5000:5000 -e API_KEY=$(openssl rand -hex 32) takeover-hunter
```

The image:
- compiles the Go recon tools in a builder stage,
- runs the app as a non-root user (`appuser`, uid 10001),
- serves via gunicorn,
- exposes a `HEALTHCHECK` against `/healthz`.

## Railway / Heroku

The `Procfile` runs gunicorn against `$PORT`. Set config vars (`API_KEY`,
`RATE_LIMIT_*`, etc.) in the platform dashboard. Railway builds from the
`Dockerfile` automatically; the recon binaries come with the image.

## Health checks

Point your platform's health check at `GET /healthz`. It returns `200` with a
JSON body and does not require the API key.

## Scaling notes

- The rate limiter is **in-process**. Behind multiple gunicorn workers or
  replicas, each process keeps its own counters — limits are per-process. For
  strict global limits, front the service with an API gateway or add a shared
  store (Redis); the limiter is a single class (`security.RateLimiter`) and is
  straightforward to back with Redis.
- No database is required; the service is stateless between requests.

## Observability

The app logs via the standard `logging` module under the `takeover_hunter`
logger. Configure handlers/levels in your process manager or a small `logging`
config; set `DEBUG=1` only in development.
