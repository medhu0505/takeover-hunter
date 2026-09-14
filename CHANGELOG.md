# Changelog

All notable changes to Takeover Hunter are documented here. This project
follows [Semantic Versioning](https://semver.org/).

## [2.0.0] — 2026-09-14

A ground-up hardening and refactor for production/acquisition readiness.

### Security (breaking posture change)
- **Fixed unauthenticated command injection.** Recon tools are now invoked
  with argument lists (`shell=False`) and every request-supplied host is
  validated against the RFC 1035 character set before it can reach a
  subprocess. Tool output is re-validated and scoped to the target.
- **Added SSRF guard.** Targets resolving to private/loopback/link-local/
  reserved IP space (including cloud metadata) are refused before HTTP probing;
  gated by `ALLOW_PRIVATE_TARGETS` (default off).
- **Added optional API-key authentication** (`X-API-Key` / `Bearer`,
  constant-time comparison).
- **Added per-IP rate limiting** on all `/api/*` routes.
- **Added response hardening headers** (CSP, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`).
- **Added workload caps** (subdomains, bulk URLs, workers, response body size).

### Changed (architecture)
- Split the 856-line monolith into a tested `takeover_hunter` package
  (config, validation, fingerprints, netutils, recon, reporting, security,
  sse, app).
- Introduced an application factory (`create_app`) and a WSGI entrypoint
  (`wsgi.py`); production now runs under gunicorn.
- Unified the three duplicated vulnerability-assessment code paths into a
  single `ReconEngine.assess()`.
- Collapsed six near-identical SSE generators into one generic streamer.
- Environment-driven configuration via an immutable `Config` dataclass.

### Added (features & ops)
- Expanded the fingerprint database from 20 to 26 providers (Surge, Statuspage,
  Unbounce, Helpscout, Cargo, Readme, plus corrected Azure/Tumblr signatures).
- `GET /healthz` liveness endpoint and `GET /api/providers`.
- Self-maintaining UI provider filter (pulls from `/api/providers`).
- Multi-stage, non-root Docker image with a `HEALTHCHECK`.
- GitHub Actions CI (lint + tests on Python 3.10–3.13, Docker build).
- `pyproject.toml`, `.env.example`, `.dockerignore`.
- Documentation set: `README`, `docs/ARCHITECTURE`, `docs/API`,
  `docs/DEPLOYMENT`, and this changelog.

### Testing
- Test suite expanded from 14 to 139 tests, including an explicit
  command-injection safety proof and full coverage of the validation and
  security boundaries.

### Licensing
- Relicensed going forward from MIT to a proprietary evaluation license for
  sale as intellectual property. Prior 1.x MIT history is disclosed in
  `docs/ACQUISITION_BRIEF.md`.

## [1.x] — 2026 (historical, MIT)
- Original single-file Flask app: enumeration, triage, scan, verify, JS recon,
  archive mining, bulk URL scan, HackerOne report generation, terminal UI.
