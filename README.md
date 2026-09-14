# Takeover Hunter

**Subdomain takeover detection and reporting engine.** Takeover Hunter
enumerates a target's attack surface, resolves and triages DNS delegation,
fingerprints dangling records against a database of claimable cloud providers,
double-verifies findings to suppress false positives, and generates
HackerOne/Bugcrowd-ready reports — all behind a streaming web API and terminal
UI.

Built with Flask and a thin orchestration layer over best-in-class recon
tooling (ProjectDiscovery, tomnomnom). Ships hardened: strict input
validation, optional API-key auth, per-IP rate limiting, and an SSRF guard.

```
enumerate ─► DNS triage ─► fingerprint ─► vuln scan ─► verify ─► report
```

---

## Highlights

- **26 provider signatures** — Heroku, GitHub Pages, S3, CloudFront, Azure,
  Fastly, Netlify, Vercel, Shopify, Webflow, Ghost, Zendesk, Surge, Statuspage
  and more, each with claimability and free-tier PoC metadata.
- **Streaming pipeline** — every stage streams progress to the browser over
  Server-Sent Events; long scans stay responsive.
- **Confidence scoring** — NXDOMAIN, body-fingerprint, and status-code signals
  produce High/Medium confidence with Critical/High severity classification.
- **Double verification** — findings are re-checked (stable NXDOMAIN + live
  CNAME) before they are called reportable.
- **Report generator** — one click turns a verified finding into a structured
  Markdown report with CVSS vector, reproduction steps, and impact.
- **Auxiliary recon** — JS secret scanning and archive (gau/waybackurls)
  endpoint mining for parameters, admin paths, and interesting files.
- **Hardened by default** — see [Security](#security).

## Architecture

The application is a small, well-factored Python package. Each concern lives in
its own module and is independently unit-tested.

| Module | Responsibility |
| --- | --- |
| `takeover_hunter/validation.py` | Strict hostname/domain validation (security boundary) |
| `takeover_hunter/config.py` | Environment-driven configuration |
| `takeover_hunter/fingerprints.py` | Provider signature database + matching |
| `takeover_hunter/netutils.py` | DNS resolution + SSRF-guarded HTTP probing |
| `takeover_hunter/recon.py` | Enumerate / triage / scan / verify / JS / archive workers |
| `takeover_hunter/reporting.py` | Markdown report rendering |
| `takeover_hunter/security.py` | Auth, rate limiting, response headers |
| `takeover_hunter/sse.py` | Server-Sent Events framing |
| `takeover_hunter/app.py` | Flask application factory + routes |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and data
flow, and [`docs/API.md`](docs/API.md) for the endpoint reference.

## Quick start

### Local (development)

```bash
git clone <repo> takeover-hunter && cd takeover-hunter
./run.sh            # creates venv, installs deps, serves http://127.0.0.1:5000
```

Or manually:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Docker

```bash
docker build -t takeover-hunter .
docker run -p 5000:5000 takeover-hunter
```

The image is multi-stage: Go recon binaries are compiled in a builder stage and
the runtime is a slim, non-root Python image served by gunicorn.

### Production

```bash
gunicorn --workers 4 --threads 8 --timeout 300 wsgi:app
```

## Configuration

All configuration is environment-driven; copy `.env.example` to `.env` and
adjust. Key settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `API_KEY` | *(empty)* | If set, all `/api/*` calls require this token |
| `RATE_LIMIT_REQUESTS` | `60` | Requests per window per client IP |
| `ALLOW_PRIVATE_TARGETS` | `0` | SSRF guard; keep `0` in production |
| `MAX_SUBDOMAINS` | `5000` | Per-scan workload cap |
| `DNS_RESOLVERS` | `8.8.8.8,1.1.1.1` | Upstream resolvers |

Full list in [`.env.example`](.env.example).

## Recon tooling

The enumeration and archive stages shell out to optional Go binaries when
present and degrade gracefully when they are not. Install what you need:

`subfinder`, `assetfinder`, `amass`, `dnsx`, `httpx`, `katana`, `gau`,
`waybackurls`. Invocation is always argument-list based (never a shell), and
tool output is re-validated before it is trusted.

## Testing

```bash
./run.sh test          # or:
pip install -r requirements-dev.txt
python -m pytest --cov=takeover_hunter
```

139 tests cover the validation boundary (including an explicit
command-injection safety proof), fingerprint matching, the assessment logic,
the streaming plumbing, auth, and rate limiting.

## Security

Takeover Hunter is a scanning tool and is hardened accordingly:

- **No shell.** External tools are invoked with argument lists; user input is
  strictly validated against the RFC 1035 character set before it can reach a
  subprocess, which structurally eliminates command injection.
- **SSRF guard.** Targets that resolve into private/reserved IP space are
  refused before any HTTP probe (`ALLOW_PRIVATE_TARGETS=0`).
- **Optional auth + rate limiting** on every API route.
- **Hardening headers** (CSP, `X-Content-Type-Options`, `X-Frame-Options`).

See [`SECURITY.md`](SECURITY.md) for the responsible-use policy and how to
report a vulnerability in the tool itself.

> **Authorized use only.** Run this against domains you own or that are covered
> by an explicit bug-bounty/pentest scope. Unauthorized scanning may be illegal.

## License

This is proprietary, source-available software offered for evaluation in
connection with a potential acquisition. See [`LICENSE`](LICENSE). Prior 1.x
releases were published under MIT; that history is disclosed in
[`docs/ACQUISITION_BRIEF.md`](docs/ACQUISITION_BRIEF.md).
