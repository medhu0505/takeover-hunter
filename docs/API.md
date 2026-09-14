# API Reference

Base URL: `http://<host>:<port>`

**Authentication.** If `API_KEY` is configured, every `/api/*` request must
include it as `X-API-Key: <token>` or `Authorization: Bearer <token>`. Requests
without a valid key receive `401`. When `API_KEY` is empty the API is open
(intended for local/trusted-network use only).

**Rate limiting.** `/api/*` routes are limited per client IP
(`RATE_LIMIT_REQUESTS` per `RATE_LIMIT_WINDOW_SECONDS`); exceeding it returns
`429` with a `Retry-After` header.

**Streaming.** Enumerate/triage/scan/verify/JS/archive return
`text/event-stream` (Server-Sent Events). Each stream ends with an
`event: done` frame. Other routes return JSON.

---

## Meta

### `GET /healthz`
Liveness probe. `{"status": "ok", "version": "2.0.0"}`.

### `GET /api/tools`
Availability of optional recon binaries.
`{"subfinder": true, "assetfinder": false, ...}`

### `GET /api/providers`
Provider names in the fingerprint database.
`{"providers": ["AWS CloudFront", "Heroku", ...]}`

---

## Pipeline (SSE)

### `GET /api/enumerate?target=<domain>`
Enumerate subdomains for `target` using all available recon tools.

- `400` if `target` is not a valid domain.
- Stream: `log`, then `done` → `{"subdomains": [...], "count": N}`.

### `POST /api/triage`
Classify subdomains by DNS delegation.

```json
{ "subdomains": ["api.example.com", "cdn.example.com"] }
```
Stream: `progress`, `log`, then `done` →
`{"cname": [...], "dead": [...], "a": [...]}`. Each `cname` entry carries
`provider`, `takeover_possible`, `claimable`, `free_account`.

### `POST /api/scan`
Vulnerability-scan CNAME records.

```json
{
  "cname_records": [{"sub": "api.example.com", "cname": "x.herokuapp.com"}],
  "provider_filter": ["Heroku"],
  "claimable_only": false
}
```
Stream: `progress`, `vuln` (per finding), then `done` →
`{"count": N, "vulnerable": [...]}`.

### `POST /api/bulkurlscan`
Extract hostnames from a list of URLs and scan them.

```json
{ "urls": ["https://a.example.com/app.js", "b.example.com"], "provider_filter": [] }
```
Stream identical to `/api/scan`.

### `POST /api/verify`
Re-check findings (stable NXDOMAIN + live CNAME) to eliminate false positives.

```json
{ "vulnerable": [ { "sub": "...", "cname": "..." } ] }
```
Stream: `log`, `verified` (per item), then `done` → `{"verified": [...]}`.
Each result adds `verified`, `verify_nxdomain_1/2`, `cname_still_present`.

### `POST /api/jsrecon`
Crawl live subdomains and archives for JS files, scan them for secrets.

```json
{ "target": "example.com", "subdomains": ["app.example.com"] }
```
Stream: `log`, `secret` (per hit), then `done` →
`{"js_urls": [...], "js_count": N, "secrets": [...], "scanned": N}`.

### `POST /api/archive`
Mine gau/waybackurls for endpoints, parameters, and interesting paths.

```json
{ "target": "example.com" }
```
Stream: `log`, then `done` →
`{"total": N, "params": [...], "admin": [...], "js": [...], "interesting": [...]}`.

---

## Synchronous (JSON)

### `POST /api/quickscan`
Instant single-target assessment.

```json
{ "sub": "api.example.com", "cname": "x.herokuapp.com" }
```
Returns the finding object (`vulnerable`, `confidence`, `severity`,
`nxdomain`, `provider`, `cname_chain`, ...).

### `POST /api/dns`
Custom DNS lookup.

```json
{ "host": "example.com", "type": "CNAME" }
```
Allowed `type`: `A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, ANY, SRV`.
Returns `{"records": [...]}` or `{"records": [], "error": "NXDOMAIN"}`.

### `POST /api/report`
Render a Markdown vulnerability report from a finding.

```json
{ "finding": { ... }, "h1_user": "researcher", "platform": "HackerOne" }
```
Returns `{"report": "# Subdomain Takeover: ..."}`.

---

## Error model

| Status | Meaning |
| --- | --- |
| `400` | Invalid input (bad domain/host, unsupported DNS type, malformed body) |
| `401` | Missing or invalid API key (when `API_KEY` is set) |
| `429` | Rate limit exceeded |

Error bodies are JSON: `{"error": "<message>"}`.
