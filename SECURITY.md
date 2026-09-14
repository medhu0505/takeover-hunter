# Security & Responsible Use

Takeover Hunter performs active DNS resolution and HTTP probing against the
targets you point it at. That makes it a scanning tool, and scanning tools
carry legal exposure if pointed at the wrong thing.

## Authorized use only

Only run this against domains you own, or domains covered by a bug bounty /
pentest engagement with explicit written scope (a HackerOne or Bugcrowd program
page, a signed pentest agreement, etc.). Running active recon or takeover
verification against a domain you have no authorization for can violate the
Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent
laws elsewhere, regardless of intent.

The `X-Bug-Bounty` header the tool sends during HTTP probing is a courtesy
identifier for programs that request it — it is not a substitute for actually
having scope authorization.

## What this tool does not do

It does not exploit anything. It identifies dangling CNAMEs and fingerprints
the provider they point at; claiming the resource to prove impact is a manual
step the operator takes deliberately, on infrastructure they are authorized to
interact with.

## Hardening (how the tool protects itself)

Takeover Hunter is built to be operated as a hosted service without becoming an
attack surface:

- **Command-injection safe.** External recon tools are invoked with argument
  lists (`shell=False`). Every request-supplied host is validated against the
  RFC 1035 character set before it can reach a subprocess, so no shell
  metacharacter can be introduced. Tool output is re-validated before use.
- **SSRF guard.** With `ALLOW_PRIVATE_TARGETS=0` (default), any target that
  resolves into private, loopback, link-local, or reserved IP space
  (including the `169.254.169.254` cloud-metadata endpoint) is refused before
  any HTTP request is made.
- **Authentication.** Set `API_KEY` to require a token (`X-API-Key` or
  `Authorization: Bearer`) on every `/api/*` route. Comparison is
  constant-time.
- **Rate limiting.** Per-client-IP sliding-window limits on all API routes.
- **Response hardening.** `Content-Security-Policy`, `X-Content-Type-Options`,
  `X-Frame-Options`, and `Referrer-Policy` are set on every response.
- **Workload caps.** Per-scan limits (`MAX_SUBDOMAINS`, `MAX_BULK_URLS`, worker
  counts, body-size cap) bound resource use.

## Reporting a vulnerability in this tool

If you find a security issue in Takeover Hunter itself (e.g. a way the report
generator or API endpoints could be abused, an injection point in the scan
pipeline), report it privately to the maintainer rather than opening a public
issue. Please include reproduction steps and, where possible, a suggested fix.
