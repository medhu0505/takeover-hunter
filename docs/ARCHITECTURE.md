# Architecture

Takeover Hunter is a Flask application organised as a small Python package.
The design goals are: a clean security boundary, testable units, and a
streaming request model that keeps long scans responsive.

## Data flow

```
                    ┌──────────────────────────────────────────────┐
   Browser  ──HTTP──►  Flask routes  (takeover_hunter/app.py)       │
   (SSE)    ◄─stream─┤   • validate every target (validation.py)    │
                    │   • enforce auth + rate limit (security.py)   │
                    └───────────────┬──────────────────────────────┘
                                    │ spawns a worker thread + queue
                                    ▼
                    ┌──────────────────────────────────────────────┐
                    │  ReconEngine  (takeover_hunter/recon.py)      │
                    │                                               │
                    │  enumerate ─► triage ─► scan ─► verify        │
                    │       │          │        │        │          │
                    │       ▼          ▼        ▼        ▼          │
                    │   argv tools  DNSClient  assess()  re-check   │
                    │   (no shell)  (netutils) (shared)             │
                    └───────────────┬──────────────────────────────┘
                                    │ tagged messages
                                    ▼
                    ┌──────────────────────────────────────────────┐
                    │  SSE framing  (takeover_hunter/sse.py)        │
                    │  queue → `event: <name>\n data: <json>`       │
                    └──────────────────────────────────────────────┘
```

## The producer/consumer streaming model

Each long-running operation runs in a **daemon worker thread** that pushes
tagged tuples onto a `queue.Queue`:

- `("log", level, message)` — human-readable progress
- `("progress", done, total)` — progress bar updates
- `("vuln", finding)` / `("secret", entry)` / `("verified", result)` — items
- `("<stage>_done", ...)` — terminal message that ends the stream

The Flask route drains the queue in a `stream_with_context` generator and
reframes each message as a Server-Sent Event. A single generic streamer
(`app._stream`) plus a per-route "terminal" spec removes the duplicated
generator code the original had in every endpoint.

Because work happens in a thread and results arrive incrementally, the browser
shows live output and the request is naturally cancellable (client disconnect
stops consumption).

## The security boundary

`validation.py` is the single choke point through which every request-supplied
host must pass before it reaches DNS, HTTP, or a subprocess:

- Hostnames are matched against the RFC 1035 label grammar
  (`[A-Za-z0-9-]` labels, dot-separated). This excludes every shell
  metacharacter, so even though enumeration shells out to recon tools, there is
  no character that could break out of an argument.
- Enumeration targets additionally require a dotted, alphabetic TLD.
- Tool **output** is re-validated (`recon._hosts_in_scope`) and scoped to the
  target domain before it is trusted downstream.

This layering means command injection is prevented in two independent ways:
argument-list invocation (no shell interpreter) **and** input that cannot
contain a metacharacter in the first place.

## Shared assessment core

`ReconEngine.assess()` is the single source of truth for "is this subdomain
vulnerable?" It resolves the CNAME chain, fingerprints the final target,
probes HTTP (through the SSRF guard), and applies the confidence ladder:

1. **NXDOMAIN** on the delegated target → High confidence.
2. **Body fingerprint** match (provider's unclaimed-resource string) → High.
3. **Fingerprinted provider + 404/no-response** → Medium.

The scan, bulk-URL scan, and quick-scan endpoints all call this one method,
replacing three near-identical copies in the original code.

## Configuration and the app factory

`config.py` builds an immutable `Config` from environment variables.
`app.create_app(config)` is a factory: tests construct an app with an explicit
config (auth on/off, limits tuned) with no global state, and the production
WSGI entrypoint is a one-liner (`wsgi.py`).

## Threading notes

- A single `dns.resolver.Resolver` and a `requests` call site are shared across
  worker threads; both are safe for the concurrent, independent lookups used
  here.
- Scan concurrency is bounded by `MAX_SCAN_WORKERS` via a `ThreadPoolExecutor`.
- gunicorn provides process-level concurrency in production; the in-process
  threads handle the fan-out within a single scan request.
