"""Flask application factory and HTTP routes.

The factory pattern lets tests build an isolated app with an explicit config
and makes the WSGI entrypoint (``wsgi.py``) a one-liner. Every route that
accepts a target validates it through :mod:`takeover_hunter.validation` before
any work begins, and every long scan runs in a worker thread that streams
progress back as Server-Sent Events.
"""
from __future__ import annotations

import logging
import queue
import threading
from typing import Callable, Dict, Optional, Tuple

import dns.exception
import dns.resolver
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from takeover_hunter import __version__
from takeover_hunter.config import Config, load_config
from takeover_hunter.fingerprints import match_fingerprint, provider_names
from takeover_hunter.recon import ReconEngine, cmd_exists
from takeover_hunter.reporting import render_report
from takeover_hunter.security import install_security, require_api_key
from takeover_hunter.sse import sse_event
from takeover_hunter.validation import (
    ValidationError,
    clean_hostnames,
    extract_hostname_from_url,
    normalize_hostname,
    require_domain,
)

log = logging.getLogger("takeover_hunter")

# Intermediate SSE message renderers shared by every streaming route.
_COMMON_SPEC: Dict[str, Tuple[str, Callable]] = {
    "log": ("log", lambda m: {"level": m[1], "msg": m[2]}),
    "progress": ("progress", lambda m: {"done": m[1], "total": m[2]}),
    "vuln": ("vuln", lambda m: m[1]),
    "secret": ("secret", lambda m: m[1]),
    "verified": ("verified", lambda m: m[1]),
}


def _stream(q: "queue.Queue", terminal: Dict[str, Tuple[str, Callable]]) -> Response:
    """Drain ``q`` and emit SSE frames until a terminal message is seen."""
    spec = {**_COMMON_SPEC, **terminal}

    def generate():
        while True:
            msg = q.get()
            tag = msg[0]
            rendered = spec.get(tag)
            if rendered is None:
                continue
            event_name, render = rendered
            yield sse_event(event_name, render(msg))
            if event_name == "done":
                break

    return Response(stream_with_context(generate()), content_type="text/event-stream")


def _spawn(engine_method: Callable, *args) -> "queue.Queue":
    """Run ``engine_method(*args, q)`` in a daemon thread; return the queue."""
    q: "queue.Queue" = queue.Queue()
    threading.Thread(target=engine_method, args=(*args, q), daemon=True).start()
    return q


def create_app(config: Optional[Config] = None) -> Flask:
    """Build and configure the Flask application."""
    config = config or load_config()
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config["TH_CONFIG"] = config
    engine = ReconEngine(config)
    app.config["TH_ENGINE"] = engine

    install_security(app, config)

    @app.errorhandler(ValidationError)
    def _on_validation_error(exc: ValidationError):
        return jsonify({"error": str(exc)}), 400

    # ----------------------------------------------------------------- #
    # UI + meta                                                         #
    # ----------------------------------------------------------------- #
    @app.route("/")
    def index() -> str:
        return render_template("index.html")

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "version": __version__})

    @app.route("/api/tools")
    @require_api_key
    def api_tools():
        tools = ["subfinder", "assetfinder", "amass", "dnsx", "httpx",
                 "katana", "gau", "waybackurls", "nuclei"]
        return jsonify({t: cmd_exists(t) for t in tools})

    @app.route("/api/providers")
    @require_api_key
    def api_providers():
        return jsonify({"providers": provider_names()})

    # ----------------------------------------------------------------- #
    # Pipeline                                                          #
    # ----------------------------------------------------------------- #
    @app.route("/api/enumerate")
    @require_api_key
    def api_enumerate():
        target = require_domain(request.args.get("target", ""))
        q = _spawn(engine.enumerate_stream, target)
        return _stream(q, {"enum_done": ("done", lambda m: {"subdomains": m[1], "count": m[2]})})

    @app.route("/api/triage", methods=["POST"])
    @require_api_key
    def api_triage():
        data = request.get_json(silent=True) or {}
        subdomains = clean_hostnames(data.get("subdomains", []), limit=config.max_subdomains)
        if not subdomains:
            return Response(sse_event("done", {"cname": [], "dead": [], "a": []}),
                            content_type="text/event-stream")
        q = _spawn(engine.triage, subdomains)
        return _stream(q, {"triage_done": ("done", lambda m: {"cname": m[1], "dead": m[2], "a": m[3]})})

    @app.route("/api/scan", methods=["POST"])
    @require_api_key
    def api_scan():
        data = request.get_json(silent=True) or {}
        raw_records = data.get("cname_records", [])
        provider_filter = data.get("provider_filter", [])
        claimable_only = bool(data.get("claimable_only", False))

        records = []
        for rec in raw_records:
            if not isinstance(rec, dict):
                continue
            sub = normalize_hostname(rec.get("sub", ""))
            cname = normalize_hostname(rec.get("cname", "")) or ""
            if not sub:
                continue
            records.append({"sub": sub, "cname": cname, "claimable": rec.get("claimable", False)})

        if provider_filter:
            wanted = set(provider_filter)
            records = [
                r for r in records
                if (fp := match_fingerprint(r["cname"])) and fp["provider"] in wanted
            ]
        if claimable_only:
            records = [r for r in records if r.get("claimable")]

        records = records[: config.max_subdomains]
        if not records:
            return Response(sse_event("done", {"count": 0, "vulnerable": []}),
                            content_type="text/event-stream")
        q = _spawn(engine.scan, records)
        return _stream(q, {"scan_done": ("done", lambda m: {"count": len(m[1]), "vulnerable": m[1]})})

    @app.route("/api/bulkurlscan", methods=["POST"])
    @require_api_key
    def api_bulkurlscan():
        data = request.get_json(silent=True) or {}
        raw_urls = data.get("urls", [])
        hosts = []
        seen = set()
        for raw in raw_urls:
            host = extract_hostname_from_url(raw) if isinstance(raw, str) else None
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
            if len(hosts) >= config.max_bulk_urls:
                break
        if not hosts:
            return Response(sse_event("done", {"count": 0, "vulnerable": []}),
                            content_type="text/event-stream")
        q: "queue.Queue" = queue.Queue()
        q.put(("log", "info", f"Scanning {len(hosts)} hosts..."))
        threading.Thread(target=engine.bulk_url_scan, args=(hosts, q), daemon=True).start()
        return _stream(q, {"scan_done": ("done", lambda m: {"count": len(m[1]), "vulnerable": m[1]})})

    @app.route("/api/jsrecon", methods=["POST"])
    @require_api_key
    def api_jsrecon():
        data = request.get_json(silent=True) or {}
        target = require_domain(data.get("target", ""))
        subdomains = clean_hostnames(data.get("subdomains", []), limit=config.max_subdomains)
        q = _spawn(engine.js_recon, target, subdomains)
        return _stream(q, {"js_done": ("done", lambda m: m[1])})

    @app.route("/api/archive", methods=["POST"])
    @require_api_key
    def api_archive():
        data = request.get_json(silent=True) or {}
        target = require_domain(data.get("target", ""))
        q = _spawn(engine.archive_recon, target)
        return _stream(q, {"archive_done": ("done", lambda m: m[1])})

    @app.route("/api/verify", methods=["POST"])
    @require_api_key
    def api_verify():
        data = request.get_json(silent=True) or {}
        findings = [f for f in data.get("vulnerable", []) if isinstance(f, dict)]
        q = _spawn(engine.verify, findings)
        return _stream(q, {"verify_done": ("done", lambda m: {"verified": m[1]})})

    @app.route("/api/quickscan", methods=["POST"])
    @require_api_key
    def api_quickscan():
        data = request.get_json(silent=True) or {}
        sub = normalize_hostname(data.get("sub", "")) or ""
        cname = normalize_hostname(data.get("cname", "")) or ""
        if not cname and not sub:
            return jsonify({"error": "A valid sub or cname is required"}), 400
        result = engine.assess(sub or cname, cname or sub)
        if result is None:
            # Not vulnerable — still return a structured negative result.
            fp = match_fingerprint(cname or sub)
            return jsonify({
                "sub": sub or cname, "cname": cname or sub,
                "provider": fp["provider"] if fp else "Unknown",
                "vulnerable": False, "confidence": "low", "severity": "Info",
                "nxdomain": False, "cname_chain": [],
            })
        return jsonify(result)

    @app.route("/api/dns", methods=["POST"])
    @require_api_key
    def api_dns():
        data = request.get_json(silent=True) or {}
        host = normalize_hostname(data.get("host", ""))
        rtype = str(data.get("type", "A")).strip().upper()
        allowed = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "ANY", "SRV"}
        if rtype not in allowed:
            return jsonify({"error": f"Unsupported record type: {rtype}"}), 400
        if not host:
            return jsonify({"error": "A valid host is required"}), 400
        return jsonify(_dns_lookup(engine, host, rtype))

    @app.route("/api/report", methods=["POST"])
    @require_api_key
    def api_report():
        data = request.get_json(silent=True) or {}
        finding = data.get("finding", {})
        if not isinstance(finding, dict):
            return jsonify({"error": "finding must be an object"}), 400
        report = render_report(
            finding,
            h1_user=str(data.get("h1_user", "researcher"))[:64],
            platform=str(data.get("platform", "HackerOne"))[:32],
        )
        return jsonify({"report": report})

    return app


def _dns_lookup(engine: ReconEngine, host: str, rtype: str) -> Dict:
    """Perform a DNS lookup for the ``/api/dns`` endpoint."""
    resolver = engine.dns._resolver  # trusted internal resolver
    try:
        if rtype == "ANY":
            records = []
            for t in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
                try:
                    for r in resolver.resolve(host, t):
                        records.append(f"[{t}] {r}")
                except dns.exception.DNSException:
                    pass
            return {"records": records or ["No records found"]}

        answer = resolver.resolve(host, rtype)
        records = []
        for r in answer:
            if rtype == "MX":
                records.append(f"{r.preference} {str(r.exchange).rstrip('.')}")
            elif rtype in ("CNAME", "NS"):
                records.append(str(r.target).rstrip("."))
            elif rtype == "TXT":
                records.append(" ".join(s.decode() for s in r.strings))
            else:
                records.append(str(r))
        return {"records": records}
    except dns.resolver.NXDOMAIN:
        return {"records": [], "error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"records": [], "error": f"No {rtype} records"}
    except dns.exception.Timeout:
        return {"records": [], "error": "Timeout"}
    except dns.exception.DNSException as exc:
        return {"records": [], "error": str(exc)}
