"""Takeover Hunter v2.0.0 — Production-grade Subdomain Takeover Detection Suite.

Flask 3 application factory with security header enforcement, blueprint registration,
and rate limiter integration.
"""
from __future__ import annotations

import os
from typing import Optional

from flask import Flask, jsonify, render_template

from .config import Config, get_config
from .dns_triage import (
    check_nxdomain,
    is_wildcard,
    resolve_a,
    resolve_cname,
    resolve_cname_chain,
    triage_subdomain,
)
from .enumerator import enumerate_subdomains, get_available_tools, is_tool_available
from .routes import api_bp, generate_bugcrowd_report, generate_h1_report, sse_event
from .security import SlidingWindowRateLimiter, apply_security_headers
from .signatures import FINGERPRINTS, SIGNATURES, match_fingerprint, match_signature
from .ssrf_guard import SafeProbeResult, safe_http_probe
from .validators import is_valid_hostname, validate_domain, validate_subdomain_list
from .verifier import Finding, assess_target, verify_finding

__version__ = "2.0.0"
__all__ = [
    "create_app",
    "Config",
    "get_config",
    "SIGNATURES",
    "FINGERPRINTS",
    "match_signature",
    "match_fingerprint",
    "assess_target",
    "verify_finding",
    "Finding",
    "validate_domain",
    "is_valid_hostname",
    "validate_subdomain_list",
    "safe_http_probe",
    "SafeProbeResult",
    "is_tool_available",
    "get_available_tools",
    "enumerate_subdomains",
    "resolve_cname",
    "resolve_cname_chain",
    "check_nxdomain",
    "resolve_a",
    "is_wildcard",
    "triage_subdomain",
    "sse_event",
    "generate_h1_report",
    "generate_bugcrowd_report",
]


def create_app(test_config: Optional[dict] = None) -> Flask:
    """Flask 3 application factory."""
    # Locate templates relative to package root or app root
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    templates_dir = os.path.join(base_dir, "templates")
    static_dir = os.path.join(base_dir, "static")

    app = Flask(
        __name__,
        template_folder=templates_dir if os.path.isdir(templates_dir) else None,
        static_folder=static_dir if os.path.isdir(static_dir) else None,
    )

    config_obj = get_config()
    app.config["HUNTER_CONFIG"] = config_obj
    app.config["SECRET_KEY"] = config_obj.SECRET_KEY
    app.config["TESTING"] = config_obj.TESTING

    if test_config:
        app.config.update(test_config)

    # Initialize sliding-window rate limiter extension
    limiter = SlidingWindowRateLimiter(
        limit=config_obj.RATE_LIMIT_PER_MINUTE,
        window_seconds=60,
    )
    app.extensions["rate_limiter"] = limiter

    # Security header middleware on all responses
    app.after_request(apply_security_headers)

    # Register API blueprint
    app.register_blueprint(api_bp, url_prefix="/api")

    # Serve Web UI
    @app.route("/")
    def index():
        if os.path.exists(os.path.join(templates_dir, "index.html")):
            return render_template("index.html")
        return jsonify({"message": "Takeover Hunter v2.0.0 API active", "version": "2.0.0"})

    # Global Error Handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        return jsonify({"error": "Bad Request", "message": str(e)}), 400

    @app.errorhandler(401)
    def handle_unauthorized(e):
        return jsonify({"error": "Unauthorized", "message": "Valid API key required"}), 401

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({"error": "Not Found", "message": "Endpoint not found"}), 404

    @app.errorhandler(429)
    def handle_rate_limit(e):
        return jsonify({"error": "Too Many Requests", "message": "Rate limit exceeded"}), 429

    @app.errorhandler(500)
    def handle_server_error(e):
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500

    return app
