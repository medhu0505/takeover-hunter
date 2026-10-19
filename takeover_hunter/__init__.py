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
    create_resolver,
    default_resolver,
    is_wildcard,
    resolve_a,
    resolve_cname,
    resolve_cname_chain,
    triage_subdomain,
    triage_subdomain_bulk,
)
from .enumerator import (
    enumerate_subdomains,
    get_available_tools,
    is_tool_available,
    probe_with_httpx,
    run_binary_safe,
)
from .routes import api_bp, generate_bugcrowd_report, generate_h1_report, sse_event
from .security import (
    SlidingWindowRateLimiter,
    apply_security_headers,
    extract_api_key,
    require_auth_and_rate_limit,
    verify_api_key,
)
from .signatures import (
    FINGERPRINTS,
    SIGNATURES,
    Signature,
    get_signature_by_provider,
    match_fingerprint,
    match_signature,
)
from .ssrf_guard import (
    BLOCKED_NETWORKS,
    PinnedIPHTTPAdapter,
    SafeProbeResult,
    SSRFBlockedException,
    is_ip_blocked,
    resolve_and_validate_hostname,
    safe_http_probe,
    validate_ip_string,
    verify_response_peer_ip,
)
from .validators import is_valid_hostname, validate_domain, validate_subdomain_list
from .verifier import Finding, assess_target, calculate_severity, verify_finding

# Compatibility alias for legacy callers
is_safe_target = is_valid_hostname

__version__ = "2.0.0"
__all__ = [
    "create_app",
    "Config",
    "get_config",
    "SIGNATURES",
    "FINGERPRINTS",
    "Signature",
    "get_signature_by_provider",
    "match_signature",
    "match_fingerprint",
    "assess_target",
    "verify_finding",
    "calculate_severity",
    "Finding",
    "validate_domain",
    "is_valid_hostname",
    "is_safe_target",
    "validate_subdomain_list",
    "safe_http_probe",
    "SafeProbeResult",
    "SSRFBlockedException",
    "BLOCKED_NETWORKS",
    "is_ip_blocked",
    "validate_ip_string",
    "resolve_and_validate_hostname",
    "verify_response_peer_ip",
    "PinnedIPHTTPAdapter",
    "is_tool_available",
    "get_available_tools",
    "run_binary_safe",
    "enumerate_subdomains",
    "probe_with_httpx",
    "create_resolver",
    "default_resolver",
    "resolve_cname",
    "resolve_cname_chain",
    "check_nxdomain",
    "resolve_a",
    "is_wildcard",
    "triage_subdomain",
    "triage_subdomain_bulk",
    "sse_event",
    "generate_h1_report",
    "generate_bugcrowd_report",
    "SlidingWindowRateLimiter",
    "verify_api_key",
    "extract_api_key",
    "require_auth_and_rate_limit",
    "apply_security_headers",
]


def create_app(test_config: Optional[dict] = None) -> Flask:
    """Flask 3 application factory."""
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

    limiter = SlidingWindowRateLimiter(
        limit=int(app.config.get("RATE_LIMIT_PER_MINUTE", config_obj.RATE_LIMIT_PER_MINUTE)),
        window_seconds=60,
    )
    app.extensions["rate_limiter"] = limiter

    app.after_request(apply_security_headers)
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.route("/")
    def index():
        if os.path.exists(os.path.join(templates_dir, "index.html")):
            return render_template("index.html")
        return jsonify({"message": "Takeover Hunter v2.0.0 API active", "version": "2.0.0"})

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
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
        }), 500

    return app
