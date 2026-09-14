"""Authentication, rate limiting, and response hardening.

All three are opt-in via configuration and applied by the app factory. Kept
dependency-free (no Flask-Limiter) so the asset has no extra supply chain and
stays trivial to audit.
"""
from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from typing import Callable, Deque, Dict

from flask import Response, current_app, jsonify, request

from takeover_hunter.config import Config


# --------------------------------------------------------------------------- #
# API key authentication                                                      #
# --------------------------------------------------------------------------- #
def _presented_key() -> str:
    """Extract an API key from the request (header or bearer token)."""
    header = request.headers.get("X-API-Key")
    if header:
        return header.strip()
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def require_api_key(view: Callable) -> Callable:
    """Decorator enforcing the configured API key, if one is set.

    When ``config.api_key`` is empty the API is open (local/trusted use) and
    the decorator is a no-op. Comparison is constant-time.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        config: Config = current_app.config["TH_CONFIG"]
        if not config.api_key:
            return view(*args, **kwargs)
        if hmac.compare_digest(_presented_key(), config.api_key):
            return view(*args, **kwargs)
        return jsonify({"error": "Unauthorized: missing or invalid API key"}), 401

    return wrapper


# --------------------------------------------------------------------------- #
# Rate limiting (sliding window per client IP)                                #
# --------------------------------------------------------------------------- #
class RateLimiter:
    """In-memory sliding-window rate limiter keyed by client identity."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self.max_requests:
                return False
            hits.append(now)
            return True


def _client_key() -> str:
    """Best-effort client identity for rate limiting.

    Honours the left-most ``X-Forwarded-For`` entry (set by the platform proxy
    on Railway/Heroku) and falls back to the socket peer.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def install_security(app, config: Config) -> None:
    """Wire rate limiting and hardening headers onto ``app``."""
    limiter = RateLimiter(config.rate_limit_requests, config.rate_limit_window_seconds)

    @app.before_request
    def _rate_limit():  # type: ignore[unused-ignore]
        if not config.rate_limit_enabled:
            return None
        if not request.path.startswith("/api/"):
            return None
        if not limiter.allow(_client_key()):
            resp = jsonify({"error": "Rate limit exceeded. Slow down."})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(config.rate_limit_window_seconds)
            return resp
        return None

    @app.after_request
    def _headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
        )
        return response
