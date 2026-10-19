"""Security middleware, authentication, rate limiting, and HTTP response hardening.

Enforces constant-time API key verification, thread-safe sliding-window rate limiting,
and defense-in-depth HTTP security headers (CSP, HSTS, X-Frame-Options, nosniff).
"""
from __future__ import annotations

from collections import defaultdict
from functools import wraps
import hmac
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from flask import Response, current_app, jsonify, request


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window rate limiter per client identifier."""

    def __init__(self, limit: int = 60, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, client_id: str) -> Tuple[bool, int]:
        """Check if client is within rate limits. Returns (allowed, retry_after_seconds)."""
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            timestamps = self.requests[client_id]
            valid_timestamps = [ts for ts in timestamps if ts > window_start]
            self.requests[client_id] = valid_timestamps

            if len(valid_timestamps) >= self.limit:
                oldest = valid_timestamps[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                return False, retry_after

            self.requests[client_id].append(now)
            return True, 0

    def reset(self) -> None:
        """Clear all rate limiting records."""
        with self._lock:
            self.requests.clear()


# Default package-level rate limiter
default_rate_limiter = SlidingWindowRateLimiter(limit=120, window_seconds=60)


def verify_api_key(expected_key: str, provided_key: Optional[str]) -> bool:
    """Verify API key using constant-time comparison.

    If expected_key is empty or unset, authentication is disabled and returns True.
    """
    if not expected_key:
        return True
    if not provided_key:
        return False

    return hmac.compare_digest(
        expected_key.strip().encode("utf-8"),
        provided_key.strip().encode("utf-8"),
    )


def extract_api_key(req) -> Optional[str]:
    """Extract API key from X-API-Key header or Authorization: Bearer <key>."""
    api_key = req.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()

    auth_header = req.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    return None


def require_auth_and_rate_limit(f: Callable) -> Callable:
    """Decorator to enforce optional API-key authentication and per-client rate limiting."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        cfg = current_app.config.get("HUNTER_CONFIG")
        expected_key = current_app.config.get("API_KEY") or (
            getattr(cfg, "API_KEY", "") if cfg else ""
        )

        # 1. API Key Authentication Check
        if expected_key:
            provided_key = extract_api_key(request)
            if not verify_api_key(expected_key, provided_key):
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Valid API key required via X-API-Key or Bearer token",
                }), 401

        # 2. Rate Limiting Check
        rate_limit = current_app.config.get("RATE_LIMIT_PER_MINUTE") or (
            getattr(cfg, "RATE_LIMIT_PER_MINUTE", 120) if cfg else 120
        )
        limiter = current_app.extensions.get("rate_limiter", default_rate_limiter)
        limiter.limit = rate_limit

        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        allowed, retry_after = limiter.is_allowed(client_ip)
        if not allowed:
            resp = jsonify({
                "error": "Too Many Requests",
                "message": f"Rate limit exceeded. Retry after {retry_after} seconds.",
                "retry_after": retry_after,
            })
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after)
            return resp

        return f(*args, **kwargs)

    return decorated_function


def apply_security_headers(response: Response) -> Response:
    """Attach standard defensive security response headers to all HTTP responses."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=(), payment=()"
    )

    return response
