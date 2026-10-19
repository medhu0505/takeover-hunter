"""Unit tests for takeover_hunter/security.py and takeover_hunter/config.py."""
from __future__ import annotations

import time

import pytest

from takeover_hunter import create_app
from takeover_hunter.config import Config, get_config
from takeover_hunter.security import (
    SlidingWindowRateLimiter,
    apply_security_headers,
    extract_api_key,
    verify_api_key,
)


def test_config_dynamic_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    cfg1 = get_config()
    cfg2 = Config()
    assert len(cfg1.SECRET_KEY) == 64
    assert cfg1.SECRET_KEY != "takeover-hunter-v2-default-secret-key"
    assert cfg1.SECRET_KEY != cfg2.SECRET_KEY


def test_verify_api_key_constant_time():
    assert verify_api_key("", None) is True
    assert verify_api_key("", "anything") is True
    assert verify_api_key("secret-token-123", None) is False
    assert verify_api_key("secret-token-123", "") is False
    assert verify_api_key("secret-token-123", "wrong-token") is False
    assert verify_api_key("secret-token-123", "secret-token-123") is True
    assert verify_api_key("  secret-token-123 ", "secret-token-123") is True


def test_sliding_window_rate_limiter_enforces_and_expires():
    limiter = SlidingWindowRateLimiter(limit=3, window_seconds=1)
    assert limiter.is_allowed("198.51.100.10")[0] is True
    assert limiter.is_allowed("198.51.100.10")[0] is True
    assert limiter.is_allowed("198.51.100.10")[0] is True

    allowed, retry_after = limiter.is_allowed("198.51.100.10")
    assert allowed is False
    assert retry_after >= 1

    # Different client is unaffected
    assert limiter.is_allowed("198.51.100.11")[0] is True

    # Reset clears state
    limiter.reset()
    assert limiter.is_allowed("198.51.100.10")[0] is True


def test_api_key_authentication_middleware():
    app = create_app({"TESTING": True, "API_KEY": "super-secret-api-key"})
    with app.test_client() as client:
        # Unauthenticated request to protected endpoint returns 401
        r1 = client.post("/api/report", json={"finding": {"sub": "a.example.com"}})
        assert r1.status_code == 401

        # Wrong key returns 401
        r2 = client.post(
            "/api/report",
            json={"finding": {"sub": "a.example.com"}},
            headers={"X-API-Key": "wrong-key"},
        )
        assert r2.status_code == 401

        # Valid X-API-Key returns 200
        r3 = client.post(
            "/api/report",
            json={"finding": {"sub": "a.example.com"}},
            headers={"X-API-Key": "super-secret-api-key"},
        )
        assert r3.status_code == 200

        # Valid Authorization: Bearer <key> returns 200
        r4 = client.post(
            "/api/report",
            json={"finding": {"sub": "a.example.com"}},
            headers={"Authorization": "Bearer super-secret-api-key"},
        )
        assert r4.status_code == 200


def test_rate_limiting_middleware_and_headers():
    app = create_app({"TESTING": True, "RATE_LIMIT_PER_MINUTE": 2})
    with app.test_client() as client:
        headers = {"X-Forwarded-For": "203.0.113.5, 10.0.0.1"}
        r1 = client.post("/api/report", json={"finding": {"sub": "a.example.com"}}, headers=headers)
        r2 = client.post("/api/report", json={"finding": {"sub": "a.example.com"}}, headers=headers)
        r3 = client.post("/api/report", json={"finding": {"sub": "a.example.com"}}, headers=headers)

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429
        assert "Retry-After" in r3.headers


def test_security_headers_attached_to_responses():
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        resp = client.get("/api/healthz")
        assert resp.status_code == 200
        assert "Content-Security-Policy" in resp.headers
        assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "geolocation=()" in resp.headers.get("Permissions-Policy", "")
