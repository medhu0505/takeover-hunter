"""Runtime configuration, sourced from environment variables.

All tunables live here so deployments can be reconfigured without code
changes, and so tests can construct an app with an explicit config object
instead of monkeypatching module globals.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(minimum, int(raw))
    except (TypeError, ValueError):
        return default


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name)
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Config:
    """Immutable application configuration."""

    # --- Server ---------------------------------------------------------
    host: str = field(default_factory=lambda: os.environ.get("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("PORT", 5000, minimum=1))
    debug: bool = field(default_factory=lambda: _env_bool("DEBUG", False))

    # --- Authentication -------------------------------------------------
    # If set, every /api/* request must present this token via the
    # ``X-API-Key`` header (or ``Authorization: Bearer <token>``). If unset,
    # the API is open — appropriate only for local/trusted-network use.
    api_key: str = field(default_factory=lambda: os.environ.get("API_KEY", ""))

    # --- Rate limiting (token bucket, per client IP) --------------------
    rate_limit_enabled: bool = field(
        default_factory=lambda: _env_bool("RATE_LIMIT_ENABLED", True)
    )
    rate_limit_requests: int = field(
        default_factory=lambda: _env_int("RATE_LIMIT_REQUESTS", 60, minimum=1)
    )
    rate_limit_window_seconds: int = field(
        default_factory=lambda: _env_int("RATE_LIMIT_WINDOW_SECONDS", 60, minimum=1)
    )

    # --- Safety / SSRF guard --------------------------------------------
    # When False (default), targets that resolve to private, loopback,
    # link-local, or otherwise reserved IP space are rejected before any
    # HTTP probe is issued. Set ALLOW_PRIVATE_TARGETS=1 only for lab use.
    allow_private_targets: bool = field(
        default_factory=lambda: _env_bool("ALLOW_PRIVATE_TARGETS", False)
    )

    # --- Workload caps (DoS / abuse guards) -----------------------------
    max_subdomains: int = field(
        default_factory=lambda: _env_int("MAX_SUBDOMAINS", 5000, minimum=1)
    )
    max_bulk_urls: int = field(
        default_factory=lambda: _env_int("MAX_BULK_URLS", 2000, minimum=1)
    )
    max_scan_workers: int = field(
        default_factory=lambda: _env_int("MAX_SCAN_WORKERS", 30, minimum=1)
    )
    max_js_files: int = field(
        default_factory=lambda: _env_int("MAX_JS_FILES", 50, minimum=1)
    )

    # --- Network timeouts (seconds) -------------------------------------
    dns_timeout: float = field(
        default_factory=lambda: float(_env_int("DNS_TIMEOUT", 2, minimum=1))
    )
    dns_lifetime: float = field(
        default_factory=lambda: float(_env_int("DNS_LIFETIME", 4, minimum=1))
    )
    http_timeout: int = field(
        default_factory=lambda: _env_int("HTTP_TIMEOUT", 4, minimum=1)
    )
    tool_timeout: int = field(
        default_factory=lambda: _env_int("TOOL_TIMEOUT", 180, minimum=10)
    )
    http_body_cap: int = field(
        default_factory=lambda: _env_int("HTTP_BODY_CAP", 2000, minimum=256)
    )

    # --- DNS resolvers ---------------------------------------------------
    resolvers: List[str] = field(
        default_factory=lambda: _env_list("DNS_RESOLVERS", ["8.8.8.8", "1.1.1.1"])
    )

    # --- Probe identity --------------------------------------------------
    # Courtesy identifier sent during HTTP probing for bug bounty programs
    # that request it. Not a substitute for authorization.
    bug_bounty_header: str = field(
        default_factory=lambda: os.environ.get("BUG_BOUNTY_HEADER", "takeover-hunter")
    )
    user_agent: str = field(
        default_factory=lambda: os.environ.get(
            "USER_AGENT", "Mozilla/5.0 (compatible; TakeoverHunter/2.0)"
        )
    )


def load_config() -> Config:
    """Build a :class:`Config` from the current environment."""
    return Config()
