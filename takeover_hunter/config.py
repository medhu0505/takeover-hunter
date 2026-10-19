"""Configuration module for Takeover Hunter v2.0.0.

Provides environment-driven configuration, per-scan workload caps,
concurrency limits, and security defaults.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Config:
    """Runtime configuration container with sensible production defaults."""

    # Server settings
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "3000"))
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "takeover-hunter-v2-default-secret-key")
    TESTING: bool = os.environ.get("TESTING", "false").lower() in ("1", "true", "yes")

    # Access control & authentication
    API_KEY: str = os.environ.get("TAKEOVER_API_KEY", "").strip()
    RATE_LIMIT_PER_MINUTE: int = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "120"))

    # Workload caps & timeouts
    MAX_SUBDOMAINS_PER_SCAN: int = int(os.environ.get("MAX_SUBDOMAINS_PER_SCAN", "500"))
    MAX_CONCURRENT_WORKERS: int = int(os.environ.get("MAX_CONCURRENT_WORKERS", "20"))
    HTTP_TIMEOUT_SECONDS: float = float(os.environ.get("HTTP_TIMEOUT_SECONDS", "4.0"))
    DNS_TIMEOUT_SECONDS: float = float(os.environ.get("DNS_TIMEOUT_SECONDS", "3.0"))
    MAX_REDIRECTS: int = int(os.environ.get("MAX_REDIRECTS", "3"))
    MAX_RESPONSE_BYTES: int = int(os.environ.get("MAX_RESPONSE_BYTES", "50000"))

    # DNS configuration
    DNS_NAMESERVERS: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])

    # SMTP Alerting (Optional)
    SMTP_HOST: str = os.environ.get("SMTP_HOST", "")
    SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER: str = os.environ.get("SMTP_USER", "")
    SMTP_PASS: str = os.environ.get("SMTP_PASS", "")
    SMTP_USE_TLS: bool = os.environ.get("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")
    ALERT_EMAIL: str = os.environ.get("ALERT_EMAIL", "")

    # Default platform metadata
    DEFAULT_REPORTER: str = os.environ.get("DEFAULT_REPORTER_USER", "stickybugger")
    DEFAULT_PLATFORM: str = os.environ.get("DEFAULT_PLATFORM", "HackerOne")


def get_config() -> Config:
    """Return an instantiated immutable configuration object."""
    return Config()
