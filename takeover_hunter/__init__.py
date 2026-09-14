"""Takeover Hunter — subdomain takeover detection and reporting engine.

A Flask application that orchestrates subdomain enumeration, DNS triage,
takeover fingerprinting, verification, and HackerOne-ready reporting behind a
streaming (Server-Sent Events) API.

The package is intentionally split into small, independently testable modules:

- :mod:`takeover_hunter.config`        runtime configuration (env-driven)
- :mod:`takeover_hunter.validation`    strict input validation (security boundary)
- :mod:`takeover_hunter.fingerprints`  provider signature database + matching
- :mod:`takeover_hunter.netutils`      DNS resolution and guarded HTTP probing
- :mod:`takeover_hunter.recon`         enumeration / triage / scan / verify workers
- :mod:`takeover_hunter.reporting`     vulnerability report rendering
- :mod:`takeover_hunter.sse`           Server-Sent Events framing helpers
- :mod:`takeover_hunter.security`      authentication, rate limiting, headers
- :mod:`takeover_hunter.app`           Flask application factory and routes
"""

__version__ = "2.0.0"
__all__ = ["__version__", "create_app"]


def create_app(*args, **kwargs):
    """Lazy re-export of :func:`takeover_hunter.app.create_app`.

    Imported lazily so that ``import takeover_hunter`` stays cheap and free of
    heavy transitive imports (Flask, requests) until an app is actually built.
    """
    from takeover_hunter.app import create_app as _create_app

    return _create_app(*args, **kwargs)
