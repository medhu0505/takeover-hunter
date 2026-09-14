"""Input validation — the security boundary of the application.

Every value that originates from an HTTP request and later reaches a
subprocess argument, a DNS query, or an HTTP probe MUST pass through this
module first. Hostnames are restricted to the RFC 1035 character set
(letters, digits, hyphen, dot), which structurally excludes every shell
metacharacter (``; | & $ ` ( ) < > space`` ...). That is what prevents the
recon tool invocations from being turned into command injection.

The functions here never raise on hostile input in the streaming code paths;
they return ``None`` or drop invalid entries so a single bad row cannot abort
a scan. :func:`require_domain` is the strict variant used at route
boundaries, raising :class:`ValidationError` for a clean ``400`` response.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

# Maximum total length of a DNS name (RFC 1035 section 2.3.4).
MAX_HOSTNAME_LENGTH = 253
# A single DNS label: 1-63 chars, alphanumeric, internal hyphens allowed.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
# A hostname is one or more dot-separated labels (e.g. ``api.example.com``).
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
# A registrable domain must have at least two labels and an alphabetic TLD
# (e.g. ``example.com``). Used for the enumeration ``target`` parameter.
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+(?!-)[A-Za-z]{{2,63}}$")


class ValidationError(ValueError):
    """Raised when a required, user-supplied value fails validation."""


def _strip_wrapping(value: str) -> str:
    """Reduce a raw user string toward a bare hostname.

    Strips surrounding whitespace, an optional URL scheme and path, any
    ``user@`` prefix, a trailing dot, and a ``:port`` suffix. This is a
    convenience normaliser only — the result is still validated by the
    caller before use.
    """
    value = value.strip().lower()
    if not value:
        return ""
    # If it looks like a URL (or scheme-relative), parse out the host.
    if "://" in value:
        value = urlsplit(value).hostname or ""
    elif value.startswith("//"):
        value = urlsplit("http:" + value).hostname or ""
    else:
        # Drop any path/query fragment: ``example.com/foo?x=1`` -> ``example.com``
        value = re.split(r"[/?#]", value, 1)[0]
    # Drop credentials and port, if the split above left them.
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if value.count(":") == 1:  # host:port (ignore bare IPv6, unsupported here)
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def normalize_hostname(value: Optional[str]) -> Optional[str]:
    """Normalise and validate an arbitrary hostname.

    Returns the cleaned lowercase hostname, or ``None`` if the input is not a
    syntactically valid DNS name. Safe to feed hostile input.
    """
    if not value or not isinstance(value, str):
        return None
    host = _strip_wrapping(value)
    return host if is_valid_hostname(host) else None


def normalize_domain(value: Optional[str]) -> Optional[str]:
    """Normalise and validate a registrable domain (``target`` parameter).

    Stricter than :func:`normalize_hostname`: requires at least two labels and
    an alphabetic TLD. Returns ``None`` for invalid input.
    """
    if not value or not isinstance(value, str):
        return None
    domain = _strip_wrapping(value)
    return domain if is_valid_domain(domain) else None


def is_valid_hostname(value: str) -> bool:
    """True if ``value`` is a syntactically valid DNS hostname."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_HOSTNAME_LENGTH
        and _HOSTNAME_RE.match(value) is not None
    )


def is_valid_domain(value: str) -> bool:
    """True if ``value`` is a valid registrable domain (has a dotted TLD)."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_HOSTNAME_LENGTH
        and _DOMAIN_RE.match(value) is not None
    )


def require_domain(value: Optional[str]) -> str:
    """Return a validated registrable domain or raise :class:`ValidationError`.

    Used at route boundaries where an invalid target should produce a clean
    ``400`` rather than being silently dropped.
    """
    domain = normalize_domain(value)
    if domain is None:
        raise ValidationError(
            "Invalid target: expected a domain such as 'example.com'."
        )
    return domain


def require_hostname(value: Optional[str]) -> str:
    """Return a validated hostname or raise :class:`ValidationError`."""
    host = normalize_hostname(value)
    if host is None:
        raise ValidationError(
            "Invalid host: expected a hostname such as 'api.example.com'."
        )
    return host


def clean_hostnames(values: Iterable[str], *, limit: int) -> List[str]:
    """Normalise, validate, and de-duplicate a list of hostnames.

    Invalid entries are dropped. Order of first appearance is preserved and
    the result is truncated to ``limit`` items.
    """
    seen: set[str] = set()
    out: List[str] = []
    if not values:
        return out
    for raw in values:
        host = normalize_hostname(raw)
        if host and host not in seen:
            seen.add(host)
            out.append(host)
            if len(out) >= limit:
                break
    return out


def extract_hostname_from_url(value: str) -> Optional[str]:
    """Extract and validate the hostname from a URL or bare ``host[/path]``."""
    return normalize_hostname(value)
