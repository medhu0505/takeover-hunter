"""Input validation and sanitization adhering strictly to RFC 1035 / RFC 1123.

Guards against command injection, path traversal, and malicious input.
"""
from __future__ import annotations

import re
from typing import Iterable, List

# Strict RFC 1035 label pattern: 1-63 chars, starts/ends with alphanumeric, hyphens allowed internally
LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Disallowed shell metacharacters and dangerous sequences
DISALLOWED_CHARS = set(";|&`$><\n\r\t \0\\\"'(){}[]!#%^*+=~/?")


def is_valid_hostname(hostname: str, allow_trailing_dot: bool = True) -> bool:
    """Validate whether a string is a strictly compliant RFC 1035/1123 hostname.

    Ensures no shell metacharacters, spaces, leading hyphens, or malformed labels exist.
    """
    if not isinstance(hostname, str):
        return False

    name = hostname.strip()
    if not name:
        return False

    # Check for leading flags
    if name.startswith("-"):
        return False

    # Check for forbidden characters
    if any(c in DISALLOWED_CHARS for c in name):
        return False

    # Handle trailing dot (FQDN)
    if allow_trailing_dot and name.endswith("."):
        name = name[:-1]

    # Total length: max 253 octets (RFC 1035 section 2.3.4, RFC 2181 section 11)
    if len(name) < 1 or len(name) > 253:
        return False

    labels = name.split(".")
    # Must have at least 1 label (for single hostname) or typically 2+ for domain
    for label in labels:
        if not label:
            return False
        if len(label) > 63:
            return False
        if not LABEL_PATTERN.match(label):
            return False

    return True


def validate_domain(domain: str) -> str:
    """Validate a target domain, returning normalized lowercase domain or raising ValueError."""
    if not isinstance(domain, str):
        raise ValueError("Domain must be a string")

    cleaned = domain.strip().lower()
    if not cleaned:
        raise ValueError("Domain cannot be empty")

    if not is_valid_hostname(cleaned):
        raise ValueError(f"Invalid domain format: {domain!r}. Must strictly comply with RFC 1035.")

    labels = cleaned.rstrip(".").split(".")
    if len(labels) < 2:
        raise ValueError(f"Domain must contain at least a name and TLD: {domain!r}")

    # TLD cannot be purely numeric (RFC 1123)
    if labels[-1].isdigit():
        raise ValueError(f"Top-level domain cannot be purely numeric: {labels[-1]!r}")

    return cleaned.rstrip(".")


def validate_subdomain_list(subdomains: Iterable[str], max_count: int = 500) -> List[str]:
    """Validate a collection of subdomains, filtering invalid entries and capping length."""
    if not subdomains:
        return []

    validated: List[str] = []
    seen = set()

    for item in subdomains:
        if not isinstance(item, str):
            continue
        cleaned = item.strip().lower()
        if not cleaned:
            continue

        # Strip URL scheme or path if accidentally provided
        if "://" in cleaned:
            cleaned = cleaned.split("://", 1)[1]
        cleaned = cleaned.split("/", 1)[0].split(":", 1)[0]

        if is_valid_hostname(cleaned) and cleaned not in seen:
            seen.add(cleaned)
            validated.append(cleaned)
            if len(validated) >= max_count:
                break

    return validated
