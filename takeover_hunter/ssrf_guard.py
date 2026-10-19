"""SSRF (Server-Side Request Forgery) protection and safe HTTP probing.

Enforces pre-request DNS resolution, strict IP blacklisting across IPv4 and IPv6,
and manual redirect-hop re-validation.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SSRFBlockedException(ValueError):
    """Raised when an outbound request targets a blocked or non-public network address."""
    pass


# Disallowed IPv4 and IPv6 CIDR ranges
BLOCKED_NETWORKS = [
    # IPv4 Private / Loopback / Link-local / Special
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark testing
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast

    # IPv6 Loopback / Link-local / Unique-Local / Special
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique-Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
]


def is_ip_blocked(ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any blocked, private, or link-local range."""
    # Handle IPv4-mapped IPv6 addresses (::ffff:192.168.1.1)
    if isinstance(ip_addr, ipaddress.IPv6Address) and ip_addr.ipv4_mapped:
        ip_addr = ip_addr.ipv4_mapped

    if ip_addr.is_loopback or ip_addr.is_private or ip_addr.is_link_local or ip_addr.is_multicast or ip_addr.is_reserved or ip_addr.is_unspecified:
        return True

    for net in BLOCKED_NETWORKS:
        if ip_addr in net:
            return True

    return False


def validate_ip_string(ip_str: str) -> None:
    """Validate a raw IP address string; raises SSRFBlockedException if blocked."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as e:
        raise SSRFBlockedException(f"Invalid IP address format: {ip_str!r}") from e

    if is_ip_blocked(ip):
        raise SSRFBlockedException(f"Target IP {ip_str} falls within restricted/private subnet")


def resolve_and_validate_hostname(hostname: str) -> List[str]:
    """Resolve a hostname to all A/AAAA records and verify none are in blocked ranges.

    If ANY resolved IP is in a blocked range, the entire host is rejected to guard
    against DNS rebinding and dual-homed bypasses.
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if not clean_host:
        raise SSRFBlockedException("Cannot resolve empty hostname")

    # If already a valid IP literal, validate directly
    try:
        ip = ipaddress.ip_address(clean_host)
        if is_ip_blocked(ip):
            raise SSRFBlockedException(f"Direct IP target {clean_host} is blocked by SSRF policy")
        return [str(ip)]
    except ValueError:
        pass

    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(clean_host, None)
    except socket.gaierror as e:
        # Host could be NXDOMAIN or unresolvable
        return []

    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip):
                raise SSRFBlockedException(
                    f"Hostname {clean_host} resolved to blocked IP {ip_str} (SSRF prevention)"
                )
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
        except ValueError:
            continue

    return resolved_ips


@dataclass
class SafeProbeResult:
    """Structured response container from SSRF-safe HTTP probes."""
    status_code: int = 0
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    final_url: str = ""
    error: Optional[str] = None


def safe_http_probe(
    target_url_or_host: str,
    timeout: float = 4.0,
    max_redirects: int = 3,
    max_bytes: int = 50000,
    custom_headers: Optional[Dict[str, str]] = None,
) -> SafeProbeResult:
    """Execute an outbound HTTP probe with pre-flight DNS validation and redirect verification."""
    # Normalize input into an initial URL
    if not target_url_or_host.startswith(("http://", "https://")):
        current_url = f"https://{target_url_or_host.strip()}"
    else:
        current_url = target_url_or_host.strip()

    headers = {
        "User-Agent": "TakeoverHunter/2.0.0 (Defensive Security Scanner; RFC 1035)",
        "Accept": "*/*",
        "X-Bug-Bounty": "Security-Audit",
    }
    if custom_headers:
        headers.update(custom_headers)

    redirects_remaining = max_redirects

    while True:
        parsed = urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            return SafeProbeResult(
                status_code=0,
                error=f"Disallowed URL scheme {parsed.scheme!r}. Only HTTP/HTTPS permitted."
            )

        hostname = parsed.hostname
        if not hostname:
            return SafeProbeResult(status_code=0, error="URL missing valid hostname")

        # Validate hostname & resolve IPs
        try:
            resolve_and_validate_hostname(hostname)
        except SSRFBlockedException as e:
            return SafeProbeResult(status_code=0, error=str(e))

        try:
            # allow_redirects=False is mandatory for manual hop re-validation
            resp = requests.get(
                current_url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                stream=True,
            )
        except requests.exceptions.RequestException as e:
            # If HTTPS failed, fallback to HTTP if we haven't redirected yet
            if current_url.startswith("https://") and redirects_remaining == max_redirects:
                current_url = "http://" + current_url[8:]
                continue
            return SafeProbeResult(status_code=0, error=str(e), final_url=current_url)

        # Handle Redirects manually
        if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
            if redirects_remaining <= 0:
                return SafeProbeResult(
                    status_code=resp.status_code,
                    error="Maximum redirects exceeded",
                    final_url=current_url
                )
            redirects_remaining -= 1
            raw_location = resp.headers["Location"]
            next_url = urljoin(current_url, raw_location)
            current_url = next_url
            continue

        # Terminal response: read content up to max_bytes
        try:
            body_chunks: List[bytes] = []
            bytes_read = 0
            for chunk in resp.iter_content(chunk_size=4096):
                body_chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read >= max_bytes:
                    break
            body_text = b"".join(body_chunks).decode("utf-8", errors="replace")
        except Exception as e:
            body_text = ""

        return SafeProbeResult(
            status_code=resp.status_code,
            body=body_text,
            headers={k.lower(): v for k, v in resp.headers.items()},
            final_url=current_url,
        )
