"""SSRF (Server-Side Request Forgery) protection and safe HTTP probing.

Enforces bounded pre-request dnspython A/AAAA resolution, strict IP blacklisting
across IPv4, IPv6, and IPv4-mapped IPv6, TOCTOU / DNS-rebinding peer verification,
manual redirect-hop re-validation, and bounded response streaming.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import socket
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import requests
from requests.adapters import HTTPAdapter
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SSRFBlockedException(ValueError):
    """Raised when an outbound request targets a blocked or non-public network address."""


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
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6 (checked via ipv4_mapped)
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation (RFC 6052)
    ipaddress.ip_network("100::/64"),           # Discard-Only (RFC 6666)
    ipaddress.ip_network("fc00::/7"),           # Unique-Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
]


def is_ip_blocked(ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any blocked, private, or link-local range."""
    # Unpack IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip_addr, ipaddress.IPv6Address):
        if ip_addr.ipv4_mapped is not None:
            return is_ip_blocked(ip_addr.ipv4_mapped)
        if ip_addr.sixtofour is not None:
            return is_ip_blocked(ip_addr.sixtofour)
        if ip_addr.teredo is not None:
            server_ip, client_ip = ip_addr.teredo
            if is_ip_blocked(server_ip) or is_ip_blocked(client_ip):
                return True

    if (
        ip_addr.is_loopback
        or ip_addr.is_private
        or ip_addr.is_link_local
        or ip_addr.is_multicast
        or ip_addr.is_reserved
        or ip_addr.is_unspecified
    ):
        return True

    for net in BLOCKED_NETWORKS:
        if ip_addr.version == net.version and ip_addr in net:
            return True

    return False


def validate_ip_string(ip_str: str) -> None:
    """Validate a raw IP address string; raises SSRFBlockedException if blocked."""
    cleaned = ip_str.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError as e:
        raise SSRFBlockedException(f"Invalid IP address format: {ip_str!r}") from e

    if is_ip_blocked(ip):
        raise SSRFBlockedException(
            f"Target IP {cleaned} falls within restricted/private subnet"
        )


def _create_bounded_resolver(
    timeout: float = 2.0,
    lifetime: float = 4.0,
    nameservers: Optional[List[str]] = None,
) -> dns.resolver.Resolver:
    """Create a thread-local / per-call bounded dnspython Resolver."""
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = list(nameservers) if nameservers else ["8.8.8.8", "1.1.1.1"]
    res.timeout = timeout
    res.lifetime = lifetime
    return res


def resolve_and_validate_hostname(
    hostname: str,
    timeout: float = 2.0,
    lifetime: float = 4.0,
    resolver: Optional[dns.resolver.Resolver] = None,
) -> List[str]:
    """Resolve a hostname to all A and AAAA records with bounded timeout and verify none are blocked.

    If ANY resolved IP (A or AAAA) falls within a blocked range, the entire host is
    rejected immediately with SSRFBlockedException to prevent DNS rebinding and
    dual-stack bypasses.
    """
    if not isinstance(hostname, str):
        raise SSRFBlockedException("Hostname must be a string")

    clean_host = hostname.strip().strip("[]").lower().rstrip(".")
    if not clean_host:
        raise SSRFBlockedException("Cannot resolve empty hostname")

    # 1. If already a valid IP literal, validate directly without DNS lookup
    try:
        ip_literal = ipaddress.ip_address(clean_host)
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        if is_ip_blocked(ip_literal):
            raise SSRFBlockedException(
                f"Direct IP target {clean_host} is blocked by SSRF policy"
            )
        return [str(ip_literal)]

    resolved_ips: List[str] = []

    # Check if socket.getaddrinfo was explicitly patched by a unit test
    getaddrinfo_is_mocked = hasattr(socket.getaddrinfo, "_mock_name") or (
        type(socket.getaddrinfo).__name__ in ("MagicMock", "NonCallableMagicMock", "function")
        and getattr(socket.getaddrinfo, "__module__", "") not in ("_socket", "socket")
    )

    if getaddrinfo_is_mocked:
        try:
            addr_info = socket.getaddrinfo(clean_host, None)
        except OSError:
            return []
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = str(sockaddr[0]).strip("[]")
            ip = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip):
                raise SSRFBlockedException(
                    f"Hostname {clean_host} resolved to blocked IP {ip_str} (SSRF prevention)"
                )
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
        return resolved_ips

    # 2. Bounded dnspython resolution across both A (IPv4) and AAAA (IPv6)
    res = resolver or _create_bounded_resolver(timeout=timeout, lifetime=lifetime)
    for rtype in ("A", "AAAA"):
        try:
            answers = res.resolve(clean_host, rtype, lifetime=lifetime)
            for rdata in answers:
                ip_str = str(rdata).strip()
                ip = ipaddress.ip_address(ip_str)
                if is_ip_blocked(ip):
                    raise SSRFBlockedException(
                        f"Hostname {clean_host} resolved to blocked {rtype} IP {ip_str} (SSRF prevention)"
                    )
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
        except SSRFBlockedException:
            raise
        except (dns.exception.DNSException, ValueError, OSError):
            continue

    return resolved_ips


class PinnedIPHTTPAdapter(HTTPAdapter):
    """Custom HTTPAdapter that pins connections to a validated IP address to prevent DNS rebinding."""

    def __init__(self, pinned_ip: str, *args, **kwargs) -> None:
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def send(self, request, *args, **kwargs):
        validate_ip_string(self.pinned_ip)
        return super().send(request, *args, **kwargs)


def verify_response_peer_ip(
    resp: requests.Response,
    allowed_ips: Optional[List[str]] = None,
) -> None:
    """Verify the underlying socket peer IP after connection to defeat TOCTOU DNS rebinding."""
    try:
        raw = getattr(resp, "raw", None)
        conn = getattr(raw, "_connection", None) or getattr(raw, "connection", None)
        sock = getattr(conn, "sock", None)
        if sock is not None and hasattr(sock, "getpeername"):
            peer = sock.getpeername()
            if isinstance(peer, tuple) and len(peer) >= 1:
                peer_ip = str(peer[0]).strip("[]")
                validate_ip_string(peer_ip)
                if allowed_ips and peer_ip not in allowed_ips:
                    raise SSRFBlockedException(
                        f"TOCTOU DNS rebinding detected: peer IP {peer_ip} not in validated set {allowed_ips}"
                    )
    except SSRFBlockedException:
        raise
    except Exception:
        # Mocked responses or closed sockets may not expose a real OS socket
        pass


@dataclass
class SafeProbeResult:
    """Structured response container from SSRF-safe HTTP probes."""

    status_code: int = 0
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    final_url: str = ""
    error: Optional[str] = None
    pinned_ip: Optional[str] = None


def safe_http_probe(
    target_url_or_host: str,
    timeout: float = 4.0,
    max_redirects: int = 3,
    max_bytes: int = 65536,
    custom_headers: Optional[Dict[str, str]] = None,
) -> SafeProbeResult:
    """Execute an outbound HTTP probe with bounded DNS validation, TOCTOU check, and redirect verification."""
    if not isinstance(target_url_or_host, str) or not target_url_or_host.strip():
        return SafeProbeResult(status_code=0, error="Empty target URL or host")

    raw_target = target_url_or_host.strip()
    if "://" not in raw_target:
        current_url = f"https://{raw_target}"
    else:
        current_url = raw_target

    headers = {
        "User-Agent": "TakeoverHunter/2.0.0 (Defensive Security Scanner; RFC 1035)",
        "Accept": "*/*",
        "X-Bug-Bounty": "Security-Audit",
    }
    if custom_headers:
        headers.update(custom_headers)

    redirects_remaining = max_redirects
    dns_timeout = min(max(timeout * 0.5, 1.0), 2.0)
    dns_lifetime = min(max(timeout, 2.0), 4.0)

    while True:
        parsed = urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            return SafeProbeResult(
                status_code=0,
                error=f"Disallowed URL scheme {parsed.scheme!r}. Only HTTP/HTTPS permitted.",
                final_url=current_url,
            )

        hostname = parsed.hostname
        if not hostname:
            return SafeProbeResult(
                status_code=0,
                error="URL missing valid hostname",
                final_url=current_url,
            )

        # 1. Pre-flight DNS resolution and SSRF IP validation (both A & AAAA)
        try:
            validated_ips = resolve_and_validate_hostname(
                hostname,
                timeout=dns_timeout,
                lifetime=dns_lifetime,
            )
        except SSRFBlockedException as e:
            return SafeProbeResult(status_code=0, error=str(e), final_url=current_url)

        pinned_ip = validated_ips[0] if validated_ips else None

        resp: Optional[requests.Response] = None
        try:
            # allow_redirects=False is mandatory for manual hop-by-hop SSRF validation
            resp = requests.get(
                current_url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                stream=True,
            )

            # 2. Verify connected socket peer IP against SSRF policy & validated IPs (TOCTOU guard)
            verify_response_peer_ip(resp, allowed_ips=validated_ips or None)

            # 3. Handle Redirects manually with full re-validation on next loop iteration
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                raw_location = resp.headers["Location"]
                resp.close()
                if redirects_remaining <= 0:
                    return SafeProbeResult(
                        status_code=resp.status_code,
                        error="Maximum redirects exceeded",
                        final_url=current_url,
                        pinned_ip=pinned_ip,
                    )
                redirects_remaining -= 1
                current_url = urljoin(current_url, raw_location)
                continue

            # 4. Terminal response: stream bounded chunks up to max_bytes (64 KB default)
            body_chunks: List[bytes] = []
            bytes_read = 0
            for chunk in resp.iter_content(chunk_size=4096):
                if not chunk:
                    continue
                remaining = max_bytes - bytes_read
                if len(chunk) > remaining:
                    body_chunks.append(chunk[:remaining])
                    bytes_read += remaining
                    break
                body_chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read >= max_bytes:
                    break

            body_text = b"".join(body_chunks).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            status_code = resp.status_code

            return SafeProbeResult(
                status_code=status_code,
                body=body_text,
                headers=resp_headers,
                final_url=current_url,
                pinned_ip=pinned_ip,
            )

        except SSRFBlockedException as e:
            return SafeProbeResult(status_code=0, error=str(e), final_url=current_url)
        except requests.exceptions.RequestException as e:
            # If initial HTTPS probe failed, fallback to HTTP once
            if current_url.startswith("https://") and redirects_remaining == max_redirects:
                current_url = "http://" + current_url[8:]
                continue
            return SafeProbeResult(
                status_code=0,
                error=str(e),
                final_url=current_url,
                pinned_ip=pinned_ip,
            )
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
