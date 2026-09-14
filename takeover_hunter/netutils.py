"""DNS resolution and guarded HTTP probing.

This module owns all outbound network I/O against scan targets. Two safety
properties are enforced here:

1. An SSRF guard (:func:`target_is_probeable`) rejects any host that resolves
   into private, loopback, link-local, or otherwise reserved IP space before
   an HTTP request is issued. This stops the hosted service from being used to
   reach internal infrastructure or cloud metadata endpoints
   (``169.254.169.254``). Hosts that do not resolve at all are allowed, since
   an unresolvable CNAME target is exactly the takeover signal we look for.

2. Response bodies are truncated to a configured cap so a hostile target
   cannot exhaust memory.

Callers pass a :class:`~takeover_hunter.config.Config`; nothing here reads
module-level globals, which keeps the network policy testable.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

import dns.exception
import dns.resolver
import requests
import urllib3

from takeover_hunter.config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def build_resolver(config: Config) -> dns.resolver.Resolver:
    """Construct a DNS resolver configured from ``config``."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = list(config.resolvers)
    resolver.timeout = config.dns_timeout
    resolver.lifetime = config.dns_lifetime
    return resolver


class DNSClient:
    """Thin wrapper over :class:`dns.resolver.Resolver` with tidy helpers.

    All lookups swallow the expected DNS exceptions and return neutral values
    (``None`` / empty list / ``False``) so callers in streaming worker threads
    never have to guard every query. Genuinely unexpected errors are also
    contained — a scan of thousands of hosts must not die on one bad record.
    """

    def __init__(self, config: Config):
        self._config = config
        self._resolver = build_resolver(config)

    # --- record lookups -------------------------------------------------
    def resolve_a(self, host: str) -> List[str]:
        """Return the A records for ``host`` (empty list on any failure)."""
        try:
            return [str(r) for r in self._resolver.resolve(host, "A")]
        except (dns.exception.DNSException, Exception):
            return []

    def resolve_cname(self, host: str) -> Optional[str]:
        """Return the immediate CNAME target for ``host`` (or ``None``)."""
        try:
            answer = self._resolver.resolve(host, "CNAME")
            return str(answer[0].target).rstrip(".")
        except (dns.exception.DNSException, Exception):
            return None

    def resolve_cname_chain(self, host: str, max_depth: int = 5) -> List[str]:
        """Follow the CNAME chain from ``host`` up to ``max_depth`` hops."""
        chain: List[str] = []
        current = host
        for _ in range(max_depth):
            try:
                answer = self._resolver.resolve(current, "CNAME")
            except (dns.exception.DNSException, Exception):
                break
            target = str(answer[0].target).rstrip(".")
            chain.append(target)
            current = target
        return chain

    def is_nxdomain(self, host: str) -> bool:
        """True only if ``host`` authoritatively does not exist (NXDOMAIN)."""
        try:
            self._resolver.resolve(host, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except (dns.exception.DNSException, Exception):
            return False

    def is_wildcard(self, domain: str) -> bool:
        """Detect wildcard DNS by resolving a random label under ``domain``."""
        import time

        probe = f"takeover-hunter-wildcard-{int(time.time())}.{domain}"
        try:
            self._resolver.resolve(probe, "A")
            return True
        except (dns.exception.DNSException, Exception):
            return False

    def resolves_private(self, host: str) -> bool:
        """True if ``host`` resolves to any non-public (reserved) address."""
        for record in self.resolve_a(host):
            try:
                ip = ipaddress.ip_address(record)
            except ValueError:
                continue
            if not ip.is_global:
                return True
        return False


def target_is_probeable(dns_client: DNSClient, host: str, config: Config) -> bool:
    """SSRF guard: may we issue an HTTP request to ``host``?

    Returns ``True`` unless the host resolves into reserved address space and
    private targets are disallowed by configuration.
    """
    if config.allow_private_targets:
        return True
    return not dns_client.resolves_private(host)


def http_probe(host: str, config: Config, dns_client: Optional[DNSClient] = None) -> Dict:
    """Fetch ``host`` over HTTPS then HTTP, returning a normalised result.

    The result dict always has ``code`` (int, ``0`` on total failure),
    ``body`` (truncated str), and ``headers`` (dict). When an SSRF guard is
    available and the host resolves privately, the probe is skipped with a
    ``blocked`` flag rather than reaching internal infrastructure.
    """
    if dns_client is not None and not target_is_probeable(dns_client, host, config):
        return {"code": 0, "body": "", "headers": {}, "blocked": True}

    headers = {
        "User-Agent": config.user_agent,
        "X-Bug-Bounty": config.bug_bounty_header,
    }
    for scheme in ("https", "http"):
        try:
            response = requests.get(
                f"{scheme}://{host}",
                timeout=config.http_timeout,
                verify=False,
                allow_redirects=True,
                headers=headers,
            )
            return {
                "code": response.status_code,
                "body": response.text[: config.http_body_cap],
                "headers": dict(response.headers),
            }
        except requests.RequestException:
            continue
    return {"code": 0, "body": "", "headers": {}}


def http_alive(host: str, config: Config) -> bool:
    """Cheap liveness check via HEAD — avoids downloading a body."""
    for scheme in ("https", "http"):
        try:
            response = requests.head(
                f"{scheme}://{host}",
                timeout=max(1, config.http_timeout - 1),
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": config.user_agent},
            )
            if response.status_code not in (0, 502, 503, 504):
                return True
        except requests.RequestException:
            continue
    return False
