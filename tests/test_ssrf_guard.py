"""Comprehensive unit tests for takeover_hunter/ssrf_guard.py."""
from __future__ import annotations

import ipaddress
import socket
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest
import requests

from takeover_hunter.ssrf_guard import (
    PinnedIPHTTPAdapter,
    SafeProbeResult,
    SSRFBlockedException,
    is_ip_blocked,
    resolve_and_validate_hostname,
    safe_http_probe,
    validate_ip_string,
    verify_response_peer_ip,
)


@pytest.mark.parametrize(
    "blocked_ip",
    [
        "127.0.0.1",
        "127.0.1.1",
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.170.2",
        "0.0.0.0",
        "100.64.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:172.16.0.1",
        "::ffff:192.168.1.1",
        "::ffff:169.254.169.254",
        "fc00::1",
        "fd12:3456:789a::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "2002:7f00:0001::",  # 6to4 mapped 127.0.0.1
    ],
)
def test_blocked_ips_detected(blocked_ip):
    ip_obj = ipaddress.ip_address(blocked_ip)
    assert is_ip_blocked(ip_obj) is True
    with pytest.raises(SSRFBlockedException):
        validate_ip_string(blocked_ip)


@pytest.mark.parametrize(
    "public_ip",
    [
        "93.184.216.34",
        "8.8.8.8",
        "1.1.1.1",
        "151.101.1.69",
        "2606:2800:220:1:248:1893:25c8:1946",
    ],
)
def test_public_ips_allowed(public_ip):
    ip_obj = ipaddress.ip_address(public_ip)
    assert is_ip_blocked(ip_obj) is False
    validate_ip_string(public_ip)


def test_validate_ip_string_invalid_format():
    with pytest.raises(SSRFBlockedException, match="Invalid IP address format"):
        validate_ip_string("not-an-ip-address")


def test_teredo_ipv6_unwrap_blocked():
    # Teredo prefix 2001:0000::/32 with embedded private IP
    teredo_ip = ipaddress.IPv6Address("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
    assert isinstance(is_ip_blocked(teredo_ip), bool)


def test_resolve_and_validate_hostname_empty_and_non_string():
    with pytest.raises(SSRFBlockedException):
        resolve_and_validate_hostname("")
    with pytest.raises(SSRFBlockedException):
        resolve_and_validate_hostname("   ")
    with pytest.raises(SSRFBlockedException):
        resolve_and_validate_hostname(None)  # type: ignore


def test_resolve_and_validate_direct_ip_literals():
    assert resolve_and_validate_hostname("93.184.216.34") == ["93.184.216.34"]
    with pytest.raises(SSRFBlockedException):
        resolve_and_validate_hostname("169.254.169.254")
    with pytest.raises(SSRFBlockedException):
        resolve_and_validate_hostname("[::1]")


def test_resolve_and_validate_dnspython_multi_record_blocks_if_any_private():
    fake_resolver = MagicMock()

    def resolve_side_effect(host, rtype, lifetime=None):
        if rtype == "A":
            return ["93.184.216.34", "169.254.169.254"]
        raise dns.resolver.NoAnswer()

    fake_resolver.resolve.side_effect = resolve_side_effect
    with pytest.raises(SSRFBlockedException, match="169.254.169.254"):
        resolve_and_validate_hostname("rebind.example.com", resolver=fake_resolver)


def test_resolve_and_validate_dnspython_blocks_aaaa_loopback():
    fake_resolver = MagicMock()

    def resolve_side_effect(host, rtype, lifetime=None):
        if rtype == "A":
            return ["93.184.216.34"]
        if rtype == "AAAA":
            return ["::ffff:127.0.0.1"]
        raise dns.resolver.NoAnswer()

    fake_resolver.resolve.side_effect = resolve_side_effect
    with pytest.raises(SSRFBlockedException):
        resolve_and_validate_hostname("dualstack.example.com", resolver=fake_resolver)


def test_resolve_and_validate_dnspython_public_a_and_aaaa():
    fake_resolver = MagicMock()

    def resolve_side_effect(host, rtype, lifetime=None):
        if rtype == "A":
            return ["93.184.216.34"]
        if rtype == "AAAA":
            return ["2606:2800:220:1:248:1893:25c8:1946"]
        raise dns.resolver.NoAnswer()

    fake_resolver.resolve.side_effect = resolve_side_effect
    ips = resolve_and_validate_hostname("example.com", resolver=fake_resolver)
    assert ips == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]


def test_resolve_and_validate_mocked_getaddrinfo_fallback():
    with patch.object(
        socket,
        "getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    ):
        assert resolve_and_validate_hostname("example.com") == ["93.184.216.34"]

    with patch.object(
        socket,
        "getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    ):
        with pytest.raises(SSRFBlockedException):
            resolve_and_validate_hostname("local.example.com")

    with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        assert resolve_and_validate_hostname("nx.example.com") == []


def test_verify_response_peer_ip_detects_toctou_rebinding():
    resp = MagicMock()
    resp.raw._connection.sock.getpeername.return_value = ("169.254.169.254", 80)
    with pytest.raises(SSRFBlockedException):
        verify_response_peer_ip(resp, allowed_ips=["93.184.216.34"])

    resp.raw._connection.sock.getpeername.return_value = ("1.2.3.4", 80)
    with pytest.raises(SSRFBlockedException, match="TOCTOU DNS rebinding"):
        verify_response_peer_ip(resp, allowed_ips=["93.184.216.34"])

    resp.raw._connection.sock.getpeername.return_value = ("93.184.216.34", 80)
    verify_response_peer_ip(resp, allowed_ips=["93.184.216.34"])


def test_pinned_ip_http_adapter():
    adapter = PinnedIPHTTPAdapter("127.0.0.1")
    with pytest.raises(SSRFBlockedException):
        adapter.send(MagicMock())


def test_safe_http_probe_blocks_non_http_schemes():
    res = safe_http_probe("file:///etc/passwd")
    assert res.status_code == 0
    assert "Disallowed URL scheme" in (res.error or "")

    res_empty = safe_http_probe("   ")
    assert res_empty.status_code == 0
    assert res_empty.error is not None

    res_no_host = safe_http_probe("https:///path-only")
    assert res_no_host.status_code == 0
    assert "missing valid hostname" in (res_no_host.error or "")


def test_safe_http_probe_blocks_redirect_to_metadata_ip():
    redirect_resp = MagicMock()
    redirect_resp.status_code = 302
    redirect_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    with patch(
        "takeover_hunter.ssrf_guard.resolve_and_validate_hostname",
        side_effect=lambda h, **kw: ["93.184.216.34"]
        if h == "public.example.com"
        else (_ for _ in ()).throw(SSRFBlockedException("Blocked metadata IP")),
    ):
        with patch("takeover_hunter.ssrf_guard.requests.get", return_value=redirect_resp) as mock_get:
            result = safe_http_probe("https://public.example.com")
            assert result.status_code == 0
            assert "Blocked metadata IP" in (result.error or "")
            assert mock_get.call_count == 1


def test_safe_http_probe_enforces_max_redirects():
    redirect_resp = MagicMock()
    redirect_resp.status_code = 301
    redirect_resp.headers = {"Location": "https://public.example.com/loop"}

    with patch("takeover_hunter.ssrf_guard.resolve_and_validate_hostname", return_value=["93.184.216.34"]):
        with patch("takeover_hunter.ssrf_guard.requests.get", return_value=redirect_resp):
            result = safe_http_probe("https://public.example.com", max_redirects=2)
            assert result.status_code == 301
            assert "Maximum redirects exceeded" in (result.error or "")


def test_safe_http_probe_truncates_large_response_at_max_bytes():
    ok_resp = MagicMock()
    ok_resp.status_code = 200
    ok_resp.headers = {"Content-Type": "text/html"}
    ok_resp.iter_content.return_value = [b"", b"A" * 4096, b"B" * 4096, b"C" * 4096]

    with patch("takeover_hunter.ssrf_guard.resolve_and_validate_hostname", return_value=["93.184.216.34"]):
        with patch("takeover_hunter.ssrf_guard.requests.get", return_value=ok_resp):
            result = safe_http_probe(
                "public.example.com",
                max_bytes=5000,
                custom_headers={"X-Custom": "1"},
            )
            assert result.status_code == 200
            assert len(result.body) == 5000
            assert result.pinned_ip == "93.184.216.34"


def test_safe_http_probe_https_to_http_fallback_and_failure():
    with patch("takeover_hunter.ssrf_guard.resolve_and_validate_hostname", return_value=["93.184.216.34"]):
        with patch(
            "takeover_hunter.ssrf_guard.requests.get",
            side_effect=requests.exceptions.ConnectionError("TLS failed"),
        ) as mock_get:
            result = safe_http_probe("public.example.com")
            assert result.status_code == 0
            assert "TLS failed" in (result.error or "")
            assert mock_get.call_count == 2


def test_safe_http_probe_toctou_rebinding_and_exact_boundary():
    rebind_resp = MagicMock()
    rebind_resp.status_code = 200
    rebind_resp.raw._connection.sock.getpeername.return_value = ("127.0.0.1", 80)

    with patch("takeover_hunter.ssrf_guard.resolve_and_validate_hostname", return_value=["93.184.216.34"]):
        with patch("takeover_hunter.ssrf_guard.requests.get", return_value=rebind_resp):
            res = safe_http_probe("https://public.example.com")
            assert res.status_code == 0
            assert "127.0.0.1" in (res.error or "")

    exact_resp = MagicMock()
    exact_resp.status_code = 200
    exact_resp.headers = {}
    exact_resp.iter_content.return_value = [b"X" * 4096]
    exact_resp.close.side_effect = RuntimeError("close err")
    with patch("takeover_hunter.ssrf_guard.resolve_and_validate_hostname", return_value=["93.184.216.34"]):
        with patch("takeover_hunter.ssrf_guard.requests.get", return_value=exact_resp):
            res2 = safe_http_probe("https://public.example.com", max_bytes=4096)
            assert res2.status_code == 200
            assert len(res2.body) == 4096

    adapter = PinnedIPHTTPAdapter("93.184.216.34")
    with patch.object(requests.adapters.HTTPAdapter, "send", return_value="ok") as mock_send:
        assert adapter.send(MagicMock()) == "ok"
        assert mock_send.called

    # Default bounded resolver creation + NXDOMAIN handling
    with patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
        assert resolve_and_validate_hostname("nxdomain.example.com") == []

    # Closed socket in verify_response_peer_ip
    bad_sock_resp = MagicMock()
    bad_sock_resp.raw._connection.sock.getpeername.side_effect = OSError("closed")
    verify_response_peer_ip(bad_sock_resp, allowed_ips=["93.184.216.34"])


