"""DNS client and SSRF-guard tests (network mocked)."""
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from takeover_hunter.config import Config
from takeover_hunter.netutils import DNSClient, http_probe, target_is_probeable


def _client():
    return DNSClient(Config())


def test_resolve_cname_chain_follows_and_stops():
    client = _client()
    chain = ["a.example.com", "b.herokuapp.com"]

    def fake(host, rtype):
        if host == "sub.example.com":
            return [MagicMock(target=chain[0] + ".")]
        if host == chain[0]:
            return [MagicMock(target=chain[1] + ".")]
        raise dns.exception.DNSException("end")

    with patch.object(client._resolver, "resolve", side_effect=fake):
        assert client.resolve_cname_chain("sub.example.com") == chain


def test_resolve_cname_chain_empty_when_none():
    client = _client()
    with patch.object(client._resolver, "resolve", side_effect=dns.exception.DNSException("no")):
        assert client.resolve_cname_chain("sub.example.com") == []


def test_is_nxdomain_true_only_on_nxdomain():
    client = _client()
    with patch.object(client._resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
        assert client.is_nxdomain("gone.example.com") is True
    with patch.object(client._resolver, "resolve", side_effect=dns.exception.Timeout()):
        assert client.is_nxdomain("slow.example.com") is False
    with patch.object(client._resolver, "resolve", return_value=[MagicMock()]):
        assert client.is_nxdomain("live.example.com") is False


def test_resolves_private_detects_reserved_space():
    client = _client()
    with patch.object(client, "resolve_a", return_value=["10.0.0.5"]):
        assert client.resolves_private("internal.example.com") is True
    with patch.object(client, "resolve_a", return_value=["169.254.169.254"]):
        assert client.resolves_private("metadata.example.com") is True
    with patch.object(client, "resolve_a", return_value=["93.184.216.34"]):
        assert client.resolves_private("public.example.com") is False


def test_ssrf_guard_blocks_private_by_default():
    client = _client()
    config = Config(allow_private_targets=False)
    with patch.object(client, "resolves_private", return_value=True):
        assert target_is_probeable(client, "internal", config) is False
    config_allow = Config(allow_private_targets=True)
    with patch.object(client, "resolves_private", return_value=True):
        assert target_is_probeable(client, "internal", config_allow) is True


def test_http_probe_skipped_for_private_target():
    client = _client()
    config = Config(allow_private_targets=False)
    with patch.object(client, "resolves_private", return_value=True):
        result = http_probe("internal.example.com", config, client)
    assert result["blocked"] is True
    assert result["code"] == 0


def test_http_probe_returns_normalised_result():
    client = _client()
    config = Config(allow_private_targets=True, http_body_cap=10)
    fake_resp = MagicMock(status_code=200, text="x" * 100, headers={"Server": "nginx"})
    with patch("takeover_hunter.netutils.requests.get", return_value=fake_resp):
        result = http_probe("live.example.com", config, client)
    assert result["code"] == 200
    assert len(result["body"]) == 10  # truncated to cap
    assert result["headers"]["Server"] == "nginx"
