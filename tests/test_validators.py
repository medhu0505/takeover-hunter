"""Tests for RFC 1035 validator and command injection prevention."""
from __future__ import annotations

import pytest

from takeover_hunter.validators import (
    is_valid_hostname,
    validate_domain,
    validate_subdomain_list,
)


@pytest.mark.parametrize(
    "hostname",
    [
        "example.com",
        "sub.example.com",
        "deep.nested.sub.domain.co.uk",
        "a.com",
        "123.com",
        "my-host-name.org",
        "sub-domain.example.com",
        "example.com.",
        "xn--bcher-kva.example",
        "api-v2.internal.service.io",
    ],
)
def test_valid_hostnames(hostname):
    assert is_valid_hostname(hostname) is True
    assert validate_domain(hostname).rstrip(".") == hostname.lower().rstrip(".")


@pytest.mark.parametrize(
    "injected_input",
    [
        "example.com; id",
        "example.com;rm -rf /",
        "example.com | whoami",
        "example.com || cat /etc/passwd",
        "example.com && ping 127.0.0.1",
        "example.com & sleep 10",
        "`id`.example.com",
        "$(whoami).example.com",
        "example.com`cat /etc/shadow`",
        "example.com$(ls -la)",
        "example.com > /tmp/pwn",
        "example.com < /etc/hosts",
        "example.com\nid",
        "example.com\r\nid",
        "example.com\t--flag",
        "example.com id",
        "example.com' OR 1=1--",
        'example.com" OR 1=1--',
        "example.com\\malicious",
        "example.com/api/v1",
        "example.com?query=1",
        "example.com#fragment",
        "example.com!test",
        "example.com*wildcard",
        "example.com+plus",
        "example.com=equal",
        "example.com~tilde",
        "example.com^caret",
        "example.com%20encoded",
        "example.com(paren)",
        "example.com[bracket]",
        "example.com{brace}",
    ],
)
def test_shell_metacharacters_rejected(injected_input):
    assert is_valid_hostname(injected_input) is False
    with pytest.raises(ValueError, match="Invalid domain format"):
        validate_domain(injected_input)


@pytest.mark.parametrize(
    "flag_input",
    [
        "-v",
        "-d",
        "--help",
        "--target=example.com",
        "-o/tmp/out",
        "-rf",
    ],
)
def test_flags_rejected(flag_input):
    assert is_valid_hostname(flag_input) is False
    with pytest.raises(ValueError, match="Invalid domain format"):
        validate_domain(flag_input)


def test_label_length_at_limit_63():
    label_63 = "a" * 63
    domain = f"{label_63}.example.com"
    assert is_valid_hostname(domain) is True


def test_label_length_exceeded_64():
    label_64 = "a" * 64
    domain = f"{label_64}.example.com"
    assert is_valid_hostname(domain) is False
    with pytest.raises(ValueError, match="Invalid domain format"):
        validate_domain(domain)


def test_domain_total_length_exceeded_254():
    sub = ("a" * 60 + ".") * 4 + "example.com"
    assert len(sub) > 253
    assert is_valid_hostname(sub) is False
    with pytest.raises(ValueError, match="Invalid domain format"):
        validate_domain(sub)


def test_label_leading_hyphen_rejected():
    assert is_valid_hostname("-sub.example.com") is False
    assert is_valid_hostname("sub.-example.com") is False


def test_label_trailing_hyphen_rejected():
    assert is_valid_hostname("sub-.example.com") is False
    assert is_valid_hostname("sub.example-.com") is False


def test_empty_labels_rejected():
    assert is_valid_hostname("sub..example.com") is False
    assert is_valid_hostname(".example.com") is False
    assert is_valid_hostname("") is False
    assert is_valid_hostname("   ") is False
    assert is_valid_hostname("example.com.", allow_trailing_dot=False) is False


def test_validate_domain_empty_rejected():
    with pytest.raises(ValueError, match="Domain cannot be empty"):
        validate_domain("   ")


def test_numeric_tld_rejected():
    with pytest.raises(ValueError, match="Top-level domain cannot be purely numeric"):
        validate_domain("example.123")


def test_single_label_domain_rejected_by_validate_domain():
    with pytest.raises(ValueError, match="Domain must contain at least a name and TLD"):
        validate_domain("localhost")


def test_non_string_inputs_handled():
    assert is_valid_hostname(None) is False  # type: ignore
    assert is_valid_hostname(12345) is False  # type: ignore
    assert is_valid_hostname(["example.com"]) is False  # type: ignore
    with pytest.raises(ValueError, match="Domain must be a string"):
        validate_domain(None)  # type: ignore


def test_validate_subdomain_list_empty():
    assert validate_subdomain_list([]) == []
    assert validate_subdomain_list(None) == []  # type: ignore


def test_validate_subdomain_list_filters_and_deduplicates():
    inputs = [
        "https://sub1.example.com/path",
        "http://sub2.example.com:8080",
        "SUB1.EXAMPLE.COM",
        "valid.example.com",
        "invalid;injection.com",
        "-flag.example.com",
        "",
        "   ",
        None,
        123,
    ]
    result = validate_subdomain_list(inputs, max_count=50)  # type: ignore
    assert result == ["sub1.example.com", "sub2.example.com", "valid.example.com"]


def test_validate_subdomain_list_caps_output():
    subs = [f"sub{i}.example.com" for i in range(100)]
    capped = validate_subdomain_list(subs, max_count=10)
    assert len(capped) == 10
