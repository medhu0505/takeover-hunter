"""
Unit tests for the deterministic parts of app.py.

Deliberately scoped to logic that doesn't touch the network: fingerprint
matching, SSE framing, and the HackerOne report template. Live-DNS/live-HTTP
paths (is_wildcard, http_probe, enumerate_subdomains_stream, ...) are mocked
where exercised at all -- this suite is not a substitute for testing against
a real target, it's a guard against regressions in the parts a bad diff can
silently break (e.g. a fingerprint typo that stops matching a provider, or a
template edit that drops a field from the submitted report).
"""
import json
from unittest.mock import MagicMock, patch

import pytest

import app as app_module
from app import app as flask_app
from app import match_fingerprint, resolve_cname_chain, sse_event


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


# --- match_fingerprint ------------------------------------------------------

@pytest.mark.parametrize(
    "cname,expected_provider",
    [
        ("foo.herokuapp.com", "Heroku"),
        ("bar.github.io", "GitHub Pages"),
        ("something.s3.amazonaws.com", "AWS S3"),
        ("myapp.netlify.app", "Netlify"),
        ("myapp.vercel.app", "Vercel"),
        ("shop.myshopify.com", "Shopify"),
    ],
)
def test_match_fingerprint_known_providers(cname, expected_provider):
    fp = match_fingerprint(cname)
    assert fp is not None
    assert fp["provider"] == expected_provider


def test_match_fingerprint_unknown_returns_none():
    assert match_fingerprint("origin.internal.example.com") is None


def test_match_fingerprint_is_case_insensitive():
    fp = match_fingerprint("FOO.HEROKUAPP.COM")
    assert fp is not None
    assert fp["provider"] == "Heroku"


def test_fingerprints_have_no_duplicate_patterns():
    seen = {}
    for fp in app_module.FINGERPRINTS:
        for pattern in fp["patterns"]:
            assert pattern not in seen, (
                f"pattern {pattern!r} appears in both "
                f"{seen.get(pattern)!r} and {fp['provider']!r}"
            )
            seen[pattern] = fp["provider"]


# --- sse_event ---------------------------------------------------------------

def test_sse_event_format():
    out = sse_event("progress", {"found": 3})
    assert out.startswith("event: progress\n")
    assert "data: " in out
    assert out.endswith("\n\n")
    payload = json.loads(out.split("data: ", 1)[1].strip())
    assert payload == {"found": 3}


# --- resolve_cname_chain (DNS mocked) -----------------------------------------

def test_resolve_cname_chain_follows_chain_and_stops_on_failure():
    chain = ["a.example.com", "b.herokuapp.com"]

    def fake_resolve(host, rtype):
        if host == "sub.example.com":
            return [MagicMock(target=chain[0] + ".")]
        if host == chain[0]:
            return [MagicMock(target=chain[1] + ".")]
        raise app_module.dns.exception.DNSException("no more records")

    with patch.object(app_module.resolver, "resolve", side_effect=fake_resolve):
        result = resolve_cname_chain("sub.example.com")

    assert result == chain


def test_resolve_cname_chain_empty_when_no_cname():
    with patch.object(
        app_module.resolver, "resolve",
        side_effect=app_module.dns.exception.DNSException("nope"),
    ):
        assert resolve_cname_chain("sub.example.com") == []


# --- /api/report ---------------------------------------------------------------

def test_api_report_includes_all_finding_fields(client):
    finding = {
        "sub": "old.example.com",
        "cname": "ghost-app.herokuapp.com",
        "provider": "Heroku",
        "nxdomain": True,
        "body_match": False,
        "claimable": True,
        "free_account": True,
        "severity": "High",
        "confidence": "high",
        "http_code": 404,
    }
    resp = client.post(
        "/api/report",
        data=json.dumps({
            "finding": finding,
            "h1_user": "stickybugger",
            "platform": "HackerOne",
        }),
        content_type="application/json",
    )
    assert resp.status_code == 200
    report = resp.get_json()["report"]

    assert "old.example.com" in report
    assert "ghost-app.herokuapp.com" in report
    assert "Heroku" in report
    assert "NXDOMAIN confirmed" in report
    assert "Free PoC possible" in report
    assert "HackerOne: @stickybugger" in report


def test_api_report_handles_missing_optional_fields(client):
    resp = client.post(
        "/api/report",
        data=json.dumps({"finding": {"sub": "x.example.com"}}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert "x.example.com" in resp.get_json()["report"]


# --- Target Sanitization & Endpoints -----------------------------------------

def test_is_safe_target_valid():
    assert app_module.is_safe_target("example.com") is True
    assert app_module.is_safe_target("sub.domain.example.co.uk") is True
    assert app_module.is_safe_target("api-v2.cloud.internal") is True


def test_is_safe_target_rejects_dangerous_input():
    assert app_module.is_safe_target("; cat /etc/passwd") is False
    assert app_module.is_safe_target("test.com | rm -rf") is False
    assert app_module.is_safe_target("$(whoami).example.com") is False
    assert app_module.is_safe_target("`id`.example.com") is False
    assert app_module.is_safe_target("") is False


def test_api_tools_endpoint(client):
    resp = client.get("/api/tools")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "subfinder" in data
    assert "httpx" in data


def test_api_quickscan_requires_cname(client):
    resp = client.post(
        "/api/quickscan",
        data=json.dumps({"sub": "sub.example.com"}),
        content_type="application/json",
    )
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_api_dns_unsupported_type(client):
    resp = client.post(
        "/api/dns",
        data=json.dumps({"host": "example.com", "type": "INVALID_TYPE"}),
        content_type="application/json",
    )
    assert resp.status_code == 400
    assert "error" in resp.get_json()

