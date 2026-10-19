"""Core integration tests for Takeover Hunter v2.0.0 and app/wsgi entrypoints."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import dns.exception
import pytest

import app as app_entrypoint
import takeover_hunter as th
from takeover_hunter import (
    FINGERPRINTS,
    create_app,
    default_resolver,
    is_safe_target,
    match_fingerprint,
    resolve_cname_chain,
    sse_event,
)
import wsgi as wsgi_entrypoint


@pytest.fixture
def client():
    flask_app = create_app({"TESTING": True, "RATE_LIMIT_PER_MINUTE": 10000})
    with flask_app.test_client() as c:
        yield c


def test_app_and_wsgi_entrypoints_expose_unified_factory():
    assert hasattr(app_entrypoint, "app")
    assert hasattr(wsgi_entrypoint, "app")
    assert app_entrypoint.app.blueprints.keys() == wsgi_entrypoint.app.blueprints.keys()
    assert "api" in app_entrypoint.app.blueprints


def test_root_app_py_is_thin_entrypoint():
    app_py_lines = Path("/app/applet/app.py").read_text(encoding="utf-8").strip().splitlines()
    assert len(app_py_lines) <= 15
    assert "from takeover_hunter import create_app" in "\n".join(app_py_lines)


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
    for fp in FINGERPRINTS:
        for pattern in fp["patterns"]:
            assert pattern not in seen, (
                f"pattern {pattern!r} appears in both "
                f"{seen.get(pattern)!r} and {fp['provider']!r}"
            )
            seen[pattern] = fp["provider"]


def test_sse_event_format():
    out = sse_event("progress", {"found": 3})
    assert out.startswith("event: progress\n")
    assert "data: " in out
    assert out.endswith("\n\n")
    payload = json.loads(out.split("data: ", 1)[1].strip())
    assert payload == {"found": 3}


def test_resolve_cname_chain_follows_chain_and_stops_on_failure():
    chain = ["a.example.com", "b.herokuapp.com"]

    def fake_resolve(host, rtype):
        if host == "sub.example.com":
            return [MagicMock(target=chain[0] + ".")]
        if host == chain[0]:
            return [MagicMock(target=chain[1] + ".")]
        raise dns.exception.DNSException("no more records")

    with patch.object(default_resolver, "resolve", side_effect=fake_resolve):
        result = resolve_cname_chain("sub.example.com")

    assert result == chain


def test_resolve_cname_chain_empty_when_no_cname():
    with patch.object(
        default_resolver,
        "resolve",
        side_effect=dns.exception.DNSException("nope"),
    ):
        assert resolve_cname_chain("sub.example.com") == []


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
    data = resp.get_json()
    report = data["report"]
    assert "old.example.com" in report
    assert "ghost-app.herokuapp.com" in report
    assert "Heroku" in report
    assert "NXDOMAIN confirmed" in report
    assert "Free PoC possible" in report
    assert "HackerOne: @stickybugger" in report
    assert "bugcrowd_report" in data


def test_api_report_handles_missing_optional_fields(client):
    resp = client.post(
        "/api/report",
        data=json.dumps({"finding": {"sub": "x.example.com"}}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert "x.example.com" in resp.get_json()["report"]


def test_is_safe_target_valid():
    assert is_safe_target("example.com") is True
    assert is_safe_target("sub.domain.example.co.uk") is True
    assert is_safe_target("api-v2.cloud.internal") is True


def test_is_safe_target_rejects_dangerous_input():
    assert is_safe_target("; cat /etc/passwd") is False
    assert is_safe_target("test.com | rm -rf") is False
    assert is_safe_target("$(whoami).example.com") is False
    assert is_safe_target("`id`.example.com") is False
    assert is_safe_target("") is False


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


def test_template_dom_xss_hardening():
    html = Path("/app/applet/templates/index.html").read_text(encoding="utf-8")
    assert ".replace(/\"/g,'&quot;').replace(/'/g,'&#39;')" in html
    assert "onclick=\"selectResult('vuln',this,${JSON.stringify" not in html
    assert "onclick=\"showReport(${JSON.stringify" not in html
