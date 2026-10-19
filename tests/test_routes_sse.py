"""Unit tests for routes, SSE streaming, workload caps, dns_triage, and enumerator."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from takeover_hunter import create_app
from takeover_hunter.dns_triage import (
    check_nxdomain,
    create_resolver,
    is_wildcard,
    resolve_a,
    triage_subdomain,
    triage_subdomain_bulk,
)
from takeover_hunter.enumerator import (
    enumerate_subdomains,
    probe_with_httpx,
    run_binary_safe,
)
from takeover_hunter.ssrf_guard import SafeProbeResult
from takeover_hunter.verifier import Finding


@pytest.fixture
def client():
    app = create_app({
        "TESTING": True,
        "RATE_LIMIT_PER_MINUTE": 10000,
        "MAX_SUBDOMAINS_PER_SCAN": 5,
    })
    with app.test_client() as c:
        yield c


def test_index_and_health_and_signatures_endpoints(client):
    r_index = client.get("/")
    assert r_index.status_code == 200

    r_health = client.get("/api/healthz")
    assert r_health.status_code == 200
    assert r_health.get_json()["status"] == "ok"

    r_sigs = client.get("/api/signatures")
    assert r_sigs.status_code == 200
    assert len(r_sigs.get_json()) == 26

    r_404 = client.get("/api/does-not-exist")
    assert r_404.status_code == 404


def test_enumerate_sse_and_invalid_domain(client):
    r_bad = client.get("/api/enumerate?target=-invalid")
    assert r_bad.status_code == 400

    with patch("takeover_hunter.routes.is_wildcard", return_value=True), \
         patch(
             "takeover_hunter.routes.enumerate_subdomains",
             return_value=([f"s{i}.example.com" for i in range(10)], ["subfinder: found 10"]),
         ):
        r_ok = client.get("/api/enumerate?target=example.com")
        assert r_ok.status_code == 200
        text = r_ok.get_data(as_text=True)
        assert "event: done" in text
        # Enforces MAX_SUBDOMAINS_PER_SCAN=5 cap
        assert '"count": 5' in text


def test_triage_sse_and_workload_cap(client):
    r_bad = client.post("/api/triage", json={"subdomains": "not-a-list"})
    assert r_bad.status_code == 400

    r_empty = client.post("/api/triage", json={"subdomains": []})
    assert r_empty.status_code == 200
    assert "event: done" in r_empty.get_data(as_text=True)

    with patch(
        "takeover_hunter.routes.triage_subdomain",
        return_value={
            "sub": "sub.example.com",
            "has_cname": True,
            "cname": "app.herokuapp.com",
            "final_target": "app.herokuapp.com",
            "chain": ["app.herokuapp.com"],
            "nxdomain": False,
            "type": "cname",
        },
    ):
        subs = [f"sub{i}.example.com" for i in range(12)]
        r_ok = client.post("/api/triage", json={"subdomains": subs})
        assert r_ok.status_code == 200
        body = r_ok.get_data(as_text=True)
        assert '"total": 5' in body
        assert "event: done" in body


def test_scan_sse_and_workload_cap(client):
    r_bad = client.post("/api/scan", json={"cname_records": "invalid"})
    assert r_bad.status_code == 400

    fake_finding = Finding(
        sub="a.example.com",
        cname="ghost.herokuapp.com",
        provider="Heroku",
        claimable=True,
        free_account=True,
        nxdomain=False,
        http_code=404,
        body_match=True,
        match_string="No such app",
        vulnerable=True,
        confidence="high",
        severity="High",
        poc_guidance="",
    )
    recs = [{"sub": f"s{i}.example.com", "cname": "ghost.herokuapp.com", "claimable": True} for i in range(10)]
    with patch("takeover_hunter.routes.assess_target", return_value=fake_finding):
        r_ok = client.post(
            "/api/scan",
            json={"cname_records": recs, "provider_filter": ["Heroku"], "claimable_only": True},
        )
        assert r_ok.status_code == 200
        body = r_ok.get_data(as_text=True)
        assert '"total": 5' in body
        assert "event: vuln" in body


def test_bulkurlscan_sse_and_workload_cap(client):
    r_bad = client.post("/api/bulkurlscan", json={"urls": "not-a-list"})
    assert r_bad.status_code == 400

    urls = [f"https://sub{i}.example.com/login" for i in range(10)]
    with patch("takeover_hunter.routes.resolve_cname_chain", return_value=["app.herokuapp.com"]), \
         patch("takeover_hunter.routes.assess_target", return_value=None):
        r_ok = client.post("/api/bulkurlscan", json={"urls": urls})
        assert r_ok.status_code == 200
        body = r_ok.get_data(as_text=True)
        assert '"total": 5' in body
        assert "event: done" in body


def test_verify_sse_and_workload_cap(client):
    r_bad = client.post("/api/verify", json={"vulnerable": "not-a-list"})
    assert r_bad.status_code == 400

    vuln_items = [
        {
            "sub": f"v{i}.example.com",
            "cname": "app.herokuapp.com",
            "provider": "Heroku",
            "nxdomain": False,
            "http_code": 404,
            "body_match": True,
            "match_string": "No such app",
        }
        for i in range(8)
    ]
    with patch("takeover_hunter.routes.verify_finding", side_effect=lambda f, **kw: f):
        r_ok = client.post("/api/verify", json={"vulnerable": vuln_items})
        assert r_ok.status_code == 200
        body = r_ok.get_data(as_text=True)
        assert "event: verified" in body
        assert "event: done" in body


def test_jsrecon_and_archive_sse(client):
    assert client.post("/api/jsrecon", json={"target": "bad;host"}).status_code == 400
    assert client.post("/api/jsrecon", json={"target": "example.com", "subdomains": "bad"}).status_code == 400
    assert client.post("/api/archive", json={"target": "bad;host"}).status_code == 400

    fake_js = SafeProbeResult(status_code=200, body='const api_key = "ABCDEF1234567890";')
    with patch("takeover_hunter.routes.safe_http_probe", return_value=fake_js):
        r_js = client.post("/api/jsrecon", json={"target": "example.com", "subdomains": ["a.example.com"]})
        assert r_js.status_code == 200
        text = r_js.get_data(as_text=True)
        assert "event: secret" in text
        assert "event: done" in text

    with patch("takeover_hunter.routes.run_binary_safe", return_value=([], None)):
        r_arch = client.post("/api/archive", json={"target": "example.com"})
        assert r_arch.status_code == 200
        assert "event: done" in r_arch.get_data(as_text=True)


def test_quickscan_and_dns_routes(client):
    with patch("takeover_hunter.routes.assess_target", return_value=None):
        r_qs = client.post("/api/quickscan", json={"sub": "sub.example.com", "cname": "app.herokuapp.com"})
        assert r_qs.status_code == 200
        assert r_qs.get_json()["vulnerable"] is False

    fake_res = MagicMock()
    fake_res.resolve.return_value = ["93.184.216.34"]
    with patch("takeover_hunter.routes.create_resolver", return_value=fake_res):
        r_dns = client.post("/api/dns", json={"host": "example.com", "type": "A"})
        assert r_dns.status_code == 200
        assert r_dns.get_json()["records"] == ["93.184.216.34"]


def test_dns_triage_isolated_resolvers_and_bulk():
    r1 = create_resolver()
    r2 = create_resolver()
    assert r1 is not r2

    fake_res = MagicMock()
    fake_res.resolve.side_effect = dns.resolver.NXDOMAIN()
    assert is_wildcard("example.com", resolver=fake_res) is False
    assert check_nxdomain("dead.example.com", resolver=fake_res) is True
    assert resolve_a("dead.example.com", resolver=fake_res) == []

    res_dead = triage_subdomain("dead.example.com", resolver=fake_res)
    assert res_dead["type"] == "dead"

    bulk = triage_subdomain_bulk(["dead.example.com"], max_workers=2, resolver=fake_res)
    assert len(bulk["dead"]) == 1


def test_enumerator_run_binary_safe_enforces_shell_false():
    lines, err = run_binary_safe([])
    assert lines == []
    assert err is not None

    with patch("takeover_hunter.enumerator.is_tool_available", return_value=True), \
         patch("takeover_hunter.enumerator.subprocess.run") as mock_run:
        mock_proc = MagicMock(stdout="a.example.com\nb.example.com\n", stderr="", returncode=0)
        mock_run.return_value = mock_proc
        out, err = run_binary_safe(["subfinder", "-d", "example.com"])
        assert out == ["a.example.com", "b.example.com"]
        assert err is None
        assert mock_run.call_args.kwargs["shell"] is False

    with patch("takeover_hunter.enumerator.is_tool_available", return_value=False):
        subs, logs = enumerate_subdomains("example.com")
        assert "www.example.com" in subs
        assert probe_with_httpx(["example.com"]) == {}
