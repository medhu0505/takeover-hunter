"""HTTP route tests: validation, auth, rate limiting, streaming, lookups."""
from unittest.mock import patch

import dns.resolver

from takeover_hunter.app import create_app
from takeover_hunter.config import Config
from takeover_hunter.recon import ReconEngine


# --- meta -------------------------------------------------------------------

def test_healthz(client):
    data = client.get("/healthz").get_json()
    assert data["status"] == "ok"
    assert "version" in data


def test_index_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200


def test_tools_and_providers(client):
    assert client.get("/api/tools").status_code == 200
    providers = client.get("/api/providers").get_json()["providers"]
    assert "Heroku" in providers


# --- validation / injection at the route boundary ---------------------------

def test_enumerate_rejects_injection(client):
    resp = client.get("/api/enumerate?target=example.com;id")
    assert resp.status_code == 400
    assert "Invalid target" in resp.get_json()["error"]


def test_enumerate_rejects_empty(client):
    assert client.get("/api/enumerate?target=").status_code == 400


def test_archive_rejects_injection(client):
    resp = client.post("/api/archive", json={"target": "a.com && whoami"})
    assert resp.status_code == 400


def test_jsrecon_rejects_injection(client):
    resp = client.post("/api/jsrecon", json={"target": "$(reboot)"})
    assert resp.status_code == 400


def test_dns_rejects_bad_type(client):
    resp = client.post("/api/dns", json={"host": "example.com", "type": "EVIL"})
    assert resp.status_code == 400


def test_dns_rejects_bad_host(client):
    resp = client.post("/api/dns", json={"host": "bad;host", "type": "A"})
    assert resp.status_code == 400


def test_quickscan_requires_input(client):
    resp = client.post("/api/quickscan", json={})
    assert resp.status_code == 400


# --- report -----------------------------------------------------------------

def test_report_ok(client):
    finding = {
        "sub": "old.example.com", "cname": "x.herokuapp.com", "provider": "Heroku",
        "nxdomain": True, "claimable": True, "free_account": True,
        "severity": "High", "confidence": "high", "http_code": 404,
    }
    resp = client.post("/api/report", json={"finding": finding, "h1_user": "h1u"})
    assert resp.status_code == 200
    assert "old.example.com" in resp.get_json()["report"]


def test_report_bad_finding_type(client):
    resp = client.post("/api/report", json={"finding": "nope"})
    assert resp.status_code == 400


# --- authentication ---------------------------------------------------------

def test_auth_required_when_key_set(keyed_client):
    assert keyed_client.get("/api/tools").status_code == 401


def test_auth_accepts_header(keyed_client):
    resp = keyed_client.get("/api/tools", headers={"X-API-Key": "secret-key"})
    assert resp.status_code == 200


def test_auth_accepts_bearer(keyed_client):
    resp = keyed_client.get("/api/tools", headers={"Authorization": "Bearer secret-key"})
    assert resp.status_code == 200


def test_auth_rejects_wrong_key(keyed_client):
    resp = keyed_client.get("/api/tools", headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401


# --- rate limiting ----------------------------------------------------------

def test_rate_limit_triggers_429():
    app = create_app(Config(api_key="", rate_limit_enabled=True,
                            rate_limit_requests=3, rate_limit_window_seconds=60))
    app.config["TESTING"] = True
    c = app.test_client()
    codes = [c.get("/api/tools").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert 429 in codes


def test_rate_limit_ignores_non_api_routes():
    app = create_app(Config(rate_limit_enabled=True, rate_limit_requests=1,
                            rate_limit_window_seconds=60))
    app.config["TESTING"] = True
    c = app.test_client()
    assert c.get("/").status_code == 200
    assert c.get("/").status_code == 200  # not rate limited


# --- streaming plumbing (engine mocked) -------------------------------------

def _read_sse(resp):
    return resp.get_data(as_text=True)


def test_triage_stream_emits_done(client):
    def fake_triage(self, subdomains, q):
        q.put(("log", "info", "start"))
        q.put(("triage_done", [{"sub": "a.example.com"}], [], []))

    with patch.object(ReconEngine, "triage", fake_triage):
        resp = client.post("/api/triage", json={"subdomains": ["a.example.com"]})
        body = _read_sse(resp)
    assert "event: log" in body
    assert "event: done" in body
    assert "a.example.com" in body


def test_triage_empty_input_returns_done(client):
    resp = client.post("/api/triage", json={"subdomains": []})
    assert "event: done" in _read_sse(resp)


def test_scan_stream_emits_vuln_and_done(client):
    def fake_scan(self, records, q):
        q.put(("vuln", {"sub": "v.example.com", "severity": "High"}))
        q.put(("scan_done", [{"sub": "v.example.com"}]))

    with patch.object(ReconEngine, "scan", fake_scan):
        resp = client.post("/api/scan", json={
            "cname_records": [{"sub": "v.example.com", "cname": "x.herokuapp.com"}]
        })
        body = _read_sse(resp)
    assert "event: vuln" in body
    assert "event: done" in body


def test_scan_provider_filter_drops_nonmatching(client):
    resp = client.post("/api/scan", json={
        "cname_records": [{"sub": "v.example.com", "cname": "origin.internal.example.com"}],
        "provider_filter": ["Heroku"],
    })
    # Non-matching provider filtered out -> immediate done with 0.
    body = _read_sse(resp)
    assert "event: done" in body
    assert '"count": 0' in body


# --- dns lookup (resolver mocked) -------------------------------------------

def test_dns_lookup_a_record(client):
    engine = client.application.config["TH_ENGINE"]
    with patch.object(engine.dns._resolver, "resolve", return_value=["93.184.216.34"]):
        resp = client.post("/api/dns", json={"host": "example.com", "type": "A"})
    assert resp.get_json()["records"] == ["93.184.216.34"]


def test_dns_lookup_nxdomain(client):
    engine = client.application.config["TH_ENGINE"]
    with patch.object(engine.dns._resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
        resp = client.post("/api/dns", json={"host": "gone.example.com", "type": "A"})
    assert resp.get_json()["error"] == "NXDOMAIN"


# --- quickscan (engine mocked) ----------------------------------------------

def test_quickscan_vulnerable(client):
    finding = {"sub": "s.example.com", "cname": "x.herokuapp.com", "vulnerable": True,
               "confidence": "high", "severity": "High"}
    with patch.object(ReconEngine, "assess", lambda self, s, c="": finding):
        resp = client.post("/api/quickscan", json={"sub": "s.example.com", "cname": "x.herokuapp.com"})
    assert resp.get_json()["vulnerable"] is True


def test_quickscan_not_vulnerable(client):
    with patch.object(ReconEngine, "assess", lambda self, s, c="": None):
        resp = client.post("/api/quickscan", json={"cname": "origin.example.com"})
    assert resp.get_json()["vulnerable"] is False
