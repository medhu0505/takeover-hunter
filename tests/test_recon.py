"""Recon engine tests: assessment logic and shell-injection safety."""
from unittest.mock import patch

from takeover_hunter.config import Config
from takeover_hunter.recon import ReconEngine, _hosts_in_scope, _run_argv


def _engine():
    return ReconEngine(Config(allow_private_targets=True))


# --- shell-injection safety of the tool runner ------------------------------

def test_run_argv_does_not_invoke_shell(tmp_path):
    """A metacharacter-laden argument must be passed literally, never executed."""
    marker = tmp_path / "pwned"
    payload = f"; touch {marker}"
    lines, err = _run_argv(
        ["python3", "-c", "import sys; print(sys.argv[1])", payload],
        timeout=10,
    )
    assert err is None
    assert lines == [payload.strip()]  # argument echoed literally
    assert not marker.exists()         # side-effect command NOT executed


def test_run_argv_reports_timeout():
    lines, err = _run_argv(["python3", "-c", "import time; time.sleep(5)"], timeout=1)
    assert lines == []
    assert err == "timeout"


def test_run_argv_reports_spawn_failure():
    lines, err = _run_argv(["this-binary-does-not-exist-xyz"], timeout=5)
    assert lines == []
    assert err is not None


# --- scope filtering --------------------------------------------------------

def test_hosts_in_scope_filters_and_validates():
    lines = [
        "api.example.com",
        "https://cdn.example.com/app.js",
        "evil.com",                    # out of scope
        "bad;host.example.com",        # invalid -> dropped
        "example.com",
    ]
    assert _hosts_in_scope(lines, "example.com") == [
        "api.example.com", "cdn.example.com", "example.com",
    ]


# --- assessment logic -------------------------------------------------------

def test_assess_nxdomain_is_high_confidence():
    engine = _engine()
    with patch.object(engine.dns, "resolve_cname_chain", return_value=["x.herokuapp.com"]), \
         patch.object(engine.dns, "is_nxdomain", return_value=True), \
         patch("takeover_hunter.recon.http_probe", return_value={"code": 404, "body": "", "headers": {}}):
        result = engine.assess("app.example.com", "x.herokuapp.com")
    assert result["vulnerable"] is True
    assert result["confidence"] == "high"
    assert result["provider"] == "Heroku"


def test_assess_body_match_is_high_confidence():
    engine = _engine()
    with patch.object(engine.dns, "resolve_cname_chain", return_value=["x.herokuapp.com"]), \
         patch.object(engine.dns, "is_nxdomain", return_value=False), \
         patch("takeover_hunter.recon.http_probe",
               return_value={"code": 200, "body": "No such app", "headers": {}}):
        result = engine.assess("app.example.com", "x.herokuapp.com")
    assert result["confidence"] == "high"
    assert result["body_match"] is True
    assert result["match_string"] == "No such app"


def test_assess_medium_on_404_with_fingerprint():
    engine = _engine()
    with patch.object(engine.dns, "resolve_cname_chain", return_value=["x.herokuapp.com"]), \
         patch.object(engine.dns, "is_nxdomain", return_value=False), \
         patch("takeover_hunter.recon.http_probe", return_value={"code": 404, "body": "", "headers": {}}):
        result = engine.assess("app.example.com", "x.herokuapp.com")
    assert result["confidence"] == "medium"


def test_assess_returns_none_when_not_vulnerable():
    engine = _engine()
    with patch.object(engine.dns, "resolve_cname_chain", return_value=["origin.internal.example.com"]), \
         patch.object(engine.dns, "is_nxdomain", return_value=False), \
         patch("takeover_hunter.recon.http_probe", return_value={"code": 200, "body": "ok", "headers": {}}):
        assert engine.assess("app.example.com", "origin.internal.example.com") is None


def test_assess_critical_severity_on_sensitive_subdomain():
    engine = _engine()
    with patch.object(engine.dns, "resolve_cname_chain", return_value=["x.herokuapp.com"]), \
         patch.object(engine.dns, "is_nxdomain", return_value=True), \
         patch("takeover_hunter.recon.http_probe", return_value={"code": 404, "body": "", "headers": {}}):
        result = engine.assess("api.example.com", "x.herokuapp.com")
    assert result["severity"] == "Critical"


# --- worker orchestration (DNS/HTTP mocked, queue drained) ------------------

import queue as _queue


def _drain(q):
    items = []
    while not q.empty():
        items.append(q.get_nowait())
    return items


def _tags(items):
    return [it[0] for it in items]


def test_triage_buckets_cname_a_and_dead():
    engine = _engine()
    q = _queue.Queue()
    with patch.object(engine.dns, "resolve_cname",
                      side_effect=lambda h: "x.herokuapp.com" if h == "c.example.com" else None), \
         patch.object(engine.dns, "resolve_a",
                      side_effect=lambda h: ["1.2.3.4"] if h == "a.example.com" else []), \
         patch.object(engine, "_dnsx_bulk", return_value={}):
        engine.triage(["c.example.com", "a.example.com", "dead.example.com"], q)
    items = _drain(q)
    done = [it for it in items if it[0] == "triage_done"][0]
    _, cnames, dead, arecs = done
    assert cnames[0]["sub"] == "c.example.com" and cnames[0]["provider"] == "Heroku"
    assert arecs[0]["sub"] == "a.example.com"
    assert dead[0]["sub"] == "dead.example.com"


def test_scan_aggregates_vulnerable():
    engine = _engine()
    q = _queue.Queue()
    finding = {"sub": "v.example.com", "vulnerable": True, "severity": "High"}
    with patch.object(ReconEngine, "assess", lambda self, s, c="": finding if s == "v.example.com" else None):
        engine.scan([{"sub": "v.example.com", "cname": "x.herokuapp.com"},
                     {"sub": "safe.example.com", "cname": "origin.example.com"}], q)
    items = _drain(q)
    assert "vuln" in _tags(items)
    done = [it for it in items if it[0] == "scan_done"][0]
    assert len(done[1]) == 1


def test_bulk_url_scan_uses_assess():
    engine = _engine()
    q = _queue.Queue()
    with patch.object(ReconEngine, "assess", lambda self, s, c="": {"sub": s, "vulnerable": True}):
        engine.bulk_url_scan(["a.example.com", "b.example.com"], q)
    done = [it for it in _drain(q) if it[0] == "scan_done"][0]
    assert len(done[1]) == 2


def test_verify_confirms_when_stable_nxdomain():
    engine = _engine()
    q = _queue.Queue()
    with patch.object(engine.dns, "is_nxdomain", return_value=True), \
         patch.object(engine.dns, "resolve_cname", return_value="x.herokuapp.com"), \
         patch("takeover_hunter.recon.http_probe", return_value={"code": 404, "body": "", "headers": {}}):
        engine.verify([{"sub": "v.example.com", "cname": "x.herokuapp.com"}], q)
    done = [it for it in _drain(q) if it[0] == "verify_done"][0]
    assert done[1][0]["verified"] is True


def test_verify_not_confirmed_when_cname_gone():
    engine = _engine()
    q = _queue.Queue()
    with patch.object(engine.dns, "is_nxdomain", return_value=True), \
         patch.object(engine.dns, "resolve_cname", return_value=None), \
         patch("takeover_hunter.recon.http_probe", return_value={"code": 404, "body": "", "headers": {}}):
        engine.verify([{"sub": "v.example.com", "cname": "x.herokuapp.com"}], q)
    done = [it for it in _drain(q) if it[0] == "verify_done"][0]
    assert done[1][0]["verified"] is False


def test_js_recon_no_subdomains_short_circuits():
    engine = _engine()
    q = _queue.Queue()
    engine.js_recon("example.com", [], q)
    done = [it for it in _drain(q) if it[0] == "js_done"][0]
    assert done[1]["js_count"] == 0


def test_enumerate_no_tools_returns_empty(monkeypatch):
    engine = _engine()
    q = _queue.Queue()
    monkeypatch.setattr("takeover_hunter.recon.cmd_exists", lambda name: False)
    monkeypatch.setattr(engine.dns, "is_wildcard", lambda d: False)
    engine.enumerate_stream("example.com", q)
    done = [it for it in _drain(q) if it[0] == "enum_done"][0]
    assert done[1] == [] and done[2] == 0


def test_archive_no_tools_reports_zero(monkeypatch):
    engine = _engine()
    q = _queue.Queue()
    monkeypatch.setattr("takeover_hunter.recon.cmd_exists", lambda name: False)
    engine.archive_recon("example.com", q)
    done = [it for it in _drain(q) if it[0] == "archive_done"][0]
    assert done[1]["total"] == 0
