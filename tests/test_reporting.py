"""Report rendering tests."""
from takeover_hunter.reporting import render_report


def _finding(**overrides):
    base = {
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
    base.update(overrides)
    return base


def test_report_includes_all_core_fields():
    report = render_report(_finding(), h1_user="stickybugger", platform="HackerOne")
    assert "old.example.com" in report
    assert "ghost-app.herokuapp.com" in report
    assert "Heroku" in report
    assert "NXDOMAIN confirmed" in report
    assert "free-tier proof-of-concept is possible" in report
    assert "HackerOne: @stickybugger" in report
    assert "HIGH" in report  # confidence upper-cased


def test_report_handles_missing_optional_fields():
    report = render_report({"sub": "x.example.com"})
    assert "x.example.com" in report
    assert "researcher" in report  # default user


def test_report_claimable_paid_note():
    report = render_report(_finding(claimable=True, free_account=False))
    assert "requires a paid account" in report


def test_report_not_claimable_note():
    report = render_report(_finding(claimable=False, free_account=False))
    assert "NOT CLAIMABLE" in report


def test_report_body_match_line():
    report = render_report(_finding(nxdomain=False, body_match=True, match_string="No such app"))
    assert "Body fingerprint matched: 'No such app'" in report
    assert "resolved (verify manually)" in report
