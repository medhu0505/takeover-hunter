"""Unit tests for all 26 provider signatures and two-pass verification logic."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from takeover_hunter.signatures import (
    SIGNATURES,
    get_signature_by_provider,
    match_fingerprint,
    match_signature,
)
from takeover_hunter.ssrf_guard import SafeProbeResult
from takeover_hunter.verifier import Finding, assess_target, calculate_severity, verify_finding


def test_total_signature_count_is_26():
    assert len(SIGNATURES) == 26


@pytest.mark.parametrize(
    "cname,expected_provider",
    [
        ("myapp.herokuapp.com", "Heroku"),
        ("org.github.io", "GitHub Pages"),
        ("mybucket.s3.amazonaws.com", "AWS S3"),
        ("mybucket.s3-website-us-east-1.amazonaws.com", "AWS S3"),
        ("mybucket.s3.eu-west-1.amazonaws.com", "AWS S3"),
        ("mybucket.s3-accelerate.amazonaws.com", "AWS S3"),
        ("d111111abcdef8.cloudfront.net", "AWS CloudFront"),
        ("my-load-balancer-123.us-west-2.elb.amazonaws.com", "AWS ELB"),
        ("webapp.azurewebsites.net", "Azure Web Apps"),
        ("profile.trafficmanager.net", "Azure Traffic Manager"),
        ("global.prod.fastly.net", "Fastly"),
        ("site.netlify.app", "Netlify"),
        ("project.vercel.app", "Vercel"),
        ("legacy.now.sh", "Vercel"),
        ("proxy-ssl.webflow.com", "Webflow"),
        ("dev-site.pantheonsite.io", "Pantheon"),
        ("blog.ghost.io", "Ghost"),
        ("store.myshopify.com", "Shopify"),
        ("domains.tumblr.com", "Tumblr"),
        ("blog.wordpress.com", "WordPress.com"),
        ("support.zendesk.com", "Zendesk"),
        ("team.bitbucket.io", "Bitbucket"),
        ("static.surge.sh", "Surge.sh"),
        ("app.fly.dev", "Fly.io"),
        ("service.onrender.com", "Render"),
        ("docs.readthedocs.io", "ReadTheDocs"),
        ("company.helpscoutdocs.com", "HelpScout"),
        ("kb.helpjuice.com", "HelpJuice"),
        ("promo.unbouncepages.com", "Unbounce"),
        ("portfolio.cargocollective.com", "Cargo Collective"),
    ],
)
def test_all_26_provider_signatures_match_suffix(cname, expected_provider):
    sig = match_signature(cname)
    assert sig is not None
    assert sig.provider == expected_provider
    fp = match_fingerprint(cname)
    assert fp is not None
    assert fp["provider"] == expected_provider


@pytest.mark.parametrize(
    "false_positive_cname",
    [
        "snow.shopping.example.com",       # substring 'now.sh' inside hostname
        "github.io.attacker.com",          # provider domain in prefix, not suffix
        "herokuapp.com.evil.org",          # provider domain in prefix
        "not-herokuapp.com",               # partial label match
        "mygithub.io",                     # partial label match
        "s3-website.attacker.com",         # non-AWS domain with s3-website label
        "ec2-1-2-3-4.compute.amazonaws.com",  # AWS domain that is not S3 or ELB
        "fake-fastly.net",                 # partial label match
        "myshopify.com.phishing.io",       # prefix match
        "now.sh.internal.corp",            # prefix match
        "...",                             # dots only
        "",
        "   ",
    ],
)
def test_substring_false_positives_rejected(false_positive_cname):
    assert match_signature(false_positive_cname) is None
    assert match_fingerprint(false_positive_cname) is None


def test_get_signature_by_provider():
    assert get_signature_by_provider("heroku").provider == "Heroku"
    assert get_signature_by_provider("nonexistent") is None


def test_calculate_severity_elevates_sensitive_subdomains():
    assert calculate_severity("auth.example.com", "High") == "Critical"
    assert calculate_severity("api.example.com", "Medium") == "Critical"
    assert calculate_severity("blog.example.com", "High") == "High"


def test_assess_target_does_not_flag_generic_404_without_fingerprint():
    probe = SafeProbeResult(status_code=404, body="<html><body>404 Normal Not Found</body></html>")
    with patch("takeover_hunter.verifier.resolve_cname_chain", return_value=["app.herokuapp.com"]), \
         patch("takeover_hunter.verifier.check_nxdomain", return_value=False):
        finding = assess_target("blog.example.com", http_probe_fn=lambda _: probe)
        assert finding is None


def test_assess_target_flags_matching_http_fingerprint():
    probe = SafeProbeResult(status_code=404, body="There isn't a GitHub Pages site here.")
    with patch("takeover_hunter.verifier.resolve_cname_chain", return_value=["org.github.io"]), \
         patch("takeover_hunter.verifier.check_nxdomain", return_value=False):
        finding = assess_target("docs.example.com", http_probe_fn=lambda _: probe)
        assert finding is not None
        assert finding.vulnerable is True
        assert finding.provider == "GitHub Pages"
        assert finding.body_match is True
        assert finding.confidence == "high"
        assert finding.to_dict()["provider"] == "GitHub Pages"


def test_assess_target_fallbacks_and_edge_branches():
    probe_empty = SafeProbeResult(status_code=0, body="")

    # 1. Fallback to cname_target parameter when resolve_cname_chain is empty, with nxdomain_required=True provider
    with patch("takeover_hunter.verifier.resolve_cname_chain", return_value=[]), \
         patch("takeover_hunter.verifier.check_nxdomain", return_value=True):
        f_nx_req = assess_target(
            "tm.example.com",
            cname_target="dangling.trafficmanager.net",
            http_probe_fn=lambda _: probe_empty,
        )
        assert f_nx_req is not None
        assert f_nx_req.provider == "Azure Traffic Manager"
        assert f_nx_req.confidence == "high"

    # 2. Fallback to resolve_cname(clean_sub) when chain and cname_target are empty
    with patch("takeover_hunter.verifier.resolve_cname_chain", return_value=[]), \
         patch("takeover_hunter.verifier.resolve_cname", return_value="dangling.github.io."), \
         patch("takeover_hunter.verifier.check_nxdomain", return_value=True):
        f_direct = assess_target("git.example.com", http_probe_fn=lambda _: probe_empty)
        assert f_direct is not None
        assert f_direct.provider == "GitHub Pages"
        assert f_direct.nxdomain is True

    # 3. Return None when no CNAME can be resolved at all
    with patch("takeover_hunter.verifier.resolve_cname_chain", return_value=[]), \
         patch("takeover_hunter.verifier.resolve_cname", return_value=None):
        assert assess_target("none.example.com", http_probe_fn=lambda _: probe_empty) is None

    # 4. Multi-hop chain where intermediate hop matches signature and final target is custom
    with patch(
        "takeover_hunter.verifier.resolve_cname_chain",
        return_value=["intermediate.herokuapp.com", "backend.internal.example.org"],
    ), patch("takeover_hunter.verifier.check_nxdomain", return_value=True):
        f_hop = assess_target("hop.example.com", http_probe_fn=lambda _: probe_empty)
        assert f_hop is not None
        assert f_hop.provider == "Heroku"

    # 5. Unknown/Orphaned provider with NXDOMAIN=True
    with patch(
        "takeover_hunter.verifier.resolve_cname_chain",
        return_value=["dead.unregistered-domain.example"],
    ), patch("takeover_hunter.verifier.check_nxdomain", return_value=True):
        f_orphan = assess_target("orphan.example.com", http_probe_fn=lambda _: probe_empty)
        assert f_orphan is not None
        assert f_orphan.provider == "Orphaned"
        assert f_orphan.confidence == "medium"


def test_two_pass_verification_nxdomain_provider_confirmed_and_rejected():
    finding = Finding(
        sub="tm.example.com",
        cname="dangling.trafficmanager.net",
        provider="Azure Traffic Manager",
        claimable=True,
        free_account=True,
        nxdomain=True,
        http_code=0,
        body_match=False,
        match_string="",
        vulnerable=True,
        confidence="high",
        severity="High",
        poc_guidance="",
    )

    # Pass 2 confirmed when both NXDOMAIN checks return True and CNAME chain ends at target
    with patch(
        "takeover_hunter.verifier.resolve_cname_chain",
        return_value=["hop1.example.com", "dangling.trafficmanager.net"],
    ), patch("takeover_hunter.verifier.check_nxdomain", side_effect=[True, True]), \
       patch("takeover_hunter.verifier.time.sleep") as mock_sleep:
        verified = verify_finding(
            finding,
            delay_seconds=0.3,
            http_probe_fn=lambda _: SafeProbeResult(status_code=0),
        )
        assert verified.verified is True
        assert verified.verify_nxdomain_1 is True
        assert verified.verify_nxdomain_2 is True
        mock_sleep.assert_called_once_with(0.3)

    # Pass 2 rejected if second NXDOMAIN check resolves (transient DNS jitter)
    with patch(
        "takeover_hunter.verifier.resolve_cname_chain",
        return_value=["dangling.trafficmanager.net"],
    ), patch("takeover_hunter.verifier.check_nxdomain", side_effect=[True, False]):
        verified_jitter = verify_finding(
            finding,
            delay_seconds=0.0,
            http_probe_fn=lambda _: SafeProbeResult(status_code=0),
        )
        assert verified_jitter.verified is False


def test_two_pass_verification_http_fingerprint_provider():
    finding = Finding(
        sub="shop.example.com",
        cname="unclaimed.myshopify.com",
        provider="Shopify",
        claimable=True,
        free_account=False,
        nxdomain=False,
        http_code=404,
        body_match=True,
        match_string="Sorry, this shop is currently unavailable",
        vulnerable=True,
        confidence="high",
        severity="High",
        poc_guidance="",
    )

    # Confirmed when multi-hop CNAME still points to Shopify and HTTP probe matches fingerprint + status
    with patch(
        "takeover_hunter.verifier.resolve_cname_chain",
        return_value=["edge.example.com", "unclaimed.myshopify.com"],
    ), patch("takeover_hunter.verifier.check_nxdomain", return_value=False):
        v1 = verify_finding(
            finding,
            delay_seconds=0.0,
            http_probe_fn=lambda _: SafeProbeResult(
                status_code=404,
                body="Sorry, this shop is currently unavailable.",
            ),
        )
        assert v1.verified is True

    # Suppressed when second HTTP probe returns 200 OK or lacks fingerprint
    with patch(
        "takeover_hunter.verifier.resolve_cname_chain",
        return_value=["unclaimed.myshopify.com"],
    ), patch("takeover_hunter.verifier.check_nxdomain", return_value=False):
        v2 = verify_finding(
            finding,
            delay_seconds=0.0,
            http_probe_fn=lambda _: SafeProbeResult(status_code=200, body="Welcome to our live store"),
        )
        assert v2.verified is False


def test_verify_finding_additional_branches():
    probe_empty = SafeProbeResult(status_code=0, body="")

    # 1. Direct resolve_cname fallback + rotated CNAME on same provider + NXDOMAIN on non-nxdomain_required provider
    f_gh = Finding(
        sub="docs.example.com",
        cname="old-org.github.io",
        provider="GitHub Pages",
        claimable=True,
        free_account=True,
        nxdomain=True,
        http_code=0,
        body_match=False,
        match_string="",
        vulnerable=True,
        confidence="high",
        severity="High",
        poc_guidance="",
    )
    with patch("takeover_hunter.verifier.resolve_cname_chain", return_value=[]), \
         patch("takeover_hunter.verifier.resolve_cname", return_value="new-org.github.io"), \
         patch("takeover_hunter.verifier.check_nxdomain", side_effect=[True, True]):
        res_gh = verify_finding(f_gh, delay_seconds=0.0, http_probe_fn=lambda _: probe_empty)
        assert res_gh.cname_still_present is True
        assert res_gh.verified is True

    # 2. Provider lookup fallback when final CNAME doesn't directly match signature pattern
    f_named = Finding(
        sub="custom.example.com",
        cname="alias.custom-target.org",
        provider="Shopify",
        claimable=True,
        free_account=False,
        nxdomain=False,
        http_code=404,
        body_match=True,
        match_string="Sorry, this shop is currently unavailable",
        vulnerable=True,
        confidence="high",
        severity="High",
        poc_guidance="",
    )
    with patch("takeover_hunter.verifier.resolve_cname_chain", return_value=["alias.custom-target.org"]), \
         patch("takeover_hunter.verifier.check_nxdomain", return_value=False):
        res_named = verify_finding(
            f_named,
            delay_seconds=0.0,
            http_probe_fn=lambda _: SafeProbeResult(
                status_code=404,
                body="Sorry, this shop is currently unavailable",
            ),
        )
        assert res_named.verified is True

    # 3. Orphaned CNAME verification branch
    f_orphan = Finding(
        sub="orphan.example.com",
        cname="dead.custom-domain.org",
        provider="Orphaned",
        claimable=False,
        free_account=False,
        nxdomain=True,
        http_code=0,
        body_match=False,
        match_string="",
        vulnerable=True,
        confidence="medium",
        severity="High",
        poc_guidance="",
    )
    with patch("takeover_hunter.verifier.resolve_cname_chain", return_value=["dead.custom-domain.org"]), \
         patch("takeover_hunter.verifier.check_nxdomain", side_effect=[True, True]):
        res_orphan = verify_finding(f_orphan, delay_seconds=0.0, http_probe_fn=lambda _: probe_empty)
        assert res_orphan.verified is True
