"""Fingerprint database and matching tests."""
import pytest

from takeover_hunter.fingerprints import (
    FINGERPRINTS,
    match_fingerprint,
    provider_names,
)


@pytest.mark.parametrize(
    "cname,provider",
    [
        ("foo.herokuapp.com", "Heroku"),
        ("bar.github.io", "GitHub Pages"),
        ("x.s3.amazonaws.com", "AWS S3"),
        ("app.netlify.app", "Netlify"),
        ("app.vercel.app", "Vercel"),
        ("shop.myshopify.com", "Shopify"),
        ("d123.cloudfront.net", "AWS CloudFront"),
        ("proj.surge.sh", "Surge.sh"),
        ("acme.statuspage.io", "Statuspage"),
    ],
)
def test_match_known_providers(cname, provider):
    fp = match_fingerprint(cname)
    assert fp is not None
    assert fp["provider"] == provider


def test_match_is_case_insensitive():
    fp = match_fingerprint("FOO.HEROKUAPP.COM")
    assert fp and fp["provider"] == "Heroku"


def test_unknown_returns_none():
    assert match_fingerprint("origin.internal.example.com") is None
    assert match_fingerprint("") is None
    assert match_fingerprint(None) is None


def test_no_duplicate_patterns_across_providers():
    seen = {}
    for fp in FINGERPRINTS:
        for pattern in fp["patterns"]:
            assert pattern not in seen, (
                f"pattern {pattern!r} shared by {seen.get(pattern)!r} and {fp['provider']!r}"
            )
            seen[pattern] = fp["provider"]


def test_every_fingerprint_has_required_keys():
    required = {"provider", "patterns", "takeover", "claimable", "free_account", "status_match"}
    for fp in FINGERPRINTS:
        assert required.issubset(fp.keys()), fp
        assert isinstance(fp["patterns"], list) and fp["patterns"]


def test_provider_names_sorted_unique():
    names = provider_names()
    assert names == sorted(names)
    assert len(names) == len(set(names))
    assert "Heroku" in names
