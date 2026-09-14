"""Cloud-provider takeover signature database and matching.

Each fingerprint describes a hosting provider whose dangling CNAME can be
claimed by an attacker. Fields:

- ``provider``     human-readable provider name
- ``patterns``     CNAME-target substrings that identify the provider
- ``takeover``     whether a dangling record on this provider is takeover-able
- ``claimable``    whether the resource can be re-claimed to prove impact
- ``free_account`` whether claiming requires only a free account (cheap PoC)
- ``status_match`` HTTP body string that confirms an unclaimed resource

The signatures are derived from public, well-established takeover research
(e.g. EdOverflow's ``can-i-take-over-xyz``). Extend :data:`FINGERPRINTS` to
broaden coverage — each entry is independent and unit-tested for pattern
uniqueness.
"""
from __future__ import annotations

from typing import Dict, List, Optional

Fingerprint = Dict[str, object]

FINGERPRINTS: List[Fingerprint] = [
    {"provider": "Heroku", "patterns": ["herokuapp.com", "herokudns.com", "herokussl.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "No such app"},
    {"provider": "GitHub Pages", "patterns": ["github.io", "githubusercontent.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "There isn't a GitHub Pages site here"},
    {"provider": "AWS S3", "patterns": ["s3.amazonaws.com", "s3-website", "s3.dualstack"], "takeover": True, "claimable": True, "free_account": False, "status_match": "NoSuchBucket"},
    {"provider": "AWS CloudFront", "patterns": ["cloudfront.net"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Bad Request"},
    {"provider": "AWS ELB", "patterns": ["elb.amazonaws.com"], "takeover": True, "claimable": False, "free_account": False, "status_match": ""},
    {"provider": "Azure Traffic Manager", "patterns": ["trafficmanager.net"], "takeover": True, "claimable": True, "free_account": True, "status_match": ""},
    {"provider": "Azure Web", "patterns": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "azure-api.net", "azureedge.net"], "takeover": True, "claimable": True, "free_account": True, "status_match": "404 Web Site not found"},
    {"provider": "Fastly", "patterns": ["fastly.net"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Fastly error: unknown domain"},
    {"provider": "Netlify", "patterns": ["netlify.app", "netlify.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "Not Found"},
    {"provider": "Vercel", "patterns": ["vercel.app", "now.sh", "vercel-dns.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "The deployment could not be found"},
    {"provider": "Webflow", "patterns": ["proxy.webflow.com", "webflow.io"], "takeover": True, "claimable": True, "free_account": False, "status_match": "The page you are looking for doesn't exist"},
    {"provider": "Pantheon", "patterns": ["pantheonsite.io"], "takeover": True, "claimable": True, "free_account": False, "status_match": "404 error unknown site"},
    {"provider": "Ghost", "patterns": ["ghost.io"], "takeover": True, "claimable": True, "free_account": False, "status_match": "The thing you were looking for is no longer here"},
    {"provider": "Shopify", "patterns": ["myshopify.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Sorry, this shop is currently unavailable"},
    {"provider": "Tumblr", "patterns": ["domains.tumblr.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "Whatever you were looking for doesn't currently exist at this address"},
    {"provider": "WordPress", "patterns": ["wordpress.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "Do you want to register"},
    {"provider": "Zendesk", "patterns": ["zendesk.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Help Center Closed"},
    {"provider": "Bitbucket", "patterns": ["bitbucket.io"], "takeover": True, "claimable": True, "free_account": True, "status_match": "Repository not found"},
    {"provider": "Surge.sh", "patterns": ["surge.sh"], "takeover": True, "claimable": True, "free_account": True, "status_match": "project not found"},
    {"provider": "Readme.io", "patterns": ["readme.io"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Project doesnt exist"},
    {"provider": "Cargo", "patterns": ["cargocollective.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": "404 Not Found"},
    {"provider": "Statuspage", "patterns": ["statuspage.io"], "takeover": True, "claimable": True, "free_account": False, "status_match": "You are being redirected"},
    {"provider": "Unbounce", "patterns": ["unbouncepages.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": "The requested URL was not found on this server"},
    {"provider": "Helpscout", "patterns": ["helpscoutdocs.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": "No settings were found for this company"},
    {"provider": "Seismic", "patterns": ["seismic.com", "tenant-services"], "takeover": True, "claimable": False, "free_account": False, "status_match": "The page you are looking for does not exist"},
    {"provider": "Marketo", "patterns": ["mktoweb.com", "marketo.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": ""},
]

# Regex patterns for opportunistic secret detection in fetched JavaScript.
JS_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{8,})["\']', "API Key"),
    (r'(?i)(secret|token|auth)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']', "Secret/Token"),
    (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']([A-Za-z0-9/+]{16,})["\']', "AWS Access Key"),
    (r'(?i)(aws_secret[a-z_]*)\s*[=:]\s*["\']([A-Za-z0-9/+]{16,})["\']', "AWS Secret"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "Password"),
    (r'(AKIA[0-9A-Z]{16})', "AWS Access Key ID"),
    (r'Bearer\s+([A-Za-z0-9\-_\.]{20,})', "Bearer Token"),
]


def match_fingerprint(cname_target: Optional[str]) -> Optional[Fingerprint]:
    """Return the fingerprint whose pattern matches ``cname_target``, or None.

    Matching is case-insensitive and substring-based against the CNAME target.
    """
    if not cname_target:
        return None
    lowered = cname_target.lower()
    for fp in FINGERPRINTS:
        if any(pattern in lowered for pattern in fp["patterns"]):  # type: ignore[operator]
            return fp
    return None


def provider_names() -> List[str]:
    """Sorted list of unique provider names, for UI filter population."""
    return sorted({str(fp["provider"]) for fp in FINGERPRINTS})
