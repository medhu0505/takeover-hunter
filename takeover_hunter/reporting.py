"""Vulnerability report rendering.

Turns a confirmed finding into a HackerOne / Bugcrowd-ready Markdown report.
Pure and side-effect free, so it is trivial to unit test and safe to call
from a request handler.
"""
from __future__ import annotations

from typing import Dict


def _claimability_note(finding: Dict) -> str:
    claimable = finding.get("claimable")
    free = finding.get("free_account")
    if claimable and free:
        return "CLAIMABLE — free-tier proof-of-concept is possible"
    if claimable:
        return "CLAIMABLE — requires a paid account to reproduce"
    return (
        "NOT CLAIMABLE — auto-generated/ELB-style hostname; a proof-of-concept "
        "is not possible without hostname recycling"
    )


def render_report(
    finding: Dict,
    *,
    h1_user: str = "researcher",
    platform: str = "HackerOne",
) -> str:
    """Render a Markdown vulnerability report for a takeover ``finding``.

    ``finding`` is the dict emitted by the scan/verify pipeline. Missing
    optional keys degrade gracefully so a partial finding still renders.
    """
    sub = finding.get("sub", "unknown")
    cname = finding.get("cname", "unknown")
    provider = finding.get("provider", "Unknown")
    severity = finding.get("severity", "High")
    confidence = str(finding.get("confidence", "high")).upper()
    http_code = finding.get("http_code", "N/A")

    nx_status = (
        "NXDOMAIN confirmed"
        if finding.get("nxdomain")
        else "resolved (verify manually)"
    )
    body_note = (
        f"Body fingerprint matched: '{finding.get('match_string')}' — confirmed."
        if finding.get("body_match")
        else "No body fingerprint; NXDOMAIN is the primary indicator."
    )
    claimable_note = _claimability_note(finding)

    return f"""# Subdomain Takeover: {sub}

## Summary
`{sub}` has a dangling CNAME pointing to `{cname}`, an unclaimed resource on
**{provider}**. The delegated target returns {nx_status}, so no active resource
exists at this endpoint and it can be claimed by an attacker.

**Claimability:** {claimable_note}

## Severity
**{severity}** — Confidence: {confidence}
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N

## Steps To Reproduce
1. Resolve the dangling record:
   ```
   dig {sub} CNAME +noall +answer
   → {cname}
   ```
2. Confirm the target is unclaimed:
   ```
   dig @8.8.8.8 {cname}
   → {nx_status}
   ```
3. Probe the live host:
   ```
   curl -sk -o /dev/null -w "%{{http_code}}" \\
     -H "X-Bug-Bounty: {platform}-{h1_user}" https://{sub}
   → HTTP {http_code}
   ```
   {body_note}

## Impact
Full subdomain takeover. An attacker who claims `{cname}` can:
- Serve arbitrary content under `{sub}` with valid TLS via automated issuance.
- Capture session cookies scoped to the parent domain.
- Defeat CSP / CORS allowlists that trust this subdomain.
- Intercept API traffic or credentials from clients still routing here.

## Remediation
Remove the dangling CNAME record for `{sub}` from DNS, or re-provision the
resource on {provider} so the delegation resolves to an owned endpoint.

## Supporting Material
- `dig {sub} CNAME +noall +answer`
- `dig @8.8.8.8 {cname}`
- `curl` response: HTTP {http_code}
- Reference: https://github.com/EdOverflow/can-i-take-over-xyz
- Probe identity header: `X-Bug-Bounty: {platform}-{h1_user}`

## Reporter
{platform}: @{h1_user}
"""
