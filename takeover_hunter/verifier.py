"""Two-pass takeover verification and confidence classification engine.

Pass 1 (Assessment): Combines CNAME delegation, NXDOMAIN resolution, and SSRF-safe HTTP probing.
Pass 2 (Verification): Re-validates DNS persistence and HTTP state to suppress transient false positives.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .dns_triage import check_nxdomain, resolve_cname, resolve_cname_chain
from .signatures import Signature, match_signature
from .ssrf_guard import SafeProbeResult, safe_http_probe


@dataclass
class Finding:
    """Standardized vulnerability finding record."""
    sub: str
    cname: str
    provider: str
    claimable: bool
    free_account: bool
    nxdomain: bool
    http_code: int
    body_match: bool
    match_string: str
    vulnerable: bool
    confidence: str
    severity: str
    poc_guidance: str
    cname_chain: List[str] = field(default_factory=list)
    verified: bool = False
    verify_nxdomain_1: bool = False
    verify_nxdomain_2: bool = False
    verify_http: int = 0
    cname_still_present: bool = False

    def to_dict(self) -> Dict:
        """Convert finding to serializable dictionary."""
        return asdict(self)


def calculate_severity(subdomain: str, base_severity: str = "High") -> str:
    """Elevate severity to Critical if subdomain handles authentication, payments, or identity."""
    sensitive_keywords = (
        "auth", "login", "api", "sso", "account", "id",
        "pay", "wallet", "admin", "oauth", "token", "billing",
    )
    clean_sub = subdomain.lower()
    if any(keyword in clean_sub for keyword in sensitive_keywords):
        return "Critical"
    return base_severity


def assess_target(
    subdomain: str,
    cname_target: Optional[str] = None,
    http_probe_fn=None,
) -> Optional[Finding]:
    """Pass 1 (Assessment): Evaluate takeover vulnerability for a subdomain/CNAME pair."""
    probe_fn = http_probe_fn or safe_http_probe
    clean_sub = subdomain.strip().lower().rstrip(".")

    # Resolve CNAME chain if not provided
    chain = resolve_cname_chain(clean_sub) if not cname_target else [cname_target]
    effective_target = chain[-1] if chain else (cname_target or "")
    if not effective_target:
        # Fallback to direct resolution
        direct = resolve_cname(clean_sub)
        if direct:
            effective_target = direct
            chain = [direct]

    if not effective_target:
        return None

    sig: Optional[Signature] = match_signature(effective_target)
    nx = check_nxdomain(effective_target)
    probe_res: SafeProbeResult = probe_fn(clean_sub)

    is_vuln = False
    confidence = "low"
    body_match = False
    matched_string = ""

    # Rule A: NXDOMAIN on target endpoint
    if nx:
        is_vuln = True
        confidence = "high"
    # Rule B: Specific HTTP body fingerprint match
    elif sig and sig.http_fingerprints:
        for fp in sig.http_fingerprints:
            if fp.lower() in probe_res.body.lower():
                is_vuln = True
                confidence = "high"
                body_match = True
                matched_string = fp
                break

    # Rule C: Provider signature match with HTTP 0 or 404
    if not is_vuln and sig:
        if sig.http_status and probe_res.status_code in sig.http_status:
            is_vuln = True
            confidence = "medium"
        elif probe_res.status_code in (0, 404):
            is_vuln = True
            confidence = "medium"

    if not is_vuln:
        return None

    base_sev = sig.severity if sig else "High"
    severity = calculate_severity(clean_sub, base_sev)

    return Finding(
        sub=clean_sub,
        cname=effective_target,
        provider=sig.provider if sig else "Orphaned",
        claimable=sig.claimable if sig else False,
        free_account=sig.free_account if sig else False,
        nxdomain=nx,
        http_code=probe_res.status_code,
        body_match=body_match,
        match_string=matched_string,
        vulnerable=True,
        confidence=confidence,
        severity=severity,
        poc_guidance=sig.poc_guidance if sig else "Remove dangling DNS record immediately.",
        cname_chain=chain,
        verified=False,
    )


def verify_finding(
    finding: Finding,
    delay_seconds: float = 0.2,
    http_probe_fn=None,
) -> Finding:
    """Pass 2 (Verification): Re-evaluate DNS and HTTP to suppress transient false positives."""
    probe_fn = http_probe_fn or safe_http_probe
    sub = finding.sub
    cname = finding.cname

    # Step 1: Check if CNAME delegation is still present in live DNS
    current_cname = resolve_cname(sub)
    cname_still_present = (
        current_cname is not None and
        (cname.lower() in current_cname.lower() or current_cname.lower() in cname.lower())
    )

    # Step 2: Double NXDOMAIN verification pass to prevent DNS jitter
    nx1 = check_nxdomain(cname)
    if delay_seconds > 0:
        time.sleep(delay_seconds)
    nx2 = check_nxdomain(cname)

    # Step 3: Re-probe HTTP
    probe = probe_fn(sub)

    # Verification Decision Matrix
    confirmed = False
    if cname_still_present:
        if finding.nxdomain:
            # Requires persistent NXDOMAIN across both probes
            confirmed = nx1 and nx2
        elif finding.body_match and finding.match_string:
            # Requires HTTP body pattern to still reproduce
            confirmed = finding.match_string.lower() in probe.body.lower()
        else:
            # Medium confidence verified if CNAME intact and non-200 status persisted
            confirmed = (nx1 or nx2) or (probe.status_code in (0, 404, 403, 502))

    finding.verified = confirmed
    finding.verify_nxdomain_1 = nx1
    finding.verify_nxdomain_2 = nx2
    finding.verify_http = probe.status_code
    finding.cname_still_present = cname_still_present

    return finding
