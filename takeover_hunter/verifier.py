"""Two-pass takeover verification and confidence classification engine.

Pass 1 (Assessment): Combines multi-hop CNAME delegation, NXDOMAIN resolution, and SSRF-safe HTTP probing.
Pass 2 (Verification): Re-validates DNS persistence (0.3s apart) and HTTP fingerprint state to suppress false positives.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import time
from typing import Dict, List, Optional

from .dns_triage import check_nxdomain, resolve_cname, resolve_cname_chain
from .signatures import Signature, get_signature_by_provider, match_signature
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
        "auth",
        "login",
        "api",
        "sso",
        "account",
        "id",
        "pay",
        "wallet",
        "admin",
        "oauth",
        "token",
        "billing",
    )
    clean_sub = subdomain.lower()
    labels = clean_sub.replace("-", ".").replace("_", ".").split(".")
    if any(keyword in labels or clean_sub.startswith(keyword) for keyword in sensitive_keywords):
        return "Critical"
    return base_severity


def assess_target(
    subdomain: str,
    cname_target: Optional[str] = None,
    http_probe_fn=None,
) -> Optional[Finding]:
    """Pass 1 (Assessment): Evaluate takeover vulnerability for a subdomain/CNAME pair.

    Does NOT flag a target solely because HTTP returned 404 or 0; requires either
    a confirmed NXDOMAIN rule or a specific provider HTTP body fingerprint match.
    """
    probe_fn = http_probe_fn or safe_http_probe
    clean_sub = subdomain.strip().lower().rstrip(".")

    # Resolve full multi-hop CNAME chain
    chain = resolve_cname_chain(clean_sub)
    if not chain and cname_target:
        clean_cname = cname_target.strip().lower().rstrip(".")
        if clean_cname:
            chain = [clean_cname]

    effective_target = chain[-1] if chain else ""
    if not effective_target:
        direct = resolve_cname(clean_sub)
        if direct:
            effective_target = direct.strip().lower().rstrip(".")
            chain = [effective_target]

    if not effective_target:
        return None

    sig: Optional[Signature] = match_signature(effective_target)
    if not sig and len(chain) > 1:
        for hop in reversed(chain):
            hop_sig = match_signature(hop)
            if hop_sig:
                sig = hop_sig
                break

    nx = check_nxdomain(effective_target)
    probe_res: SafeProbeResult = probe_fn(clean_sub)

    is_vuln = False
    confidence = "low"
    body_match = False
    matched_string = ""

    if sig:
        if sig.nxdomain_required:
            # Provider requires NXDOMAIN on the CNAME target (e.g. Azure Traffic Manager, AWS ELB)
            if nx:
                is_vuln = True
                confidence = "high" if sig.claimable else "medium"
        else:
            # Provider uses specific HTTP body fingerprints (e.g. Heroku, GitHub Pages, AWS S3, Shopify)
            status_ok = (not sig.http_status) or (probe_res.status_code in sig.http_status)
            if status_ok and probe_res.body:
                for fp in sig.http_fingerprints:
                    if fp.lower() in probe_res.body.lower():
                        is_vuln = True
                        confidence = "high"
                        body_match = True
                        matched_string = fp
                        break
            # If the CNAME target itself returns NXDOMAIN on a known provider domain, it is also dangling
            if not is_vuln and nx:
                is_vuln = True
                confidence = "high" if sig.claimable else "medium"
    else:
        # Unknown provider: only flag if the CNAME target itself returns NXDOMAIN (dangling delegation)
        if nx:
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
    delay_seconds: float = 0.3,
    http_probe_fn=None,
) -> Finding:
    """Pass 2 (Verification): Re-evaluate multi-hop CNAME chain, DNS NXDOMAIN, and HTTP fingerprints.

    - For nxdomain_required=True signatures (or NXDOMAIN findings): confirms two consecutive
      DNS checks (0.3s apart) both return NXDOMAIN on the final CNAME target AND that
      resolve_cname_chain(sub)[-1] still matches the dangling CNAME target.
    - For nxdomain_required=False signatures (HTTP fingerprint providers): confirms that
      resolve_cname_chain(sub)[-1] still points to the provider CNAME AND that a second
      independent safe_http_probe pass matches the provider's http_fingerprints and http_status.
    """
    probe_fn = http_probe_fn or safe_http_probe
    sub = finding.sub.strip().lower().rstrip(".")
    expected_cname = finding.cname.strip().lower().rstrip(".")

    # Step 1: Resolve multi-hop CNAME chain and verify final target persistence
    chain = resolve_cname_chain(sub)
    if not chain:
        direct = resolve_cname(sub)
        if direct:
            chain = [direct.strip().lower().rstrip(".")]

    final_cname = chain[-1].strip().lower().rstrip(".") if chain else ""
    sig = match_signature(final_cname or expected_cname)
    if not sig and finding.provider and finding.provider not in ("Unknown", "Orphaned"):
        sig = get_signature_by_provider(finding.provider)

    cname_still_present = False
    if final_cname:
        if final_cname == expected_cname or expected_cname in [c.lower().rstrip(".") for c in chain]:
            cname_still_present = True
        elif sig and match_signature(final_cname) == sig:
            cname_still_present = True

    target_for_nx = final_cname or expected_cname

    # Step 2: Double NXDOMAIN verification pass (0.3s apart) to prevent DNS jitter
    nx1 = check_nxdomain(target_for_nx) if target_for_nx else False
    if delay_seconds > 0:
        time.sleep(delay_seconds)
    nx2 = check_nxdomain(target_for_nx) if target_for_nx else False

    # Step 3: Second independent HTTP probe pass
    probe: SafeProbeResult = probe_fn(sub)

    # Step 4: Verification Decision Matrix
    confirmed = False
    if cname_still_present:
        if sig and sig.nxdomain_required:
            # Provider requires persistent NXDOMAIN across both checks
            confirmed = bool(nx1 and nx2)
        elif sig and not sig.nxdomain_required:
            # HTTP body fingerprint provider: verify second HTTP probe matches fingerprint + status
            status_ok = (not sig.http_status) or (probe.status_code in sig.http_status)
            fp_matched = False
            if probe.body and sig.http_fingerprints:
                for fp in sig.http_fingerprints:
                    if fp.lower() in probe.body.lower():
                        fp_matched = True
                        break
            if status_ok and fp_matched:
                confirmed = True
            elif finding.nxdomain and not finding.body_match and nx1 and nx2:
                confirmed = True
            else:
                confirmed = False
        else:
            # Generic orphaned CNAME without specific provider signature
            confirmed = bool(finding.nxdomain and nx1 and nx2)

    finding.cname_chain = chain or finding.cname_chain
    finding.verified = confirmed
    finding.verify_nxdomain_1 = nx1
    finding.verify_nxdomain_2 = nx2
    finding.verify_http = probe.status_code
    finding.cname_still_present = cname_still_present

    return finding
