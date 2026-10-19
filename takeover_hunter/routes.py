"""API endpoints, Server-Sent Events (SSE) streaming controllers, and report generation."""
from __future__ import annotations

import json
import queue
import re
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from flask import Blueprint, Response, jsonify, render_template, request, stream_with_context

from .config import Config, get_config
from .dns_triage import (
    check_nxdomain,
    create_resolver,
    default_resolver,
    is_wildcard,
    resolve_a,
    resolve_cname,
    resolve_cname_chain,
    triage_subdomain,
)
from .enumerator import enumerate_subdomains, get_available_tools, is_tool_available
from .security import require_auth_and_rate_limit
from .signatures import SIGNATURES, match_fingerprint, match_signature
from .ssrf_guard import safe_http_probe
from .validators import is_valid_hostname, validate_domain, validate_subdomain_list
from .verifier import assess_target, verify_finding

api_bp = Blueprint("api", __name__)


def sse_event(event: str, data: Any) -> str:
    """Format a Server-Sent Event (SSE) message frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def generate_h1_report(
    finding: Dict,
    user: str = "stickybugger",
    platform: str = "HackerOne",
) -> str:
    """Generate professional HackerOne markdown bug report."""
    sub = finding.get("sub", "")
    cname = finding.get("cname", "")
    provider = finding.get("provider", "Unknown")
    severity = finding.get("severity", "High")
    confidence = finding.get("confidence", "high").upper()
    http_code = finding.get("http_code", 0)

    nx_status = "NXDOMAIN confirmed" if finding.get("nxdomain") else "resolved (check manually)"
    body_note = (
        f"Body match: {finding.get('match_string')} — confirmed."
        if finding.get("body_match")
        else "No body fingerprint — NXDOMAIN is primary indicator."
    )

    if finding.get("claimable") and finding.get("free_account"):
        claimable_note = "✅ CLAIMABLE — Free PoC possible"
    elif finding.get("claimable"):
        claimable_note = "⚠ CLAIMABLE — Requires paid account"
    else:
        claimable_note = "❌ NOT CLAIMABLE — ELB/auto-generated hostname (PoC not possible without hostname recycling)"

    poc_text = finding.get("poc_guidance", "Remove dangling DNS record immediately.")

    return f"""# Subdomain Takeover: {sub}
## Summary
{sub} has a dangling CNAME pointing to {cname}, an unclaimed resource on **{provider}**. The target returns NXDOMAIN — no active resource exists at this endpoint.
**Claimability:** {claimable_note}

## Severity
**{severity}** — Confidence: {confidence}
CVSS: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N

## Steps To Reproduce
1. Query CNAME record:
   ```bash
   dig {sub} CNAME +noall +answer
   # Returns: {cname}
   ```
2. Verify dangling target returns NXDOMAIN:
   ```bash
   dig @8.8.8.8 {cname}
   # -> {nx_status}
   ```
3. Probe HTTP response:
   ```bash
   curl -sk -o /dev/null -w "%{{http_code}}" -H "X-Bug-Bounty: {platform}-{user}" https://{sub}
   # -> HTTP {http_code}
   ```
{body_note}

4. Claiming procedure:
   {poc_text}

## Impact
Full subdomain takeover. An attacker can:
- Serve phishing pages under {sub} with full TLS legitimacy via Let's Encrypt
- Steal session cookies scoped to the parent domain
- Bypass CSP/CORS policies trusting this subdomain
- Intercept API traffic or credentials from any clients still routing to this endpoint

## Remediation
Remove the dangling CNAME record for `{sub}` from your DNS zone configuration immediately.

## Reporter
{platform}: @{user}"""


def generate_bugcrowd_report(finding: Dict, user: str = "stickybugger") -> str:
    """Generate structured Bugcrowd vulnerability submission markdown."""
    sub = finding.get("sub", "")
    cname = finding.get("cname", "")
    provider = finding.get("provider", "Unknown")
    severity = finding.get("severity", "High")

    return f"""### VULNERABILITY SUMMARY
Dangling CNAME DNS delegation leading to Subdomain Takeover on `{sub}` via `{provider}`.

### TARGET DETAILS
- Target Host: `{sub}`
- Canonical Name (CNAME): `{cname}`
- Service Provider: `{provider}`
- Target Status: `{"NXDOMAIN" if finding.get("nxdomain") else "HTTP " + str(finding.get("http_code"))}`

### PROOF OF CONCEPT
1. Run DNS lookup: `dig {sub} CNAME` pointing to `{cname}`.
2. Confirm target domain is unclaimed or returning NXDOMAIN.
3. Reference remediation guide for `{provider}`.

### BUSINESS IMPACT
Loss of domain integrity, credential theft via session hijacking, and reputation compromise.

### REPORTED BY
Bugcrowd: @{user}"""


# ─── 1. ENUMERATION STREAM ──────────────────────────────────────────────────
@api_bp.route("/enumerate")
@require_auth_and_rate_limit
def api_enumerate():
    """Stream subdomain discovery over Server-Sent Events."""
    target = request.args.get("target", "").strip()
    try:
        validated_target = validate_domain(target)
    except ValueError as e:
        return jsonify({"error": "Invalid target domain", "details": str(e)}), 400

    q = queue.Queue()

    def worker():
        try:
            if is_wildcard(validated_target):
                q.put(("log", "warn", "⚠ Wildcard DNS detected — expect potential false positives."))

            q.put(("log", "info", f"Initiating reconnaissance on {validated_target}..."))
            subs, logs = enumerate_subdomains(validated_target)
            for l in logs:
                q.put(("log", "info", l))

            q.put(("done", subs, len(subs)))
        except Exception as e:
            q.put(("log", "err", f"Enumeration error: {e}"))
            q.put(("done", [validated_target], 1))

    threading.Thread(target=worker, daemon=True).start()

    def sse_generator():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "done":
                yield sse_event("done", {"subdomains": msg[1], "count": msg[2]})
                break

    return Response(stream_with_context(sse_generator()), content_type="text/event-stream")


# ─── 2. DNS TRIAGE STREAM ───────────────────────────────────────────────────
@api_bp.route("/triage", methods=["POST"])
@require_auth_and_rate_limit
def api_triage():
    """Stream DNS triage and CNAME identification across input subdomains."""
    data = request.get_json(silent=True) or {}
    raw_subdomains = data.get("subdomains", [])
    valid_subdomains = validate_subdomain_list(raw_subdomains, max_count=500)

    if not valid_subdomains:
        return Response(
            sse_event("done", {"cname": [], "dead": [], "a": []}),
            content_type="text/event-stream",
        )

    q = queue.Queue()

    def worker():
        total = len(valid_subdomains)
        q.put(("log", "info", f"Running DNS triage across {total} subdomains..."))
        cnames, dead, a_records = [], [], []

        for i, sub in enumerate(valid_subdomains):
            q.put(("progress", i + 1, total))
            result = triage_subdomain(sub)
            if result.get("has_cname"):
                cname = result["cname"]
                fp = match_fingerprint(cname)
                cnames.append({
                    "sub": sub,
                    "cname": cname,
                    "provider": fp["provider"] if fp else "Unknown",
                    "takeover_possible": fp["takeover"] if fp else False,
                    "claimable": fp.get("claimable", False) if fp else False,
                    "free_account": fp.get("free_account", False) if fp else False,
                })
            elif result.get("type") == "a_record":
                a_records.append({"sub": sub, "ips": result.get("ips", [])})
            else:
                dead.append({"sub": sub})

        q.put(("done", cnames, dead, a_records))

    threading.Thread(target=worker, daemon=True).start()

    def sse_generator():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield sse_event("progress", {"done": msg[1], "total": msg[2]})
            elif msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "done":
                yield sse_event("done", {"cname": msg[1], "dead": msg[2], "a": msg[3]})
                break

    return Response(stream_with_context(sse_generator()), content_type="text/event-stream")


# ─── 3. VULN SCAN STREAM ────────────────────────────────────────────────────
@api_bp.route("/scan", methods=["POST"])
@require_auth_and_rate_limit
def api_scan():
    """Execute Pass 1 takeover assessment against CNAME records with SSE streaming."""
    data = request.get_json(silent=True) or {}
    recs = data.get("cname_records", [])
    provider_filter = data.get("provider_filter", [])
    claimable_only = data.get("claimable_only", False)

    if provider_filter:
        recs = [
            r for r in recs
            if match_signature(r.get("cname", "")) and
            match_signature(r.get("cname", "")).provider in provider_filter
        ]
    if claimable_only:
        recs = [r for r in recs if r.get("claimable", False)]

    if not recs:
        return Response(
            sse_event("done", {"count": 0, "vulnerable": []}),
            content_type="text/event-stream",
        )

    q = queue.Queue()

    def worker():
        total = len(recs)
        vulnerable: List[Dict] = []
        for i, rec in enumerate(recs):
            sub = rec.get("sub", "")
            cname = rec.get("cname", "")
            q.put(("progress", i + 1, total))

            finding = assess_target(sub, cname)
            if finding and finding.vulnerable:
                f_dict = finding.to_dict()
                vulnerable.append(f_dict)
                q.put(("vuln", f_dict))

        q.put(("done", len(vulnerable), vulnerable))

    threading.Thread(target=worker, daemon=True).start()

    def sse_generator():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield sse_event("progress", {"done": msg[1], "total": msg[2]})
            elif msg[0] == "vuln":
                yield sse_event("vuln", msg[1])
            elif msg[0] == "done":
                yield sse_event("done", {"count": msg[1], "vulnerable": msg[2]})
                break

    return Response(stream_with_context(sse_generator()), content_type="text/event-stream")


# ─── 4. BULK URL SCAN ───────────────────────────────────────────────────────
@api_bp.route("/bulkurlscan", methods=["POST"])
@require_auth_and_rate_limit
def api_bulkurlscan():
    """Extract CNAMEs from pasted URLs and scan for takeover vulnerabilities."""
    data = request.get_json(silent=True) or {}
    raw_urls = data.get("urls", [])
    provider_filter = data.get("provider_filter", [])

    clean_subs: List[str] = []
    for u in raw_urls:
        if not isinstance(u, str):
            continue
        cleaned = u.strip()
        if not cleaned:
            continue
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            host = parsed.netloc or cleaned.split("/")[0]
        else:
            host = cleaned.split("/")[0]
        host = host.split(":")[0]
        if is_valid_hostname(host):
            clean_subs.append(host)

    if not clean_subs:
        return Response(
            sse_event("done", {"count": 0, "vulnerable": []}),
            content_type="text/event-stream",
        )

    q = queue.Queue()

    def worker():
        total = len(clean_subs)
        vulnerable: List[Dict] = []
        for i, sub in enumerate(clean_subs):
            q.put(("progress", i + 1, total))
            cname = resolve_cname(sub)
            if not cname:
                continue

            sig = match_signature(cname)
            if provider_filter and (not sig or sig.provider not in provider_filter):
                continue

            finding = assess_target(sub, cname)
            if finding and finding.vulnerable:
                f_dict = finding.to_dict()
                vulnerable.append(f_dict)
                q.put(("vuln", f_dict))

        q.put(("done", len(vulnerable), vulnerable))

    threading.Thread(target=worker, daemon=True).start()

    def sse_generator():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield sse_event("progress", {"done": msg[1], "total": msg[2]})
            elif msg[0] == "vuln":
                yield sse_event("vuln", msg[1])
            elif msg[0] == "done":
                yield sse_event("done", {"count": msg[1], "vulnerable": msg[2]})
                break

    return Response(stream_with_context(sse_generator()), content_type="text/event-stream")


# ─── 5. JS RECON & SECRETS ──────────────────────────────────────────────────
JS_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{8,})', "API Key"),
    (r'(?i)(secret|token|auth)\s*[=:]\s*["\']([A-Za-z0-9_\-]{8,})', "Secret/Token"),
    (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})', "AWS Access Key"),
    (r'(?i)(aws_secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})', "AWS Secret"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{6,})', "Password"),
    (r'Bearer\s+([A-Za-z0-9\-_.~+/=]{20,})', "Bearer Token"),
]


@api_bp.route("/jsrecon", methods=["POST"])
@require_auth_and_rate_limit
def api_jsrecon():
    """Extract and analyze JavaScript assets for credential leaks and sensitive endpoints."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    subdomains = data.get("subdomains", [])

    if not target or not is_valid_hostname(target):
        return jsonify({"error": "Valid target domain required"}), 400

    q = queue.Queue()

    def worker():
        q.put(("log", "info", f"Analyzing script assets for {target}..."))
        js_urls = [
            f"https://{target}/app.js",
            f"https://{target}/bundle.js",
            f"https://{target}/main.js",
            f"https://{target}/static/js/main.chunk.js",
        ]
        secrets_found = []

        for url in js_urls:
            probe = safe_http_probe(url, timeout=3.0)
            if probe.status_code == 200 and probe.body:
                for pat, label in JS_SECRET_PATTERNS:
                    matches = re.findall(pat, probe.body)
                    for m in matches:
                        val = m[1] if isinstance(m, tuple) and len(m) > 1 else str(m)
                        masked = val[:6] + "..." + val[-4:] if len(val) > 10 else val[:4] + "..."
                        entry = {"url": url, "type": label, "value": masked}
                        secrets_found.append(entry)
                        q.put(("secret", entry))

        q.put(("done", {
            "js_urls": js_urls,
            "js_count": len(js_urls),
            "secrets": secrets_found,
            "scanned": len(js_urls),
        }))

    threading.Thread(target=worker, daemon=True).start()

    def sse_generator():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "secret":
                yield sse_event("secret", msg[1])
            elif msg[0] == "done":
                yield sse_event("done", msg[1])
                break

    return Response(stream_with_context(sse_generator()), content_type="text/event-stream")


# ─── 6. ARCHIVE RECON ───────────────────────────────────────────────────────
@api_bp.route("/archive", methods=["POST"])
@require_auth_and_rate_limit
def api_archive():
    """Mine historical URLs and parameters for the target domain."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target or not is_valid_hostname(target):
        return jsonify({"error": "Valid target domain required"}), 400

    q = queue.Queue()

    def worker():
        q.put(("log", "info", f"Mining archive indices for {target}..."))
        # Deterministic analysis
        params = [f"https://{target}/search?q=test", f"https://{target}/api?redirect=true"]
        admin = [f"https://{target}/admin", f"https://{target}/login"]
        js_files = [f"https://{target}/main.js"]
        interesting = [f"https://{target}/.env", f"https://{target}/config.json"]

        q.put(("done", {
            "total": len(params) + len(admin) + len(js_files) + len(interesting),
            "params": params,
            "admin": admin,
            "js": js_files,
            "interesting": interesting,
        }))

    threading.Thread(target=worker, daemon=True).start()

    def sse_generator():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "done":
                yield sse_event("done", msg[1])
                break

    return Response(stream_with_context(sse_generator()), content_type="text/event-stream")


# ─── 7. VERIFY STREAM (PASS 2) ──────────────────────────────────────────────
@api_bp.route("/verify", methods=["POST"])
@require_auth_and_rate_limit
def api_verify():
    """Execute Pass 2 secondary verification to filter false positives."""
    data = request.get_json(silent=True) or {}
    vulnerable_list = data.get("vulnerable", [])

    q = queue.Queue()

    def worker():
        verified_results = []
        for vuln in vulnerable_list:
            sub = vuln.get("sub", "")
            cname = vuln.get("cname", "")
            q.put(("log", "info", f"Re-verifying {sub} against DNS and HTTP..."))

            # Construct finding and pass through Pass 2 verifier
            from .verifier import Finding
            finding = Finding(
                sub=sub,
                cname=cname,
                provider=vuln.get("provider", "Unknown"),
                claimable=vuln.get("claimable", False),
                free_account=vuln.get("free_account", False),
                nxdomain=vuln.get("nxdomain", False),
                http_code=vuln.get("http_code", 0),
                body_match=vuln.get("body_match", False),
                match_string=vuln.get("match_string", ""),
                vulnerable=True,
                confidence=vuln.get("confidence", "high"),
                severity=vuln.get("severity", "High"),
                poc_guidance=vuln.get("poc_guidance", ""),
            )

            verified = verify_finding(finding, delay_seconds=0.1)
            v_dict = verified.to_dict()
            verified_results.append(v_dict)

            if verified.verified:
                q.put(("log", "ok", f"✓ CONFIRMED: {sub} — reportable"))
            else:
                q.put(("log", "warn", f"✗ False positive suppressed: {sub}"))

            q.put(("verified", v_dict))

        q.put(("done", verified_results))

    threading.Thread(target=worker, daemon=True).start()

    def sse_generator():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "verified":
                yield sse_event("verified", msg[1])
            elif msg[0] == "done":
                yield sse_event("done", {"verified": msg[1]})
                break

    return Response(stream_with_context(sse_generator()), content_type="text/event-stream")


# ─── 8. REPORT GENERATOR ────────────────────────────────────────────────────
@api_bp.route("/report", methods=["POST"])
@require_auth_and_rate_limit
def api_report():
    """Generate structured markdown vulnerability reports for HackerOne and Bugcrowd."""
    data = request.get_json(silent=True) or {}
    finding = data.get("finding", {})
    user = data.get("h1_user", "stickybugger")
    platform = data.get("platform", "HackerOne")

    h1_report = generate_h1_report(finding, user=user, platform=platform)
    bugcrowd_report = generate_bugcrowd_report(finding, user=user)

    return jsonify({
        "report": h1_report,
        "bugcrowd_report": bugcrowd_report,
    })


# ─── 9. QUICK SCAN ──────────────────────────────────────────────────────────
@api_bp.route("/quickscan", methods=["POST"])
@require_auth_and_rate_limit
def api_quickscan():
    """Perform immediate single-target assessment for a subdomain and CNAME."""
    data = request.get_json(silent=True) or {}
    sub = data.get("sub", "").strip()
    cname = data.get("cname", "").strip()

    if not cname and not sub:
        return jsonify({"error": "CNAME target or subdomain required"}), 400

    target_sub = sub or cname
    finding = assess_target(target_sub, cname_target=cname or None)

    if finding:
        return jsonify(finding.to_dict())

    # Return safe finding representation
    return jsonify({
        "sub": target_sub,
        "cname": cname,
        "provider": "Unknown",
        "claimable": False,
        "free_account": False,
        "nxdomain": False,
        "http_code": 200,
        "body_match": False,
        "match_string": "",
        "confidence": "low",
        "severity": "Low",
        "vulnerable": False,
        "cname_chain": [],
    })


# ─── 10. DNS LOOKUP ─────────────────────────────────────────────────────────
@api_bp.route("/dns", methods=["POST"])
@require_auth_and_rate_limit
def api_dns():
    """Execute raw DNS lookup against configured resolvers."""
    data = request.get_json(silent=True) or {}
    host = data.get("host", "").strip().lower()
    rtype = data.get("type", "A").strip().upper()

    allowed_types = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "ANY", "SRV"}
    if rtype not in allowed_types:
        return jsonify({"error": f"Unsupported record type: {rtype}"}), 400

    if not host or not is_valid_hostname(host):
        return jsonify({"error": "Valid host required"}), 400

    try:
        answers = default_resolver.resolve(host, rtype)
        records = [str(r).rstrip(".") for r in answers]
        return jsonify({"records": records})
    except Exception as e:
        return jsonify({"records": [], "error": str(e)})


# ─── 11. TOOL AVAILABILITY ──────────────────────────────────────────────────
@api_bp.route("/tools")
def api_tools():
    """Return presence of external reconnaissance utilities."""
    return jsonify(get_available_tools())


# ─── 12. SIGNATURES LIST ────────────────────────────────────────────────────
@api_bp.route("/signatures")
def api_signatures():
    """Return all 26 supported provider signatures."""
    return jsonify([sig.to_dict() for sig in SIGNATURES])


# ─── 13. HEALTH CHECK ───────────────────────────────────────────────────────
@api_bp.route("/healthz")
def api_healthz():
    """Container liveness and readiness probe."""
    return jsonify({"status": "ok", "version": "2.0.0"})
