#!/usr/bin/env python3
"""TAKEOVER.HUNTER V2 — Recon Beast Edition.

Automated subdomain takeover detection, DNS intelligence, and asset triage engine.
"""

import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests
import urllib3
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    stream_with_context,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)


def cmd_exists(name: str) -> bool:
    """Check if an external binary command exists on PATH."""
    return shutil.which(name) is not None


def is_safe_target(target: str) -> bool:
    """Validate target string to ensure it is a valid hostname and safe."""
    if not target or len(target) > 253:
        return False
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}[a-zA-Z0-9]$", target))


# ─── CLAIMABILITY TAGS & FINGERPRINTS ────────────────────────────────────────
FINGERPRINTS = [
    {
        "provider": "Heroku",
        "patterns": ["herokuapp.com"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "No such app",
    },
    {
        "provider": "GitHub Pages",
        "patterns": ["github.io", "githubusercontent.com"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "There isn't a GitHub Pages site",
    },
    {
        "provider": "AWS S3",
        "patterns": ["s3.amazonaws.com", "s3-website"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "NoSuchBucket",
    },
    {
        "provider": "AWS CloudFront",
        "patterns": ["cloudfront.net"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "Bad Request",
    },
    {
        "provider": "AWS ELB",
        "patterns": ["elb.amazonaws.com"],
        "takeover": True,
        "claimable": False,
        "free_account": False,
        "status_match": "",
    },
    {
        "provider": "Azure TM",
        "patterns": ["trafficmanager.net"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "",
    },
    {
        "provider": "Azure Web",
        "patterns": ["azurewebsites.net", "cloudapp.net"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "404 Web Site not found",
    },
    {
        "provider": "Fastly",
        "patterns": ["fastly.net"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "Fastly error: unknown domain",
    },
    {
        "provider": "Netlify",
        "patterns": ["netlify.app", "netlify.com"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "Not Found",
    },
    {
        "provider": "Vercel",
        "patterns": ["vercel.app", "now.sh"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "The deployment could not be found",
    },
    {
        "provider": "Webflow",
        "patterns": ["proxy.webflow.com", "webflow.io"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "The page you are looking for does not exist",
    },
    {
        "provider": "Pantheon",
        "patterns": ["pantheonsite.io"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "404 error unknown site",
    },
    {
        "provider": "Ghost",
        "patterns": ["ghost.io"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "The thing you were looking for is no longer here",
    },
    {
        "provider": "Shopify",
        "patterns": ["myshopify.com"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "Sorry, this shop is currently unavailable",
    },
    {
        "provider": "Tumblr",
        "patterns": ["tumblr.com"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "There's nothing here",
    },
    {
        "provider": "WordPress",
        "patterns": ["wordpress.com"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "Do you want to register",
    },
    {
        "provider": "Zendesk",
        "patterns": ["zendesk.com"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "Help Center Closed",
    },
    {
        "provider": "Bitbucket",
        "patterns": ["bitbucket.io"],
        "takeover": True,
        "claimable": True,
        "free_account": True,
        "status_match": "Repository not found",
    },
    {
        "provider": "Seismic",
        "patterns": ["seismic.com", "tenant-services"],
        "takeover": True,
        "claimable": False,
        "free_account": False,
        "status_match": "The page you are looking for does not exist",
    },
    {
        "provider": "Marketo",
        "patterns": ["mktoweb.com", "marketo.com"],
        "takeover": True,
        "claimable": True,
        "free_account": False,
        "status_match": "",
    },
]

JS_SECRET_PATTERNS = [
    (r'(?i)(api[*-]?key|apikey)\s*[=:]\s*["\']', "API Key"),
    (r'(?i)(secret|token|auth)\s*[=:]\s*["\']', "Secret/Token"),
    (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']', "AWS Access Key"),
    (r'(?i)(aws_secret)\s*[=:]\s*["\']', "AWS Secret"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']', "Password"),
    (r"Bearer\s+([A-Za-z0-9-*.]{20,})", "Bearer Token"),
]

# ─── DNS RESOLVER ─────────────────────────────────────────────────────────
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
resolver.timeout = 2.0
resolver.lifetime = 4.0
resolver.cache = None


def is_wildcard(domain: str) -> bool:
    try:
        resolver.resolve(f"takeover-test-{int(time.time())}.{domain}", "A")
        return True
    except (dns.exception.DNSException, Exception):
        return False


def resolve_cname_chain(subdomain: str):
    chain, curr = [], subdomain
    try:
        for _ in range(5):
            ans = resolver.resolve(curr, "CNAME")
            target = str(ans[0].target).rstrip(".")
            chain.append(target)
            curr = target
        return chain
    except (dns.exception.DNSException, Exception):
        return chain


def check_nxdomain(host: str) -> bool:
    try:
        resolver.resolve(host, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except (dns.exception.DNSException, Exception):
        return False


def resolve_a(host: str):
    try:
        return [str(r) for r in resolver.resolve(host, "A")]
    except (dns.exception.DNSException, Exception):
        return []


def resolve_cname(host: str):
    try:
        return str(resolver.resolve(host, "CNAME")[0].target).rstrip(".")
    except (dns.exception.DNSException, Exception):
        return None


def match_fingerprint(cname_target: str):
    if not cname_target:
        return None
    target_lower = cname_target.lower()
    for fp in FINGERPRINTS:
        if any(p in target_lower for p in fp["patterns"]):
            return fp
    return None


# ─── HTTP PROBE ───────────────────────────────────────────────────────────
def http_probe(subdomain: str):
    headers = {"User-Agent": "Mozilla/5.0", "X-Bug-Bounty": "HackerOne-stickybugger"}
    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{subdomain}",
                timeout=4,
                verify=False,
                allow_redirects=True,
                headers=headers,
            )
            return {
                "code": r.status_code,
                "body": r.text[:2000],
                "headers": dict(r.headers),
            }
        except (requests.RequestException, Exception):
            continue
    return {"code": 0, "body": "", "headers": {}}


def httpx_probe_bulk(subdomains):
    if not cmd_exists("httpx"):
        return {}
    try:
        inp = "\n".join(subdomains)
        result = subprocess.run(
            ["httpx", "-silent", "-status-code", "-title", "-json", "-no-color"],
            input=inp,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        out = {}
        for line in result.stdout.splitlines():
            try:
                d = json.loads(line)
                url = (
                    d.get("url", "")
                    .replace("https://", "")
                    .replace("http://", "")
                    .rstrip("/")
                )
                out[url] = {
                    "code": d.get("status-code", 0),
                    "title": d.get("title", ""),
                }
            except (json.JSONDecodeError, KeyError, ValueError):
                pass
        return out
    except (subprocess.SubprocessError, Exception):
        return {}


def sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ─── TOOL RUNNER ──────────────────────────────────────────────────────────
def _run_tool(cmd, label, q):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        q.put(("tool_done", label, lines, None))
    except (subprocess.SubprocessError, Exception) as e:
        q.put(("tool_done", label, [], str(e)))


# ─── ENUMERATION ──────────────────────────────────────────────────────────
def enumerate_subdomains_stream(target, q):
    collected = set()
    wildcard = is_wildcard(target)
    if wildcard:
        q.put(("log", "warn", "⚠ Wildcard DNS detected — expect false positives."))
    tool_q = queue.Queue()
    tools = []
    if cmd_exists("subfinder"):
        tools.append(
            threading.Thread(
                target=_run_tool,
                args=(f"subfinder -d {target} -silent -all", "subfinder", tool_q),
            )
        )
    if cmd_exists("assetfinder"):
        tools.append(
            threading.Thread(
                target=_run_tool,
                args=(f"assetfinder --subs-only {target}", "assetfinder", tool_q),
            )
        )
    if cmd_exists("amass"):
        tools.append(
            threading.Thread(
                target=_run_tool,
                args=(f"amass enum -passive -d {target} -timeout 60", "amass", tool_q),
            )
        )
    if cmd_exists("gau"):
        cmd_gau = (
            rf"gau --subs {target} 2>/dev/null | "
            rf"grep -oP '(?<=://)([a-zA-Z0-9.*-]+\.{re.escape(target)})' | sort -u"
        )
        tools.append(
            threading.Thread(
                target=_run_tool,
                args=(cmd_gau, "gau", tool_q),
            )
        )
    if cmd_exists("waybackurls"):
        cmd_wb = (
            rf"echo {target} | waybackurls 2>/dev/null | "
            rf"grep -oP '(?<=://)([a-zA-Z0-9.*-]+\.{re.escape(target)})' | sort -u"
        )
        tools.append(
            threading.Thread(
                target=_run_tool,
                args=(cmd_wb, "waybackurls", tool_q),
            )
        )
    if not tools:
        q.put(
            (
                "log",
                "warn",
                "⚠ External enumeration tools not detected. Direct DNS triage active.",
            )
        )
    for t in tools:
        t.daemon = True
        t.start()
    for _ in range(len(tools)):
        try:
            _, label, lines, err = tool_q.get(timeout=200)
            if err:
                q.put(("log", "err", f"{label} error: {err}"))
            for line in lines:
                if target in line.lower():
                    collected.add(line.lower().strip())
            q.put(("log", "ok", f"{label}: {len(lines)} results"))
        except (queue.Empty, Exception):
            break
    subdomains = list(collected)
    q.put(("enum_done", subdomains, len(subdomains)))


@app.route("/api/enumerate")
def api_enumerate():
    target = request.args.get("target", "").strip().lower()
    if not target:
        return jsonify({"error": "No target"}), 400
    if not is_safe_target(target):
        return jsonify({"error": "Invalid target domain syntax"}), 400

    q = queue.Queue()
    threading.Thread(
        target=enumerate_subdomains_stream, args=(target, q), daemon=True
    ).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "enum_done":
                yield sse_event("done", {"subdomains": msg[1], "count": msg[2]})
                break

    return Response(stream_with_context(gen()), content_type="text/event-stream")


# ─── DNS TRIAGE ───────────────────────────────────────────────────────────
def dnsx_resolve_bulk(subdomains):
    if not cmd_exists("dnsx"):
        return {}
    try:
        inp = "\n".join(subdomains)
        result = subprocess.run(
            ["dnsx", "-silent", "-cname", "-resp", "-json"],
            input=inp,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        out = {}
        for line in result.stdout.splitlines():
            try:
                d = json.loads(line)
                host = d.get("host", "")
                cnames = d.get("cname", [])
                if host and cnames:
                    out[host] = cnames[0].rstrip(".")
            except (json.JSONDecodeError, KeyError, IndexError):
                pass
        return out
    except (subprocess.SubprocessError, Exception):
        return {}


def triage_worker(subdomains, q):
    cnames, dead, a_records = [], [], []
    total = len(subdomains)
    q.put(
        (
            "log",
            "info",
            f"Running DNS triage on {total} subdomains"
            + (" via dnsx" if cmd_exists("dnsx") else "..."),
        )
    )
    bulk_cnames = dnsx_resolve_bulk(subdomains)
    for i, sub in enumerate(subdomains):
        q.put(("progress", i + 1, total))
        cname = bulk_cnames.get(sub) or resolve_cname(sub)
        if cname:
            fp = match_fingerprint(cname)
            cnames.append(
                {
                    "sub": sub,
                    "cname": cname,
                    "provider": fp["provider"] if fp else "Unknown",
                    "takeover_possible": fp["takeover"] if fp else False,
                    "claimable": fp.get("claimable", False) if fp else False,
                    "free_account": fp.get("free_account", False) if fp else False,
                }
            )
            continue
        ips = resolve_a(sub)
        if ips:
            a_records.append({"sub": sub, "ips": ips})
        else:
            dead.append({"sub": sub})
    q.put(("triage_done", cnames, dead, a_records))


@app.route("/api/triage", methods=["POST"])
def api_triage():
    data = request.json or {}
    subdomains = data.get("subdomains", [])
    if not subdomains:
        return Response(
            sse_event("done", {"cname": [], "dead": [], "a": []}),
            content_type="text/event-stream",
        )
    q = queue.Queue()
    threading.Thread(target=triage_worker, args=(subdomains, q), daemon=True).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield sse_event("progress", {"done": msg[1], "total": msg[2]})
            elif msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "triage_done":
                yield sse_event("done", {"cname": msg[1], "dead": msg[2], "a": msg[3]})
                break

    return Response(stream_with_context(gen()), content_type="text/event-stream")


# ─── VULN SCAN ────────────────────────────────────────────────────────────
def vuln_scan_worker_parallel(cname_records, q, max_workers=30):
    total = len(cname_records)
    vulnerable = []
    semaphore = threading.Semaphore(max_workers)

    def check_one(rec):
        with semaphore:
            sub = rec["sub"]
            chain = resolve_cname_chain(sub)
            target = chain[-1] if chain else rec.get("cname", "")
            nx = check_nxdomain(target)
            probe = http_probe(sub)
            fp = match_fingerprint(target)
            is_v = False
            conf = "low"
            body_match = False
            match_string = ""
            if nx:
                is_v = True
                conf = "high"
            elif (
                fp
                and fp.get("status_match")
                and fp["status_match"].lower() in probe["body"].lower()
            ):
                is_v = True
                conf = "high"
                body_match = True
                match_string = fp["status_match"]
            elif fp and fp.get("takeover") and probe["code"] in [0, 404]:
                is_v = True
                conf = "medium"
            if is_v:
                sev = (
                    "Critical"
                    if any(
                        x in sub
                        for x in [
                            "auth",
                            "login",
                            "api",
                            "sso",
                            "account",
                            "id",
                            "pay",
                            "wallet",
                        ]
                    )
                    else "High"
                )
                result = {
                    "sub": sub,
                    "cname": target,
                    "provider": fp["provider"] if fp else "Orphaned",
                    "claimable": fp.get("claimable", False) if fp else False,
                    "free_account": fp.get("free_account", False) if fp else False,
                    "nxdomain": nx,
                    "http_code": probe["code"],
                    "body_match": body_match,
                    "match_string": match_string,
                    "vulnerable": True,
                    "confidence": conf,
                    "severity": sev,
                }
                q.put(("vuln", result))
                return result
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_one, rec) for rec in cname_records]
        for i, future in enumerate(as_completed(futures)):
            q.put(("progress", i + 1, total))
            try:
                res = future.result()
                if res:
                    vulnerable.append(res)
            except Exception:
                pass
    q.put(("scan_done", vulnerable))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json or {}
    recs = data.get("cname_records", [])
    provider_filter = data.get("provider_filter", [])
    claimable_only = data.get("claimable_only", False)
    if not recs:
        return Response(
            sse_event("done", {"count": 0, "vulnerable": []}),
            content_type="text/event-stream",
        )
    if provider_filter:
        recs = [
            r
            for r in recs
            if match_fingerprint(r.get("cname", ""))
            and match_fingerprint(r.get("cname", ""))["provider"] in provider_filter
        ]
    if claimable_only:
        recs = [r for r in recs if r.get("claimable", False)]
    if not recs:
        return Response(
            sse_event("done", {"count": 0, "vulnerable": []}),
            content_type="text/event-stream",
        )

    q = queue.Queue()
    threading.Thread(
        target=vuln_scan_worker_parallel, args=(recs, q, 30), daemon=True
    ).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield sse_event("progress", {"done": msg[1], "total": msg[2]})
            elif msg[0] == "vuln":
                yield sse_event("vuln", msg[1])
            elif msg[0] == "scan_done":
                yield sse_event("done", {"count": len(msg[1]), "vulnerable": msg[1]})
                break
            elif msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})

    return Response(stream_with_context(gen()), content_type="text/event-stream")


# ─── BULK URL SCAN ────────────────────────────────────────────────────────
def bulk_url_scan_worker(urls, provider_filter, q, max_workers=20):
    """Extract CNAME from URLs or hostnames and scan for vulnerabilities."""
    total = len(urls)
    vulnerable = []
    semaphore = threading.Semaphore(max_workers)

    def check_url(raw_item):
        with semaphore:
            try:
                raw_str = raw_item.strip()
                if "://" in raw_str:
                    parsed = urlparse(raw_str)
                    subdomain = parsed.netloc or raw_str.split("/")[0]
                else:
                    subdomain = raw_str.split("/")[0]
                subdomain = subdomain.split(":")[0].strip().lower()
            except Exception:
                subdomain = raw_item.split("/")[0].strip().lower()

            if not subdomain:
                return None

            cname = resolve_cname(subdomain)
            fp = match_fingerprint(cname or subdomain)
            if not cname:
                if fp:
                    cname = subdomain
                else:
                    return None

            if provider_filter and (not fp or fp["provider"] not in provider_filter):
                return None

            chain = resolve_cname_chain(subdomain)
            target = chain[-1] if chain else cname
            nx = check_nxdomain(target)
            probe = http_probe(subdomain)

            is_v = False
            conf = "low"
            body_match = False
            match_string = ""
            if nx:
                is_v = True
                conf = "high"
            elif (
                fp
                and fp.get("status_match")
                and fp["status_match"].lower() in probe["body"].lower()
            ):
                is_v = True
                conf = "high"
                body_match = True
                match_string = fp["status_match"]
            elif fp and fp.get("takeover") and probe["code"] in [0, 404]:
                is_v = True
                conf = "medium"

            if is_v:
                sev = (
                    "Critical"
                    if any(
                        x in subdomain
                        for x in [
                            "auth",
                            "login",
                            "api",
                            "sso",
                            "account",
                            "id",
                            "pay",
                            "wallet",
                        ]
                    )
                    else "High"
                )
                result = {
                    "sub": subdomain,
                    "cname": target,
                    "provider": fp["provider"] if fp else "Orphaned",
                    "claimable": fp.get("claimable", False) if fp else False,
                    "free_account": fp.get("free_account", False) if fp else False,
                    "nxdomain": nx,
                    "http_code": probe["code"],
                    "body_match": body_match,
                    "match_string": match_string,
                    "vulnerable": True,
                    "confidence": conf,
                    "severity": sev,
                }
                q.put(("vuln", result))
                return result
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_url, u): u for u in urls}
        for i, future in enumerate(as_completed(futures)):
            q.put(("progress", i + 1, total))
            try:
                res = future.result()
                if res:
                    vulnerable.append(res)
            except Exception as e:
                q.put(
                    ("log", "err", f"Error scanning {futures[future]}: {str(e)[:60]}")
                )

    q.put(("scan_done", vulnerable))


@app.route("/api/bulkurlscan", methods=["POST"])
def api_bulkurlscan():
    data = request.json or {}
    urls = data.get("urls", [])
    provider_filter = data.get("provider_filter", [])

    cleaned = [u.strip() for u in urls if isinstance(u, str) and u.strip()]
    if not cleaned:
        return Response(
            sse_event("done", {"count": 0, "vulnerable": []}),
            content_type="text/event-stream",
        )

    q = queue.Queue()
    filter_msg = (
        f"Filtering: {', '.join(provider_filter)}"
        if provider_filter
        else "All providers"
    )
    q.put(("log", "info", f"Scanning {len(cleaned)} targets... [{filter_msg}]"))

    threading.Thread(
        target=bulk_url_scan_worker, args=(cleaned, provider_filter, q, 20), daemon=True
    ).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield sse_event("progress", {"done": msg[1], "total": msg[2]})
            elif msg[0] == "vuln":
                yield sse_event("vuln", msg[1])
            elif msg[0] == "scan_done":
                yield sse_event("done", {"count": len(msg[1]), "vulnerable": msg[1]})
                break
            elif msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})

    return Response(stream_with_context(gen()), content_type="text/event-stream")


# ─── JS RECON ─────────────────────────────────────────────────────────────
def _probe_live_fast(sub: str) -> bool:
    """Non-blocking HEAD probe — avoids 4s body download just to check liveness."""
    for scheme in ["https", "http"]:
        try:
            r = requests.head(
                f"{scheme}://{sub}",
                timeout=3,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if r.status_code not in [0, 502, 503, 504]:
                return True
        except (requests.RequestException, Exception):
            continue
    return False


def js_recon_worker(target, subdomains, q):
    """Extract JS files from live subdomains and scan for secrets."""
    if not subdomains:
        q.put(("log", "warn", "No subdomains provided for JS Recon"))
        q.put(("js_done", {"js_urls": [], "js_count": 0, "secrets": [], "scanned": 0}))
        return
    q.put(
        (
            "log",
            "info",
            f"JS Recon: probing liveness for {len(subdomains)} subdomains...",
        )
    )
    live_subs = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_probe_live_fast, s): s for s in subdomains[:50]}
        for fut in as_completed(futures):
            if fut.result():
                live_subs.append(futures[fut])
    q.put(("log", "ok", f"Live subdomains: {len(live_subs)}"))
    if not live_subs:
        q.put(("log", "warn", "No live subdomains — skipping crawler"))

    js_urls = set()
    secrets_found = []

    if cmd_exists("katana") and live_subs:
        q.put(
            ("log", "info", f"katana: crawling {min(10, len(live_subs))} live hosts...")
        )
        try:
            inp = "\n".join([f"https://{s}" for s in live_subs[:10]])
            result = subprocess.run(
                ["katana", "-silent", "-jc", "-d", "2", "-f", "endpoint", "-list", "-"],
                input=inp,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            before = len(js_urls)
            for line in result.stdout.splitlines():
                if ".js" in line.lower() and line.strip():
                    js_urls.add(line.strip())
            added = len(js_urls) - before
            if added > 0:
                q.put(("log", "ok", f"katana: {added} JS files"))
            else:
                q.put(("log", "warn", "katana: no JS files found"))
        except (subprocess.SubprocessError, Exception) as e:
            q.put(("log", "err", f"katana: {str(e)[:60]}"))

    if cmd_exists("waybackurls"):
        q.put(("log", "info", "waybackurls: mining archive..."))
        try:
            result = subprocess.run(
                rf"echo {target} | waybackurls 2>/dev/null | grep '\.js' | sort -u",
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            before = len(js_urls)
            for line in result.stdout.splitlines():
                if line.strip():
                    js_urls.add(line.strip())
            added = len(js_urls) - before
            q.put(
                (
                    "log",
                    "ok" if added > 0 else "warn",
                    f"waybackurls: +{added} JS files",
                )
            )
        except (subprocess.SubprocessError, Exception) as e:
            q.put(("log", "err", f"waybackurls: {str(e)[:60]}"))

    if cmd_exists("gau"):
        q.put(("log", "info", "gau: mining archives..."))
        try:
            result = subprocess.run(
                rf"gau {target} 2>/dev/null | grep '\.js' | sort -u",
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            before = len(js_urls)
            for line in result.stdout.splitlines():
                if line.strip():
                    js_urls.add(line.strip())
            added = len(js_urls) - before
            q.put(("log", "ok" if added > 0 else "warn", f"gau: +{added} JS files"))
        except (subprocess.SubprocessError, Exception) as e:
            q.put(("log", "err", f"gau: {str(e)[:60]}"))

    if not js_urls:
        q.put(("log", "warn", "No JS files found across available tools"))
        q.put(("js_done", {"js_urls": [], "js_count": 0, "secrets": [], "scanned": 0}))
        return

    q.put(("log", "ok", f"Total: {len(js_urls)} JS files found"))
    q.put(("log", "info", "Scanning up to 50 for secrets..."))

    scanned = 0
    for url in list(js_urls)[:50]:
        try:
            r = requests.get(
                url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"}
            )
            if r.status_code == 200:
                content = r.text
                for pattern, label in JS_SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        val = match[-1] if isinstance(match, tuple) else match
                        if len(val) > 8:
                            entry = {
                                "url": url,
                                "type": label,
                                "value": val[:40] + "...",
                            }
                            secrets_found.append(entry)
                            q.put(("secret", entry))
            scanned += 1
        except (requests.RequestException, Exception):
            pass

    if secrets_found:
        q.put(("log", "warn", f"{len(secrets_found)} secrets found!"))
    else:
        q.put(("log", "ok", f"Scanned {scanned} files — no secrets found"))

    q.put(
        (
            "js_done",
            {
                "js_urls": list(js_urls)[:100],
                "js_count": len(js_urls),
                "secrets": secrets_found,
                "scanned": scanned,
            },
        )
    )


@app.route("/api/jsrecon", methods=["POST"])
def api_jsrecon():
    data = request.json or {}
    target = data.get("target", "").strip().lower()
    subdomains = data.get("subdomains", [])
    if not target:
        return jsonify({"error": "target required"}), 400
    if not is_safe_target(target):
        return jsonify({"error": "Invalid target domain syntax"}), 400

    q = queue.Queue()
    threading.Thread(
        target=js_recon_worker, args=(target, subdomains, q), daemon=True
    ).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "secret":
                yield sse_event("secret", msg[1])
            elif msg[0] == "js_done":
                yield sse_event("done", msg[1])
                break

    return Response(stream_with_context(gen()), content_type="text/event-stream")


# ─── ARCHIVE RECON ────────────────────────────────────────────────────────
def archive_recon_worker(target, q):
    """Mine gau + waybackurls for endpoints, parameters, and interesting paths."""
    urls = set()
    if cmd_exists("gau"):
        q.put(("log", "info", "gau: mining archives..."))
        try:
            result = subprocess.run(
                f"gau --subs {target} 2>/dev/null | sort -u",
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            for line in result.stdout.splitlines():
                if line.strip():
                    urls.add(line.strip())
            q.put(("log", "ok", f"gau: {len(urls)} URLs"))
        except (subprocess.SubprocessError, Exception):
            pass

    if cmd_exists("waybackurls"):
        q.put(("log", "info", "waybackurls: mining archive..."))
        try:
            result = subprocess.run(
                f"echo {target} | waybackurls 2>/dev/null | sort -u",
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            before = len(urls)
            for line in result.stdout.splitlines():
                if line.strip():
                    urls.add(line.strip())
            new_urls = len(urls) - before
            q.put(("log", "ok", f"waybackurls: +{new_urls} URLs"))
        except (subprocess.SubprocessError, Exception):
            pass

    q.put(("log", "info", f"Analyzing {len(urls)} URLs..."))
    params = [u for u in urls if "=" in u]
    admin = [
        u
        for u in urls
        if any(
            x in u.lower()
            for x in ["admin", "login", "dashboard", "panel", "auth", "api"]
        )
    ]
    js_files = [u for u in urls if ".js" in u.lower()]
    interesting = [
        u
        for u in urls
        if any(
            x in u.lower()
            for x in [
                "config",
                "backup",
                "env",
                "secret",
                "key",
                "token",
                ".git",
                ".env",
            ]
        )
    ]

    if admin:
        q.put(("log", "warn", f"ADMIN ENDPOINTS: {len(admin)} found"))
    if interesting:
        q.put(("log", "warn", f"INTERESTING PATHS: {len(interesting)} found"))
    q.put(("log", "ok", f"Parameters: {len(params)} | JS: {len(js_files)}"))
    q.put(
        (
            "archive_done",
            {
                "total": len(urls),
                "params": params[:200],
                "admin": admin[:100],
                "js": js_files[:100],
                "interesting": interesting[:100],
            },
        )
    )


@app.route("/api/archive", methods=["POST"])
def api_archive():
    data = request.json or {}
    target = data.get("target", "").strip().lower()
    if not target:
        return jsonify({"error": "target required"}), 400
    if not is_safe_target(target):
        return jsonify({"error": "Invalid target domain syntax"}), 400

    q = queue.Queue()
    threading.Thread(target=archive_recon_worker, args=(target, q), daemon=True).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "archive_done":
                yield sse_event("done", msg[1])
                break

    return Response(stream_with_context(gen()), content_type="text/event-stream")


# ─── VERIFY ───────────────────────────────────────────────────────────────
def verify_worker(vulnerable_list, q):
    verified_results = []
    for vuln in vulnerable_list:
        sub, cname = vuln["sub"], vuln["cname"]
        q.put(("log", "info", f"Verifying {sub}..."))
        nx1 = check_nxdomain(cname)
        time.sleep(0.3)
        nx2 = check_nxdomain(cname)
        probe = http_probe(sub)
        live_cname = resolve_cname(sub)
        cname_still_present = (
            live_cname is not None and cname.lower() in live_cname.lower()
        )
        confirmed = nx1 and nx2 and cname_still_present
        result = {
            **vuln,
            "verified": confirmed,
            "verify_nxdomain_1": nx1,
            "verify_nxdomain_2": nx2,
            "verify_http": probe["code"],
            "cname_still_present": cname_still_present,
        }
        verified_results.append(result)
        if confirmed:
            q.put(("log", "ok", f"✓ CONFIRMED: {sub} — reportable"))
        else:
            q.put(("log", "warn", f"✗ Not confirmed: {sub}"))
        q.put(("verified", result))
    q.put(("verify_done", verified_results))


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.json or {}
    vulnerable_list = data.get("vulnerable", [])
    q = queue.Queue()
    threading.Thread(
        target=verify_worker, args=(vulnerable_list, q), daemon=True
    ).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "verified":
                yield sse_event("verified", msg[1])
            elif msg[0] == "verify_done":
                yield sse_event("done", {"verified": msg[1]})
                break

    return Response(stream_with_context(gen()), content_type="text/event-stream")


# ─── REPORT ───────────────────────────────────────────────────────────────
@app.route("/api/report", methods=["POST"])
def api_report():
    data = request.json or {}
    f = data.get("finding", {})
    user = data.get("h1_user", "stickybugger")
    platform = data.get("platform", "HackerOne")
    nx_status = (
        "NXDOMAIN confirmed" if f.get("nxdomain") else "resolved (check manually)"
    )
    body_note = (
        f"Body match: {f.get('match_string')} — confirmed."
        if f.get("body_match")
        else "No body fingerprint — NXDOMAIN is primary indicator."
    )
    claimable_note = (
        "✅ CLAIMABLE — Free PoC possible"
        if f.get("claimable") and f.get("free_account")
        else "⚠ CLAIMABLE — Requires paid account"
        if f.get("claimable")
        else "❌ NOT CLAIMABLE — ELB/auto-generated hostname"
    )
    summary_text = (
        f"{f.get('sub')} has a dangling CNAME pointing to {f.get('cname')}, "
        f"an unclaimed resource on **{f.get('provider')}**. "
        "The target returns NXDOMAIN — no active resource exists."
    )
    report = f"""# Subdomain Takeover: {f.get("sub")}
## Summary
{summary_text}
**Claimability:** {claimable_note}
## Severity
**{f.get("severity")}** — Confidence: {f.get("confidence", "high").upper()}
CVSS: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N
## Steps To Reproduce

dig {f.get("sub")} CNAME +noall +answer
   → Returns: {f.get("cname")}
dig @8.8.8.8 {f.get("cname")}
   → {nx_status}
curl -sk -o /dev/null -w "%{{http_code}}" -H "X-Bug-Bounty: {platform}-{user}" https://{f.get("sub")}
   → HTTP {f.get("http_code")}
{body_note}

## Impact
Full subdomain takeover. An attacker can:

Serve phishing pages under {f.get("sub")} with full TLS legitimacy via Let's Encrypt
Steal session cookies scoped to the parent domain
Bypass CSP/CORS policies trusting this subdomain
Intercept API traffic or credentials from any clients still routing to this endpoint

## Remediation
Remove the dangling CNAME record for {f.get("sub")} from DNS immediately.
## Supporting Material

Terminal screenshot: dig {f.get("sub")} CNAME +noall +answer
Terminal screenshot: dig @8.8.8.8 {f.get("cname")}
Terminal screenshot: curl HTTP {f.get("http_code")} response
Reference: https://github.com/EdOverflow/can-i-take-over-xyz
Testing header: X-Bug-Bounty: {platform}-{user}

## Reporter
{platform}: @{user}"""
    return jsonify({"report": report})


# ─── QUICK SCAN ───────────────────────────────────────────────────────────
@app.route("/api/quickscan", methods=["POST"])
def api_quickscan():
    data = request.json or {}
    sub = data.get("sub", "").strip()
    cname = data.get("cname", "").strip()
    if not cname:
        return jsonify({"error": "cname required"}), 400
    chain = resolve_cname_chain(sub) if sub and sub != cname else []
    target = chain[-1] if chain else cname
    nx = check_nxdomain(target)
    probe = http_probe(sub or cname)
    fp = match_fingerprint(target)
    is_v = False
    conf = "low"
    body_match = False
    match_str = ""
    if nx:
        is_v = True
        conf = "high"
    elif (
        fp
        and fp.get("status_match")
        and fp["status_match"].lower() in probe["body"].lower()
    ):
        is_v = True
        conf = "high"
        body_match = True
        match_str = fp["status_match"]
    elif fp and fp.get("takeover") and probe["code"] in [0, 404]:
        is_v = True
        conf = "medium"
    sev = (
        "Critical"
        if any(
            x in (sub or cname)
            for x in ["auth", "login", "api", "sso", "account", "id", "pay"]
        )
        else "High"
    )
    return jsonify(
        {
            "sub": sub or cname,
            "cname": target,
            "provider": fp["provider"] if fp else "Unknown",
            "claimable": fp.get("claimable", False) if fp else False,
            "free_account": fp.get("free_account", False) if fp else False,
            "nxdomain": nx,
            "http_code": probe["code"],
            "body_match": body_match,
            "match_string": match_str,
            "confidence": conf,
            "severity": sev,
            "vulnerable": is_v,
            "cname_chain": chain,
        }
    )


# ─── DNS LOOKUP ───────────────────────────────────────────────────────────
@app.route("/api/dns", methods=["POST"])
def api_dns():
    data = request.json or {}
    host = data.get("host", "").strip()
    rtype = data.get("type", "A").strip().upper()
    allowed = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "ANY", "SRV"}
    if rtype not in allowed:
        return jsonify({"error": f"Unsupported: {rtype}"}), 400
    if not host:
        return jsonify({"error": "host required"}), 400
    try:
        if rtype == "ANY":
            records = []
            for t in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
                try:
                    ans = resolver.resolve(host, t)
                    records.extend([f"[{t}] {r!s}" for r in ans])
                except (dns.exception.DNSException, Exception):
                    pass
            return jsonify({"records": records or ["No records found"]})
        ans = resolver.resolve(host, rtype)
        records = []
        for r in ans:
            if rtype == "MX":
                records.append(f"{r.preference} {str(r.exchange).rstrip('.')}")
            elif rtype in ("CNAME", "NS"):
                records.append(str(r.target).rstrip("."))
            elif rtype == "TXT":
                records.append(
                    " ".join(
                        s.decode() if isinstance(s, bytes) else str(s)
                        for s in r.strings
                    )
                )
            else:
                records.append(str(r))
        return jsonify({"records": records})
    except dns.resolver.NXDOMAIN:
        return jsonify({"records": [], "error": "NXDOMAIN"})
    except dns.resolver.NoAnswer:
        return jsonify({"records": [], "error": f"No {rtype} records"})
    except dns.exception.Timeout:
        return jsonify({"records": [], "error": "Timeout"})
    except (dns.exception.DNSException, Exception) as e:
        return jsonify({"records": [], "error": str(e)})


# ─── TOOL CHECK ───────────────────────────────────────────────────────────
@app.route("/api/tools")
def api_tools():
    tools = [
        "subfinder",
        "assetfinder",
        "amass",
        "dnsx",
        "httpx",
        "katana",
        "gau",
        "waybackurls",
        "nuclei",
    ]
    return jsonify({t: cmd_exists(t) for t in tools})


# ─── INDEX ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "3000"))
    app.run(debug=False, host="0.0.0.0", port=port, threaded=True)
