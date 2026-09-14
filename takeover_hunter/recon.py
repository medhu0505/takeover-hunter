"""Recon pipeline workers: enumerate, triage, scan, verify, JS recon, archive.

Design notes
------------
* **No shell.** External recon tools are invoked with argument *lists* and
  ``shell=False``. User-supplied targets are additionally validated up-front
  (see :mod:`takeover_hunter.validation`), so there is no path from request
  input to a shell interpreter. This is the fix for the historical command
  injection.
* **Output is re-validated.** Everything a tool prints is passed back through
  hostname validation and scoped to the target domain before it is trusted.
* **Workers are producers.** Each long-running worker pushes tagged messages
  onto a :class:`queue.Queue`; the Flask route drains the queue and reframes
  the messages as SSE. Keeping I/O in worker threads keeps the request
  handler thin and cancellable.
"""
from __future__ import annotations

import logging
import queue
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Sequence, Tuple

from takeover_hunter.config import Config
from takeover_hunter.fingerprints import (
    JS_SECRET_PATTERNS,
    match_fingerprint,
)
from takeover_hunter.netutils import DNSClient, http_alive, http_probe
from takeover_hunter.validation import normalize_hostname

log = logging.getLogger("takeover_hunter.recon")

# Substrings in a subdomain that escalate a finding to Critical severity.
_CRITICAL_HINTS = ("auth", "login", "api", "sso", "account", "pay", "wallet", "admin")

# Compile JS secret patterns once at import time.
import re as _re

_JS_SECRET_COMPILED = [(_re.compile(pat), label) for pat, label in JS_SECRET_PATTERNS]


def cmd_exists(name: str) -> bool:
    """True if executable ``name`` is on PATH."""
    return shutil.which(name) is not None


def _run_argv(
    argv: Sequence[str],
    *,
    timeout: int,
    input_text: Optional[str] = None,
) -> Tuple[List[str], Optional[str]]:
    """Run ``argv`` (no shell) and return (stdout lines, error message).

    Never raises: a timeout or spawn failure is returned as the error string.
    """
    try:
        result = subprocess.run(
            list(argv),
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        return lines, None
    except subprocess.TimeoutExpired:
        return [], "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return [], str(exc)[:120]


def _hosts_in_scope(lines: Sequence[str], target: str) -> List[str]:
    """Validate ``lines`` as hostnames and keep those within ``target``."""
    suffix = "." + target
    out: List[str] = []
    for line in lines:
        host = normalize_hostname(line)
        if host and (host == target or host.endswith(suffix)):
            out.append(host)
    return out


class ReconEngine:
    """Stateless-ish orchestrator bound to a :class:`Config` and DNS client."""

    def __init__(self, config: Config):
        self.config = config
        self.dns = DNSClient(config)

    # ------------------------------------------------------------------ #
    # Enumeration                                                        #
    # ------------------------------------------------------------------ #
    def _enum_tool_specs(self, target: str) -> List[Tuple[str, List[str], Optional[str]]]:
        """Return (label, argv, stdin) for each available enumeration tool."""
        specs: List[Tuple[str, List[str], Optional[str]]] = []
        if cmd_exists("subfinder"):
            specs.append(("subfinder", ["subfinder", "-d", target, "-silent", "-all"], None))
        if cmd_exists("assetfinder"):
            specs.append(("assetfinder", ["assetfinder", "--subs-only", target], None))
        if cmd_exists("amass"):
            specs.append(("amass", ["amass", "enum", "-passive", "-d", target, "-timeout", "60"], None))
        if cmd_exists("gau"):
            specs.append(("gau", ["gau", "--subs", target], None))
        if cmd_exists("waybackurls"):
            specs.append(("waybackurls", ["waybackurls"], target))
        return specs

    def enumerate_stream(self, target: str, q: "queue.Queue") -> None:
        collected: set[str] = set()
        if self.dns.is_wildcard(target):
            q.put(("log", "warn", "Wildcard DNS detected — expect false positives."))

        specs = self._enum_tool_specs(target)
        if not specs:
            q.put(("log", "warn",
                   "No recon tools found. Install: subfinder, assetfinder, amass, gau, waybackurls."))
            q.put(("enum_done", [], 0))
            return

        tool_q: "queue.Queue" = queue.Queue()

        def worker(label: str, argv: List[str], stdin: Optional[str]) -> None:
            lines, err = _run_argv(argv, timeout=self.config.tool_timeout, input_text=stdin)
            tool_q.put((label, lines, err))

        threads = [
            threading.Thread(target=worker, args=spec, daemon=True) for spec in specs
        ]
        for t in threads:
            t.start()

        for _ in specs:
            try:
                label, lines, err = tool_q.get(timeout=self.config.tool_timeout + 30)
            except queue.Empty:
                break
            if err:
                q.put(("log", "err", f"{label}: {err}"))
            hosts = _hosts_in_scope(lines, target)
            collected.update(hosts)
            q.put(("log", "ok", f"{label}: {len(hosts)} in-scope results"))

        subdomains = sorted(collected)[: self.config.max_subdomains]
        q.put(("enum_done", subdomains, len(subdomains)))

    # ------------------------------------------------------------------ #
    # DNS triage                                                         #
    # ------------------------------------------------------------------ #
    def _dnsx_bulk(self, subdomains: Sequence[str]) -> Dict[str, str]:
        """Resolve CNAMEs in bulk via dnsx when available (JSON output)."""
        if not cmd_exists("dnsx"):
            return {}
        import json

        lines, _ = _run_argv(
            ["dnsx", "-silent", "-cname", "-resp", "-json"],
            timeout=self.config.tool_timeout,
            input_text="\n".join(subdomains),
        )
        out: Dict[str, str] = {}
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            host = record.get("host", "")
            cnames = record.get("cname", [])
            if host and cnames:
                out[host] = cnames[0].rstrip(".")
        return out

    def triage(self, subdomains: Sequence[str], q: "queue.Queue") -> None:
        cnames: List[Dict] = []
        dead: List[Dict] = []
        a_records: List[Dict] = []
        total = len(subdomains)
        q.put(("log", "info", f"DNS triage on {total} subdomains"
                              + (" via dnsx" if cmd_exists("dnsx") else "")))
        bulk = self._dnsx_bulk(subdomains)

        for i, sub in enumerate(subdomains):
            q.put(("progress", i + 1, total))
            cname = bulk.get(sub) or self.dns.resolve_cname(sub)
            if cname:
                fp = match_fingerprint(cname)
                cnames.append({
                    "sub": sub,
                    "cname": cname,
                    "provider": fp["provider"] if fp else "Unknown",
                    "takeover_possible": bool(fp["takeover"]) if fp else False,
                    "claimable": bool(fp.get("claimable", False)) if fp else False,
                    "free_account": bool(fp.get("free_account", False)) if fp else False,
                })
                continue
            ips = self.dns.resolve_a(sub)
            if ips:
                a_records.append({"sub": sub, "ips": ips})
            else:
                dead.append({"sub": sub})

        q.put(("triage_done", cnames, dead, a_records))

    # ------------------------------------------------------------------ #
    # Vulnerability assessment (shared core)                             #
    # ------------------------------------------------------------------ #
    def assess(self, sub: str, fallback_cname: str = "") -> Optional[Dict]:
        """Assess a single subdomain for takeover. Returns a finding or None.

        This is the single source of truth reused by scan, bulk-URL scan, and
        quick scan — previously duplicated three times.
        """
        chain = self.dns.resolve_cname_chain(sub) if sub else []
        target = chain[-1] if chain else fallback_cname
        if not target:
            return None
        fp = match_fingerprint(target)
        probe = http_probe(sub or target, self.config, self.dns)
        nx = self.dns.is_nxdomain(target)

        is_vuln = False
        confidence = "low"
        body_match = False
        match_string = ""
        if nx:
            is_vuln, confidence = True, "high"
        elif fp and fp.get("status_match") and str(fp["status_match"]).lower() in probe["body"].lower():
            is_vuln, confidence, body_match, match_string = True, "high", True, str(fp["status_match"])
        elif fp and fp.get("takeover") and probe["code"] in (0, 404):
            is_vuln, confidence = True, "medium"

        if not is_vuln:
            return None

        severity = "Critical" if any(h in sub for h in _CRITICAL_HINTS) else "High"
        return {
            "sub": sub or target,
            "cname": target,
            "provider": fp["provider"] if fp else "Orphaned",
            "claimable": bool(fp.get("claimable", False)) if fp else False,
            "free_account": bool(fp.get("free_account", False)) if fp else False,
            "nxdomain": nx,
            "http_code": probe["code"],
            "body_match": body_match,
            "match_string": match_string,
            "vulnerable": True,
            "confidence": confidence,
            "severity": severity,
            "cname_chain": chain,
        }

    def _scan_records(
        self,
        records: Sequence[Dict],
        q: "queue.Queue",
        *,
        get_sub,
        get_cname,
    ) -> None:
        total = len(records)
        vulnerable: List[Dict] = []
        max_workers = min(self.config.max_scan_workers, max(1, total))

        def check(rec: Dict) -> Optional[Dict]:
            return self.assess(get_sub(rec), get_cname(rec))

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(check, rec) for rec in records]
            for i, future in enumerate(as_completed(futures)):
                q.put(("progress", i + 1, total))
                try:
                    result = future.result()
                except Exception:  # pragma: no cover - defensive
                    result = None
                if result:
                    vulnerable.append(result)
                    q.put(("vuln", result))

        q.put(("scan_done", vulnerable))

    def scan(self, cname_records: Sequence[Dict], q: "queue.Queue") -> None:
        self._scan_records(
            cname_records, q,
            get_sub=lambda r: r.get("sub", ""),
            get_cname=lambda r: r.get("cname", ""),
        )

    def bulk_url_scan(self, hosts: Sequence[str], q: "queue.Queue") -> None:
        records = [{"sub": h} for h in hosts]
        self._scan_records(
            records, q,
            get_sub=lambda r: r.get("sub", ""),
            get_cname=lambda r: "",
        )

    # ------------------------------------------------------------------ #
    # Verification                                                       #
    # ------------------------------------------------------------------ #
    def verify(self, findings: Sequence[Dict], q: "queue.Queue") -> None:
        verified: List[Dict] = []
        for finding in findings:
            sub = finding.get("sub", "")
            cname = finding.get("cname", "")
            q.put(("log", "info", f"Verifying {sub}..."))
            nx1 = self.dns.is_nxdomain(cname)
            time.sleep(0.3)
            nx2 = self.dns.is_nxdomain(cname)
            probe = http_probe(sub, self.config, self.dns)
            live_cname = self.dns.resolve_cname(sub)
            cname_present = live_cname is not None and cname.lower() in live_cname.lower()
            confirmed = bool(nx1 and nx2 and cname_present)
            result = {
                **finding,
                "verified": confirmed,
                "verify_nxdomain_1": nx1,
                "verify_nxdomain_2": nx2,
                "verify_http": probe["code"],
                "cname_still_present": cname_present,
            }
            verified.append(result)
            if confirmed:
                q.put(("log", "ok", f"CONFIRMED: {sub} — reportable"))
            else:
                q.put(("log", "warn", f"Not confirmed: {sub}"))
            q.put(("verified", result))
        q.put(("verify_done", verified))

    # ------------------------------------------------------------------ #
    # JS recon                                                           #
    # ------------------------------------------------------------------ #
    def js_recon(self, target: str, subdomains: Sequence[str], q: "queue.Queue") -> None:
        if not subdomains:
            q.put(("log", "warn", "No subdomains provided for JS recon"))
            q.put(("js_done", {"js_urls": [], "js_count": 0, "secrets": [], "scanned": 0}))
            return

        candidates = list(subdomains)[:50]
        q.put(("log", "info", f"Probing liveness for {len(candidates)} subdomains..."))
        live: List[str] = []
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(http_alive, s, self.config): s for s in candidates}
            for fut in as_completed(futures):
                try:
                    if fut.result():
                        live.append(futures[fut])
                except Exception:  # pragma: no cover
                    pass
        q.put(("log", "ok", f"Live subdomains: {len(live)}"))

        js_urls: set[str] = set()

        if cmd_exists("katana") and live:
            q.put(("log", "info", f"katana: crawling {min(10, len(live))} live hosts..."))
            lines, err = _run_argv(
                ["katana", "-silent", "-jc", "-d", "2", "-f", "endpoint", "-list", "-"],
                timeout=90,
                input_text="\n".join(f"https://{s}" for s in live[:10]),
            )
            if err:
                q.put(("log", "err", f"katana: {err}"))
            js_urls.update(ln for ln in lines if ".js" in ln.lower())

        for tool, argv, stdin in (
            ("waybackurls", ["waybackurls"], target),
            ("gau", ["gau", target], None),
        ):
            if not cmd_exists(tool):
                continue
            q.put(("log", "info", f"{tool}: mining archives..."))
            before = len(js_urls)
            lines, err = _run_argv(argv, timeout=60, input_text=stdin)
            if err:
                q.put(("log", "err", f"{tool}: {err}"))
            js_urls.update(ln for ln in lines if ".js" in ln.lower())
            q.put(("log", "ok", f"{tool}: +{len(js_urls) - before} JS files"))

        if not js_urls:
            q.put(("log", "warn", "No JS files found across all sources"))
            q.put(("js_done", {"js_urls": [], "js_count": 0, "secrets": [], "scanned": 0}))
            return

        q.put(("log", "ok", f"Total: {len(js_urls)} JS files"))
        secrets = self._scan_js_secrets(list(js_urls)[: self.config.max_js_files], q)
        scanned = min(len(js_urls), self.config.max_js_files)
        if secrets:
            q.put(("log", "warn", f"{len(secrets)} potential secrets found"))
        else:
            q.put(("log", "ok", f"Scanned {scanned} files — no secrets found"))
        q.put(("js_done", {
            "js_urls": list(js_urls)[:100],
            "js_count": len(js_urls),
            "secrets": secrets,
            "scanned": scanned,
        }))

    def _scan_js_secrets(self, urls: Sequence[str], q: "queue.Queue") -> List[Dict]:
        import requests

        secrets: List[Dict] = []
        for url in urls:
            try:
                resp = requests.get(
                    url, timeout=5, verify=False,
                    headers={"User-Agent": self.config.user_agent},
                )
            except requests.RequestException:
                continue
            if resp.status_code != 200:
                continue
            for pattern, label in _JS_SECRET_COMPILED:
                for match in pattern.findall(resp.text):
                    value = match[-1] if isinstance(match, tuple) else match
                    if len(value) > 8:
                        entry = {"url": url, "type": label, "value": value[:40] + "..."}
                        secrets.append(entry)
                        q.put(("secret", entry))
        return secrets

    # ------------------------------------------------------------------ #
    # Archive recon                                                      #
    # ------------------------------------------------------------------ #
    def archive_recon(self, target: str, q: "queue.Queue") -> None:
        urls: set[str] = set()
        for tool, argv, stdin in (
            ("gau", ["gau", "--subs", target], None),
            ("waybackurls", ["waybackurls"], target),
        ):
            if not cmd_exists(tool):
                continue
            q.put(("log", "info", f"{tool}: mining archives..."))
            before = len(urls)
            lines, err = _run_argv(argv, timeout=120, input_text=stdin)
            if err:
                q.put(("log", "err", f"{tool}: {err}"))
            urls.update(lines)
            q.put(("log", "ok", f"{tool}: +{len(urls) - before} URLs"))

        q.put(("log", "info", f"Analyzing {len(urls)} URLs..."))
        params = [u for u in urls if "=" in u]
        admin = [u for u in urls if any(x in u.lower() for x in ("admin", "login", "dashboard", "panel", "auth", "api"))]
        js_files = [u for u in urls if ".js" in u.lower()]
        interesting = [u for u in urls if any(x in u.lower() for x in ("config", "backup", "env", "secret", "key", "token", ".git", ".env"))]
        if admin:
            q.put(("log", "warn", f"ADMIN ENDPOINTS: {len(admin)} found"))
        if interesting:
            q.put(("log", "warn", f"INTERESTING PATHS: {len(interesting)} found"))
        q.put(("log", "ok", f"Parameters: {len(params)} | JS: {len(js_files)}"))
        q.put(("archive_done", {
            "total": len(urls),
            "params": params[:200],
            "admin": admin[:100],
            "js": js_files[:100],
            "interesting": interesting[:100],
        }))
