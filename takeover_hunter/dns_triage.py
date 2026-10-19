"""Native dnspython DNS triage, CNAME chaining, NXDOMAIN detection, and wildcard filtering."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import dns.exception
import dns.resolver

from .validators import is_valid_hostname


def create_resolver(
    nameservers: Optional[List[str]] = None,
    timeout: float = 3.0,
    lifetime: float = 5.0,
) -> dns.resolver.Resolver:
    """Create a configured dnspython Resolver instance."""
    res = dns.resolver.Resolver()
    res.nameservers = nameservers or ["8.8.8.8", "1.1.1.1"]
    res.timeout = timeout
    res.lifetime = lifetime
    return res


# Global default resolver
default_resolver = create_resolver()


def is_wildcard(domain: str, resolver: Optional[dns.resolver.Resolver] = None) -> bool:
    """Detect if wildcard DNS resolution is active on the target domain."""
    res = resolver or default_resolver
    clean_domain = domain.strip().lower().rstrip(".")
    test_host = f"takeover-test-{int(time.time() * 1000)}.{clean_domain}"
    try:
        res.resolve(test_host, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return False
    except Exception:
        return False


def resolve_cname(host: str, resolver: Optional[dns.resolver.Resolver] = None) -> Optional[str]:
    """Resolve the immediate CNAME target of a hostname without trailing dot."""
    res = resolver or default_resolver
    clean_host = host.strip().lower().rstrip(".")
    try:
        answers = res.resolve(clean_host, "CNAME")
        if answers:
            return str(answers[0].target).rstrip(".")
    except Exception:
        pass
    return None


def resolve_cname_chain(
    host: str,
    max_depth: int = 5,
    resolver: Optional[dns.resolver.Resolver] = None,
) -> List[str]:
    """Follow a CNAME delegation chain up to max_depth hops."""
    res = resolver or default_resolver
    chain: List[str] = []
    curr = host.strip().lower().rstrip(".")
    seen = {curr}

    for _ in range(max_depth):
        try:
            answers = res.resolve(curr, "CNAME")
            target = str(answers[0].target).rstrip(".")
            if not target or target in seen:
                break
            chain.append(target)
            seen.add(target)
            curr = target
        except Exception:
            break

    return chain


def check_nxdomain(host: str, resolver: Optional[dns.resolver.Resolver] = None) -> bool:
    """Check if a host returns NXDOMAIN on A and CNAME record queries."""
    res = resolver or default_resolver
    clean_host = host.strip().lower().rstrip(".")
    try:
        res.resolve(clean_host, "A")
        return False
    except dns.resolver.NXDOMAIN:
        # Also check CNAME just in case
        try:
            res.resolve(clean_host, "CNAME")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return True
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        return False
    except Exception:
        return False


def resolve_a(host: str, resolver: Optional[dns.resolver.Resolver] = None) -> List[str]:
    """Resolve all IPv4 A records for a host."""
    res = resolver or default_resolver
    clean_host = host.strip().lower().rstrip(".")
    try:
        answers = res.resolve(clean_host, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


def triage_subdomain(
    subdomain: str,
    resolver: Optional[dns.resolver.Resolver] = None,
) -> Dict:
    """Perform full DNS triage for a single subdomain."""
    res = resolver or default_resolver
    clean_sub = subdomain.strip().lower().rstrip(".")

    chain = resolve_cname_chain(clean_sub, resolver=res)
    immediate_cname = chain[0] if chain else resolve_cname(clean_sub, resolver=res)
    final_target = chain[-1] if chain else immediate_cname

    if immediate_cname:
        nx = check_nxdomain(final_target, resolver=res) if final_target else False
        return {
            "sub": clean_sub,
            "has_cname": True,
            "cname": immediate_cname,
            "chain": chain,
            "final_target": final_target,
            "nxdomain": nx,
            "type": "cname",
        }

    ips = resolve_a(clean_sub, resolver=res)
    if ips:
        return {
            "sub": clean_sub,
            "has_cname": False,
            "cname": None,
            "chain": [],
            "ips": ips,
            "nxdomain": False,
            "type": "a_record",
        }

    # If neither CNAME nor A record exists
    return {
        "sub": clean_sub,
        "has_cname": False,
        "cname": None,
        "chain": [],
        "ips": [],
        "nxdomain": True,
        "type": "dead",
    }


def triage_subdomain_bulk(
    subdomains: List[str],
    max_workers: int = 20,
    resolver: Optional[dns.resolver.Resolver] = None,
) -> Dict[str, List[Dict]]:
    """Triage a list of subdomains in parallel, sorting into CNAME, Dead, and A-records."""
    res = resolver or default_resolver
    valid_subs = [s for s in subdomains if is_valid_hostname(s)]

    cnames: List[Dict] = []
    dead: List[Dict] = []
    a_records: List[Dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(triage_subdomain, sub, res): sub for sub in valid_subs}
        for future in as_completed(futures):
            try:
                result = future.result()
                rtype = result.get("type")
                if rtype == "cname":
                    cnames.append(result)
                elif rtype == "dead":
                    dead.append({"sub": result["sub"]})
                elif rtype == "a_record":
                    a_records.append({"sub": result["sub"], "ips": result.get("ips", [])})
            except Exception:
                continue

    return {
        "cname": cnames,
        "dead": dead,
        "a": a_records,
    }
