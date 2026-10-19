"""Curated signature database of 26 cloud and SaaS providers for takeover auditing."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Signature:
    """Structured representation of a third-party service provider takeover fingerprint."""
    provider: str
    cname_patterns: List[str]
    http_fingerprints: List[str]
    http_status: List[int]
    nxdomain_required: bool
    claimable: bool
    severity: str
    poc_guidance: str
    free_account: bool = False

    def to_dict(self) -> Dict:
        """Serialize signature to standard dictionary format."""
        return {
            "provider": self.provider,
            "patterns": self.cname_patterns,
            "cname_patterns": self.cname_patterns,
            "http_fingerprints": self.http_fingerprints,
            "http_status": self.http_status,
            "nxdomain_required": self.nxdomain_required,
            "claimable": self.claimable,
            "free_account": self.free_account,
            "severity": self.severity,
            "poc_guidance": self.poc_guidance,
            "takeover": True,
            "status_match": self.http_fingerprints[0] if self.http_fingerprints else "",
        }


SIGNATURES: List[Signature] = [
    Signature(
        provider="Heroku",
        cname_patterns=["herokuapp.com", "herokussl.com", "herokudns.com"],
        http_fingerprints=["No such app", "Heroku | No such app", "There is no app configured at that hostname"],
        http_status=[404, 502],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Register a new Heroku application and add the custom domain via Dashboard or CLI: `heroku domains:add <subdomain>`.",
    ),
    Signature(
        provider="GitHub Pages",
        cname_patterns=["github.io", "githubusercontent.com"],
        http_fingerprints=["There isn't a GitHub Pages site here", "404 There isn't a GitHub Pages site here"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Create a GitHub repository with a CNAME file in the gh-pages or main branch pointing to the target subdomain.",
    ),
    Signature(
        provider="AWS S3",
        cname_patterns=["s3.amazonaws.com", "s3-website", "s3.dualstack", "s3-website-"],
        http_fingerprints=["NoSuchBucket", "The specified bucket does not exist"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="High",
        poc_guidance="Create an AWS S3 bucket matching the exact subdomain name in the appropriate region with static website hosting enabled.",
    ),
    Signature(
        provider="AWS CloudFront",
        cname_patterns=["cloudfront.net"],
        http_fingerprints=["Bad Request: ERROR: The request could not be satisfied", "The request could not be satisfied"],
        http_status=[403, 404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="Medium",
        poc_guidance="Create a CloudFront distribution with the custom domain name and appropriate SSL certificate (requires matching certificate in us-east-1).",
    ),
    Signature(
        provider="AWS ELB",
        cname_patterns=["elb.amazonaws.com", "awsglobalaccelerator.com"],
        http_fingerprints=[],
        http_status=[],
        nxdomain_required=True,
        claimable=False,
        free_account=False,
        severity="Medium",
        poc_guidance="AWS ELB hostname recycling is generally non-claimable without pre-allocated target DNS or race condition.",
    ),
    Signature(
        provider="Azure Web Apps",
        cname_patterns=["azurewebsites.net", "cloudapp.net", "azurecontainer.io"],
        http_fingerprints=["404 Web Site not found", "Error 404 - Web app not found"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Claim an App Service in Azure matching the orphaned hostname prefix, then bind the custom domain.",
    ),
    Signature(
        provider="Azure Traffic Manager",
        cname_patterns=["trafficmanager.net"],
        http_fingerprints=[],
        http_status=[],
        nxdomain_required=True,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Create an Azure Traffic Manager profile matching the prefix in the trafficmanager.net CNAME target.",
    ),
    Signature(
        provider="Fastly",
        cname_patterns=["fastly.net", "fastlylb.net"],
        http_fingerprints=["Fastly error: unknown domain", "unknown domain: "],
        http_status=[500, 404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="High",
        poc_guidance="Add the custom domain to a new Fastly service.",
    ),
    Signature(
        provider="Netlify",
        cname_patterns=["netlify.app", "netlify.com"],
        http_fingerprints=["Not Found - Request ID", "page not found", "Netlify - Page Not Found"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Claim custom domain in a Netlify team site settings.",
    ),
    Signature(
        provider="Vercel",
        cname_patterns=["vercel.app", "now.sh", "vercel-dns.com"],
        http_fingerprints=["The deployment could not be found on Vercel", "DEPLOYMENT_NOT_FOUND"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Add the custom domain to a Vercel project.",
    ),
    Signature(
        provider="Webflow",
        cname_patterns=["proxy.webflow.com", "proxy-ssl.webflow.com", "webflow.io"],
        http_fingerprints=["The page you are looking for does not exist", "The page you are looking for doesn't exist"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="High",
        poc_guidance="Add custom domain to a Webflow project dashboard.",
    ),
    Signature(
        provider="Pantheon",
        cname_patterns=["pantheonsite.io"],
        http_fingerprints=["404 error unknown site!", "The site you are looking for could not be found"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="High",
        poc_guidance="Create Pantheon site and map the custom domain.",
    ),
    Signature(
        provider="Ghost",
        cname_patterns=["ghost.io"],
        http_fingerprints=["The thing you were looking for is no longer here", "Ghost - Page Not Found"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="High",
        poc_guidance="Claim publication on Ghost(Pro) and configure custom domain.",
    ),
    Signature(
        provider="Shopify",
        cname_patterns=["myshopify.com"],
        http_fingerprints=["Sorry, this shop is currently unavailable", "Shopify | Store Not Found"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="High",
        poc_guidance="Add the custom domain in Shopify Online Store -> Domains.",
    ),
    Signature(
        provider="Tumblr",
        cname_patterns=["domains.tumblr.com", "tumblr.com"],
        http_fingerprints=["There's nothing here.", "Whatever you were looking for doesn't exist"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="Medium",
        poc_guidance="Assign the custom domain in Tumblr blog settings.",
    ),
    Signature(
        provider="WordPress.com",
        cname_patterns=["wordpress.com"],
        http_fingerprints=["Do you want to register", "doesn't exist"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="Medium",
        poc_guidance="Create a WordPress.com site and map domain.",
    ),
    Signature(
        provider="Zendesk",
        cname_patterns=["zendesk.com"],
        http_fingerprints=["Help Center Closed", "No such account"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="High",
        poc_guidance="Claim Zendesk subdomain with host mapping enabled.",
    ),
    Signature(
        provider="Bitbucket",
        cname_patterns=["bitbucket.io"],
        http_fingerprints=["Repository not found", "Bitbucket Cloud - 404"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Create public Bitbucket repository named <workspace>.bitbucket.io.",
    ),
    Signature(
        provider="Surge.sh",
        cname_patterns=["surge.sh"],
        http_fingerprints=["project not found", "surge.sh - page not found"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Deploy static directory using surge: `surge . <subdomain>`.",
    ),
    Signature(
        provider="Fly.io",
        cname_patterns=["edge.fly.io", "fly.dev"],
        http_fingerprints=["404 Not Found", "Fly.io edge error"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Create fly app and configure certificate: `fly certs add <subdomain>`.",
    ),
    Signature(
        provider="Render",
        cname_patterns=["onrender.com"],
        http_fingerprints=["Render | Not Found", "Render - Not Found"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Add custom domain to a Render web service.",
    ),
    Signature(
        provider="ReadTheDocs",
        cname_patterns=["readthedocs.io", "readthedocs.org"],
        http_fingerprints=["is unknown to Read the Docs", "Project not found on Read the Docs"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=True,
        severity="High",
        poc_guidance="Register documentation project on Read the Docs and configure custom domain.",
    ),
    Signature(
        provider="HelpScout",
        cname_patterns=["helpscoutdocs.com"],
        http_fingerprints=["No settings were found for this company", "Help Scout Docs 404"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="Medium",
        poc_guidance="Configure custom docs domain in Help Scout admin panel.",
    ),
    Signature(
        provider="HelpJuice",
        cname_patterns=["helpjuice.com"],
        http_fingerprints=["We could not find what you're looking for", "Helpjuice 404"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="Medium",
        poc_guidance="Add custom domain in Helpjuice knowledge base settings.",
    ),
    Signature(
        provider="Unbounce",
        cname_patterns=["unbouncepages.com"],
        http_fingerprints=["The requested URL was not found on this server", "The requested page was not found"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="High",
        poc_guidance="Add custom domain to Unbounce client account.",
    ),
    Signature(
        provider="Cargo Collective",
        cname_patterns=["cargocollective.com", "subdomain.cargo.site"],
        http_fingerprints=["404 Not Found", "Cargo Collective: 404"],
        http_status=[404],
        nxdomain_required=False,
        claimable=True,
        free_account=False,
        severity="Medium",
        poc_guidance="Claim website on Cargo Collective and enter custom domain in configuration.",
    ),
]

# Legacy compatibility list for tests expecting raw dictionaries
FINGERPRINTS = [sig.to_dict() for sig in SIGNATURES]


def get_signature_by_provider(provider_name: str) -> Optional[Signature]:
    """Look up signature by case-insensitive provider name."""
    target = provider_name.strip().lower()
    for sig in SIGNATURES:
        if sig.provider.lower() == target:
            return sig
    return None


def match_signature(cname_target: str) -> Optional[Signature]:
    """Match a CNAME target string to one of the 26 known provider signatures."""
    if not cname_target:
        return None
    target_clean = cname_target.strip().lower()
    for sig in SIGNATURES:
        for pattern in sig.cname_patterns:
            if pattern in target_clean:
                return sig
    return None


def match_fingerprint(cname_target: str) -> Optional[Dict]:
    """Compatibility helper returning dictionary representation of matched signature."""
    sig = match_signature(cname_target)
    return sig.to_dict() if sig else None
