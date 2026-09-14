# Takeover Hunter — Acquisition Brief

**Asset:** Takeover Hunter, a subdomain-takeover detection and reporting engine.
**Version:** 2.0.0 (hardened, production-ready).
**Prepared:** 2026-09-14.
**Status:** Available for acquisition as intellectual property.

---

## 1. Executive summary

Takeover Hunter is a self-contained security tool that detects subdomain
takeover vulnerabilities end to end: it enumerates a target's subdomains,
triages DNS delegation, fingerprints dangling records against 26 claimable
cloud providers, verifies findings to suppress false positives, and generates
HackerOne/Bugcrowd-ready reports. It ships as a Flask web application with a
streaming API and a terminal-style UI, plus a hardened, non-root Docker image.

The 2.0 codebase is a ground-up hardening and refactor built specifically for
transfer: a documented, tested (139 tests), modular Python package with a fixed
security posture, CI, and full operator documentation. It is offered for sale
as an IP asset.

## 2. What is being sold

| Included | Detail |
| --- | --- |
| Source code | The full `takeover_hunter` package (1,560 LOC, 10 modules), the terminal UI (1,351 LOC), and the test suite (798 LOC, 139 tests). |
| Documentation | README, architecture, API reference, deployment guide, security policy, changelog, this brief. |
| Deployment assets | Multi-stage Dockerfile, Procfile, gunicorn config, `.env.example`, GitHub Actions CI. |
| Provider signature database | 26 curated takeover fingerprints with claimability/PoC metadata. |
| Brand | The "Takeover Hunter" name and UI design. |
| Transferable IP rights | Copyright in the 2.x codebase, conveyed by written agreement. |

Negotiable / buyer-dependent (not assumed in the base valuation):

- The existing GitHub repository and its commit history.
- The Railway demo deployment and its URL.
- Any domain name, if the seller holds one.
- A transition/support period from the author.

## 3. Technical overview

- **Stack:** Python 3.10–3.13, Flask 3, dnspython, requests, gunicorn. No
  database; stateless between requests.
- **Architecture:** A small, single-purpose-module package behind an
  application factory. Long scans run in worker threads and stream progress to
  the browser over Server-Sent Events. See `docs/ARCHITECTURE.md`.
- **Recon integration:** Orchestrates best-in-class open-source tools
  (ProjectDiscovery's subfinder/dnsx/httpx/katana, tomnomnom's
  assetfinder/waybackurls, gau) with graceful degradation when a tool is
  absent.
- **Quality bar:** 139 automated tests, 75% line coverage overall with the
  security-critical modules (validation, security, reporting, fingerprints,
  SSE) at 97–100%. Linted (pyflakes-clean), CI on four Python versions plus a
  Docker build.

## 4. Security posture (a differentiator, not a liability)

The 1.x line had an unauthenticated command-injection flaw (user-supplied
targets were interpolated into shell commands). 2.0 eliminates it and adds a
defensible security model that lets the tool be operated as a hosted service:

- **Command-injection safe:** argument-list tool invocation (no shell) plus
  strict RFC 1035 hostname validation at the request boundary; an explicit
  regression test proves metacharacters never reach a shell.
- **SSRF guard:** targets resolving to private/reserved IP space (including
  cloud metadata) are refused before probing.
- **Auth + rate limiting:** optional API-key auth and per-IP limits on all API
  routes.
- **Hardening headers and workload caps** throughout.

This is material to valuation: due diligence now passes cleanly where the prior
version would have failed it.

## 5. Intellectual property position (full disclosure)

Buyers and their counsel should understand the IP history precisely:

1. **Prior MIT publication.** Version 1.x was published publicly under the MIT
   License. Copies obtained under MIT remain MIT for their recipients; that
   grant on those specific published versions cannot be retroactively revoked.
2. **2.x is a substantial proprietary rewrite.** The version offered here is a
   near-total re-architecture (new package structure, security model, tests,
   and docs) relicensed under a proprietary evaluation license going forward.
   It is separately ownable and transferable.
3. **Recommended path to clean exclusivity.** Make the working repository
   private, transfer it (or a fresh proprietary repository) to the buyer, and
   execute an asset-purchase/assignment agreement covering the 2.x copyright
   and the brand. The historical MIT commits are disclosed rather than hidden.
4. **Dependencies are permissively licensed.** Flask, dnspython, requests, and
   the orchestrated Go tools carry permissive licenses; the tool invokes them
   as separate executables and does not embed their code.

This transparency is deliberate. A buyer's technical and legal reviewers will
check the git history; disclosing it up front is what makes the transaction
credible.

## 6. Market and positioning

Subdomain takeover is a persistent, well-understood vulnerability class with an
active bug-bounty market and continuous enterprise attack-surface-management
demand. Takeover Hunter's niche is the **end-to-end operator workflow** in one
tool: enumerate → triage → fingerprint → verify → report, with a usable UI and
a report generator, rather than a single-purpose CLI.

Comparable free tools exist (subzy, subjack, nuclei templates,
can-i-take-over-xyz). The asset's edge is the assembled pipeline, the
verification/report layer, and a clean, hardened, deployable web product a
buyer can brand and ship. It is not a defensible algorithm, and the valuation
does not pretend otherwise.

## 7. Valuation

The base case values the transaction as an **IP/code-asset sale with no revenue
and no user base transferred**. That is the honest current state.

| Scenario | Range (USD) | Basis |
| --- | --- | --- |
| Base case — clean IP asset sale, as-is | **$4,000 – $12,000** | Hardened, tested, documented, deployable proprietary codebase; due diligence passes. Buyer pays for assembled pipeline + UI + report layer + saved build time. |
| Strategic / motivated buyer | **$12,000 – $20,000** | An ASM vendor, a security-tooling shop, or a bug-bounty platform folding it into an existing product and brand. |
| With demonstrated traction (not current) | **3–5× ARR** | A separate path: monetize first (below), then sell on a revenue multiple. Ten paying users at $20–30/mo is roughly $2.4k–$3.6k ARR → ~$7k–$18k. |
| Floor (unmotivated market, no packaging) | **$1,000 – $3,000** | What the raw 1.x code was worth before this work, and where an as-is listing lands without the hardening and docs. |

What moved the number up from the pre-hardening floor: the RCE is fixed
(removes a deal-killer), the code is modular and tested (removes rebuild risk),
the license is now proprietary (enables exclusivity), and it is documented and
deployable (removes onboarding cost). What still caps it: no revenue, no users,
the prior MIT history, and a category with capable free alternatives.

**Recommendation (internal).** List a single **asking price of $12,000**. That
is the opening anchor, not the walk-away: expect to clear in the $8,000–$10,000
range with an ordinary buyer, and at or near full with a strategic one. **Do not
go below $5,000** — under that, keep it and monetize instead. This floor and the
clearing range are seller-internal and are deliberately omitted from the
client-facing brief (`ACQUISITION_BRIEF.docx` / `.pdf`), which shows only the
$12,000 ask. The larger prize is not the code sale; it is monetizing to a small
paying base first, then selling on a multiple, or retaining it as a
portfolio/lead asset.

> Before transferring the repository to a buyer, remove this internal section
> (or the whole markdown brief) so the floor and clearing range are not
> disclosed. The client-facing `.docx`/`.pdf` are safe to share as-is.

## 8. Growth levers (roadmap the buyer inherits)

Ranked by impact:

1. **Monetize.** Add accounts, API keys (the auth layer already exists), and a
   metered/subscription tier. Revenue is the only lever that changes the
   valuation by an order of magnitude.
2. **Deepen detection.** Expand the fingerprint database toward the full
   `can-i-take-over-xyz` set (70+), add automated claim-verification PoC steps,
   and add continuous monitoring (scheduled re-scans with diff alerts).
3. **Scale-out readiness.** Back the in-process rate limiter with Redis and add
   a job queue for very large scans; both are localized changes.
4. **Integrations.** HackerOne/Bugcrowd submission APIs, Slack/webhook alerts,
   and CSV/JSON export.
5. **Distribution.** A hosted free tier as a funnel, plus a CLI package.

## 9. Risks and disclosures

- **No revenue or users** are included in the base case.
- **Prior MIT publication** of 1.x, as disclosed in Section 5.
- **Dependency on external recon tools** for enumeration breadth; the core
  detection logic is original but the discovery inputs are third-party.
- **Operational/legal:** the tool performs active scanning; the buyer assumes
  responsibility for authorized-use enforcement (see SECURITY.md).

## 10. Transaction and next steps

1. Buyer evaluates under the proprietary evaluation license (repo access or a
   packaged snapshot).
2. Parties agree scope (code + brand only, or plus repo/domain/demo/support)
   and price per Section 7.
3. Execute an asset-purchase or exclusive-license agreement assigning the 2.x
   copyright and brand; transfer the repository private and hand over
   deployment assets.
4. Optional transition support from the author for a defined period.

*This brief is an informational summary, not a warranty or an offer. Figures
are the seller's good-faith estimates. Buyers should conduct independent
technical and legal due diligence; both parties should use counsel to paper the
transfer.*
