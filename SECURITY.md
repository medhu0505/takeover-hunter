# Security & Responsible Use

Takeover.Hunter performs active DNS resolution and HTTP probing against the targets you point it at. That makes it a scanning tool, and scanning tools carry legal exposure if pointed at the wrong thing.

## Authorized use only

Only run this against domains you own, or domains covered by a bug bounty / pentest engagement with explicit written scope (a HackerOne or Bugcrowd program page, a signed pentest agreement, etc.). Running active recon or takeover verification against a domain you have no authorization for can violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent laws elsewhere, regardless of intent.

The `X-Bug-Bounty` header the tool sends during HTTP probing is a courtesy identifier for programs that request it -- it is not a substitute for actually having scope authorization.

## What this tool does not do

It does not exploit anything. It identifies dangling CNAMEs and fingerprints the provider they point at; claiming the resource to prove impact is a manual step the operator takes deliberately, on infrastructure they are authorized to interact with.

## Reporting a vulnerability in this tool

If you find a security issue in Takeover.Hunter itself (e.g., a way the report generator or API endpoints could be abused, an injection point in the scan pipeline), open a private report via GitHub Security Advisories (Security tab -> Advisories -> Report a vulnerability) rather than a public issue.
