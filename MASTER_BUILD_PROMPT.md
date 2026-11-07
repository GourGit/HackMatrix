# TrustLens — Master Build Prompt

Build TrustLens, an authorized web-security assessment and collaborative threat-intelligence platform for detecting malicious and phishing websites. Preserve the six-agent architecture below. The platform assesses a submitted URL without exploitation, credential use, intrusive crawling, or scans beyond explicitly authorized targets.

## Product outcome

Given a URL, TrustLens returns a reproducible assessment containing a 0–100 risk score, finding severities, evidence and provenance, remediation guidance, and safe sharing of verified indicators. It must identify phishing and brand impersonation; redirect abuse; certificate and TLS weaknesses; exposed services in authorized safe scans; detectable obsolete software; and cookie/privacy weaknesses. Cryptocurrency-scam analysis is an optional extension only.

## Six agents

1. **URL & Redirect Agent** normalizes URLs, follows a bounded redirect chain, detects deceptive destinations and records every hop.
2. **Phishing & Brand Agent** evaluates visual/text/domain similarity, credential-harvesting signals, and brand impersonation. It does not submit forms.
3. **Certificate Intelligence Agent** validates certificate chains, CA trust, hostname/SAN, validity, revocation (OCSP/CRL where available), Certificate Transparency inclusion, key/signature strength, and TLS configuration.
4. **Safe Surface Agent** performs allowlisted, rate-limited, non-exploitative HTTP/TLS and explicitly authorized service discovery; identifies exposed services and version banners when safely observable.
5. **Privacy & Software Agent** evaluates cookie flags, third-party/privacy signals, headers, scripts, and publicly detectable outdated software without attempting authentication or exploitation.
6. **Threat Intelligence & Correlation Agent** correlates immutable evidence with approved feeds and analyst reports; deduplicates indicators and publishes only reviewed or confidence-labelled intelligence.

## Non-negotiable rules

- Require user authorization for targets and any network service discovery. Default to HTTPS/HTTP observation only; use a minimal approved port list only when authorization scope permits it.
- Never exploit, brute-force, authenticate, bypass controls, upload payloads, alter data, evade rate limits, or scan private/reserved/link-local addresses.
- Enforce SSRF protections, DNS/IP revalidation, redirect limits, robots-aware crawling policy, per-host concurrency and rate limits.
- Persist raw evidence content-addressed with collection time, collector version, source URL, request/response metadata redacted of secrets, hash, and retention policy.
- Risk score is explainable: weighted findings, confidence, freshness, and corroboration must be visible. A score is not a definitive claim of compromise.

## Build order

1. Create database, migration, provenance model, authorization scopes, audit logs, and API contracts.
2. Implement URL normalization, safe fetch/redirect evidence, and asynchronous job orchestration.
3. Implement certificate/TLS checks and CT/revocation evidence.
4. Add phishing/brand checks, safe surface checks, and privacy/software checks.
5. Add correlation, analyst review, intelligence sharing controls, dashboard, and exports.
6. Run unit, integration, adversarial safety, fixture-based TLS, and end-to-end tests before release.

## Acceptance criteria

All assessments use the contracts in `docs/api.md`, schema in `docs/database.md`, scoring in `docs/prd.md`, and safety/testing requirements in `docs/testing and QA.md`. Every finding links to evidence IDs and a responsible agent. Crypto-scam rules stay feature-flagged and do not affect the core score unless enabled.
