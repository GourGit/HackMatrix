# Features Development Plan

## Phase 1 — Trusted foundation

Implement identity/tenant isolation, authorization scopes, audit events, URL validation, SSRF-safe egress, evidence storage, assessment jobs, and the shared finding schema. Deliver the URL & Redirect Agent and a basic assessment view.

## Phase 2 — Certificate intelligence

Implement certificate capture, chain and CA validation, hostname/SAN and validity checks, CT/SCT collection, OCSP/CRL status, TLS protocol/cipher and cryptographic-strength findings. Surface `unknown` distinctly from failure.

## Phase 3 — Detection coverage

Add phishing/brand signals; cookie/security-header and privacy checks; and authorized Safe Surface Agent checks for exposed services and observable obsolete software. Ship clear scope confirmation and scan controls before enabling service discovery.

## Phase 4 — Collaboration

Add indicator correlation, provenance browser, review workflow, sharing policy, exports, and feedback loop for false positives. Version rules and scoring throughout.

## Optional extension

Add cryptocurrency-scam analysis behind a feature flag: wallet/address indicators, investment-language heuristics, and approved intelligence correlations. Keep it separated from core requirements and disabled by default.

## Definition of done

Each feature has API/schema updates, fixture-backed tests, safety review, evidence lineage, user-facing remediation copy, and rollback/feature-flag strategy. Do not release a feature that expands scanning scope without explicit authorization controls and adversarial safety tests.
