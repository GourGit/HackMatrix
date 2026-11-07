# Product Requirements Document

## Goal

Help authorized users assess whether a website presents phishing, malware-delivery, web-security, TLS/certificate, privacy, or impersonation risk, and collaborate on evidence-backed threat intelligence.

## Core requirements

1. Submit a URL with an authorization attestation and receive a queued assessment.
2. Trace and display redirect chains, including cross-domain and downgrade redirects.
3. Detect phishing/brand impersonation using domain, content, form, and visual/text signals; show uncertainty.
4. Validate certificate hostname, chain and trusted CA, expiration, revocation, CT evidence, TLS version/cipher, signature/key weaknesses.
5. Within authorized safe-scan scope, identify exposed services and safely observable version banners; flag detectable end-of-life/outdated software with source and confidence.
6. Assess cookies (`Secure`, `HttpOnly`, `SameSite`, scope, lifetime), privacy-relevant third parties and security headers.
7. Correlate indicators with approved threat intelligence and preserve reviewer status and provenance.

## Scoring

Risk is 0–100: `min(100, Σ severity_weight × confidence × freshness × corroboration)`. Suggested weights: critical 40, high 20, medium 8, low 3, informational 0. Freshness decays over time; corroboration may increase confidence but never severity beyond rule limits. Score bands: 0–19 low, 20–49 guarded, 50–74 high, 75–100 critical. The response exposes individual contributions and rule versions. Unknown/unavailable checks produce no positive score impact.

## Out of scope

Exploitation, intrusion, credential testing, malware detonation against third parties, and unauthorised port scanning are out of scope. Cryptocurrency scam analysis is an optional feature flag; it must not be required for the core product or score.

## Success measures

Every completed assessment has a provenance-linked result, safe failures are explicit, and all critical/high findings have actionable evidence and remediation guidance.
