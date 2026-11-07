# Testing and QA

## Test layers

- **Unit:** URL canonicalization, SSRF/address classifiers, redirect policy, score calculation, evidence hashing/redaction, rule parsers, and API validation.
- **Fixture integration:** local TLS fixtures for valid chains, hostname mismatch, expired certificates, weak keys/signatures, missing/valid SCTs, revoked/good/unreachable OCSP/CRL; HTTP fixtures for cookies, headers, redirects, phishing forms, and component banners.
- **Safety integration:** prove blocked private, loopback, link-local, reserved and DNS-rebinding destinations; verify redirect revalidation, port allowlists, method restriction, concurrency/rate limits, and scope expiry.
- **End-to-end:** authorized URL → queued work → six agent results → evidence provenance → explainable score → reviewer action → intelligence state.

## Required cases

| Area | Cases |
|---|---|
| Certificates | chain/CA trusted and untrusted, SAN mismatch, expiry, revocation good/revoked/unknown, CT pass/fail/unknown, obsolete TLS and weak cryptography. |
| Surface | safe scan denied without scope; allowed port observed; unapproved port blocked; no exploit requests; exposed banner and outdated-version confidence. |
| Privacy | Secure/HttpOnly/SameSite absent/present, overly broad domain/path, excessive persistence, third-party requests. |
| Redirects/phishing | relative and cross-host redirects, loops, HTTPS downgrade, punycode/lookalikes, credential form indicators, benign brand mentions. |
| Provenance | every finding has immutable evidence, correct hash/version/time, redaction, access control, and no raw secrets. |

## Release gates

No critical safety regression, 100% contract tests for listed endpoints, deterministic scoring fixtures, reviewed false-positive set, dependency/security scan clean or risk-accepted, and accessibility/performance checks on results views. Use synthetic or owned targets only in automated testing. Record failures as unavailable rather than fabricating results.
