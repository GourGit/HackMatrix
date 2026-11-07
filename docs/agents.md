# TrustLens Agent Responsibilities

TrustLens uses six bounded, auditable agents coordinated by an assessment orchestrator. Agents emit normalized findings, not final verdicts.

| Agent | Owns | Required outputs | Boundaries |
|---|---|---|---|
| URL & Redirect | URL normalization and redirect tracing | normalized target, hop list, final URL, redirect findings | Maximum 10 hops; revalidate DNS/IP at every hop; no private/reserved targets. |
| Phishing & Brand | phishing and impersonation signals | similarity signals, suspected brand, confidence, evidence | No form submission, account interaction, or copyrighted-logo redistribution. |
| Certificate Intelligence | TLS/certificate posture | chain, CA, hostname, expiry, CT, revocation, crypto findings | Read-only TLS handshakes; state revocation status as good/revoked/unknown. |
| Safe Surface | authorized external exposure | service observations, headers, ports, version hints | Only targets/ports in written scope; no exploitation, brute force, or broad subnet scanning. |
| Privacy & Software | cookies, privacy and obsolete components | cookie/header/script/software findings | Passive page and response analysis; version claims need observable evidence. |
| Threat Intelligence & Correlation | indicator correlation and sharing | matches, confidence, provenance links, publication state | Ingest approved feeds; analyst review before high-impact sharing. |

## Common finding envelope

Every agent returns `findingId`, `assessmentId`, `agent`, `type`, `severity`, `scoreImpact`, `confidence`, `status`, `title`, `description`, `affectedAsset`, `evidenceIds`, `observedAt`, and `ruleVersion`. Severity is informational, low, medium, high, or critical; confidence is 0–1. Agents must distinguish absence of evidence from an unavailable check.

## Coordination

The orchestrator creates one immutable assessment scope, queues independent agents, blocks unsafe destinations, deduplicates equivalent findings, calculates the score, and retains partial results. The correlation agent may enrich findings but cannot overwrite source evidence. Analysts can mark a finding disputed, accepted, or false positive with a reason and audit record.
