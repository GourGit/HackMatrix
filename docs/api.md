# API Contract

Base path: `/v1`. All endpoints require authentication and tenant isolation. JSON uses ISO-8601 UTC timestamps and UUID identifiers.

## Create assessment

`POST /assessments`

```json
{"url":"https://example.test/login","authorization":{"attested":true,"scopeId":"uuid"},"safeScan":{"enabled":false,"ports":[]},"options":{"cryptoScamAnalysis":false}}
```

`safeScan.enabled` is accepted only when `scopeId` explicitly authorizes the hostname/IPs and requested ports. The response is `202` with `assessmentId`, `status: "queued"`, and `scopeId`.

## Retrieve assessment

`GET /assessments/{assessmentId}` returns status, target, score, score version, check availability, findings, redirect chain, and evidence summaries. Findings use the common envelope in `agents.md`; evidence content requires a separate authorized request.

```json
{"assessmentId":"uuid","status":"completed","risk":{"score":58,"band":"high","version":"2026-1","contributions":[{"findingId":"uuid","points":16}]},"findings":[{"findingId":"uuid","agent":"certificate-intelligence","type":"certificate.revocation_unknown","severity":"medium","confidence":0.7,"evidenceIds":["uuid"]}],"checks":{"ct":"passed","revocation":"unknown","safeScan":"not_requested","hostnameMatch":"passed","validityDates":"passed","caChain":"passed","tlsConfiguration":"passed","cryptoStrength":"passed"}}
```

## Evidence and intelligence

- `GET /evidence/{evidenceId}` returns redacted metadata and a time-limited artifact link only if the caller is authorized.
- `GET /evidence/{evidenceId}/artifact` streams the authorized, redacted artifact blob from content-addressed storage. Rejects cross-tenant access with `EVIDENCE_FORBIDDEN` (403) and expired or missing artifacts with `NOT_FOUND` (404).
- `POST /indicators` submits an indicator with `value`, `type`, `confidence`, `sharingPolicy` (`private` | `tenant` | `community`), `source`, and optional `evidenceIds`/`sourceEvidenceId`. Values are normalized and validated by type (URLs, domains, IPs, emails, hashes, certificate fingerprints). Validates tenant evidence ownership before association (`EVIDENCE_FORBIDDEN` 403 on foreign/nonexistent evidence). All indicators start in `pending_review`. Duplicate submissions are deduplicated.
- `GET /indicators?value=&type=&sharingPolicy=&page=&pageSize=` returns tenant-visible, provenance-labelled intelligence. Community listings strictly exclude private and tenant-only indicators; external community indicators are visible only once approved (`reviewed`).
- `POST /findings/{findingId}/review` records `accepted`, `disputed`, or `false_positive` with rationale.

Errors use `{ "error": {"code":"...","message":"...","requestId":"..."} }`. Relevant codes: `INVALID_URL`, `UNAUTHORIZED_SCOPE`, `UNSAFE_TARGET`, `SAFE_SCAN_NOT_ALLOWED`, `RATE_LIMITED`, and `EVIDENCE_FORBIDDEN`.
