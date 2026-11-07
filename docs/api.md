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
{"assessmentId":"uuid","status":"completed","risk":{"score":58,"band":"high","version":"2026-1","contributions":[{"findingId":"uuid","points":16}]},"findings":[{"findingId":"uuid","agent":"certificate-intelligence","type":"certificate.revocation_unknown","severity":"medium","confidence":0.7,"evidenceIds":["uuid"]}],"checks":{"ct":"passed","revocation":"unknown","safeScan":"not_requested"}}
```

## Evidence and intelligence

- `GET /evidence/{evidenceId}` returns redacted metadata and a time-limited artifact link only if the caller is authorized.
- `POST /indicators` submits an indicator with `evidenceIds`, confidence, sharing policy, and source. It begins `pending_review`.
- `GET /indicators?value=&type=` returns tenant-visible, provenance-labelled intelligence.
- `POST /findings/{findingId}/review` records `accepted`, `disputed`, or `false_positive` with rationale.

Errors use `{ "error": {"code":"...","message":"...","requestId":"..."} }`. Relevant codes: `INVALID_URL`, `UNAUTHORIZED_SCOPE`, `UNSAFE_TARGET`, `SAFE_SCAN_NOT_ALLOWED`, `RATE_LIMITED`, and `EVIDENCE_FORBIDDEN`.
