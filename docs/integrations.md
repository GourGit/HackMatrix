# TrustLens — Third-Party Integrations

## 1. Integration principles

Use adapter interfaces so providers can be replaced or mocked. Every provider adapter must return normalized evidence and explicit availability/error status. Do not claim a provider is integrated until its credentials, terms and tests are in place.

## 2. Candidate integrations

### Google Safe Browsing
Purpose: URL threat lookup.
Adapter output: match status, threat types, cache/observation time and provider reference.
Considerations: API key, quotas, permitted use and URL data sharing.

### VirusTotal
Purpose: multi-engine URL/domain intelligence.
Adapter output: analysis status, malicious/suspicious counts, provider analysis ID and timestamp.
Considerations: API quota and terms; do not assume public API is suitable for commercial/high-volume use.

### URLhaus
Purpose: known malware URL intelligence.
Adapter output: match/no-match/unavailable, threat type, first-seen and source reference.
Considerations: provider usage rules and data freshness.

### DNS
Purpose: A, AAAA, MX, NS and TXT observations where appropriate.
Adapter: `dnspython` or asynchronous resolver integration.
Do not treat absence of a record as malicious by itself.

### RDAP
Purpose: domain registration metadata where available.
Adapter: standards-based RDAP client with timeouts.
Registration privacy and missing data are common; domain age is a weak signal, not proof.

### OpenRouter
Purpose: evidence explanation.
Adapter: asynchronous OpenAI-compatible client.
Only send sanitized structured evidence. AI output is advisory and schema-validated.

## 3. Adapter contract

A provider adapter should expose a small async method, for example:

```python
class ReputationProvider:
    async def lookup(self, url: str) -> ProviderResult:
        ...
```

`ProviderResult` should include:
- provider
- status: completed, no_match, unavailable, rate_limited, error
- normalized indicators
- observed_at
- provider_reference
- safe error code

Never interpret provider timeout as no match.

## 4. Webhooks

Webhooks are not required for the MVP. If added:
- sign payloads with HMAC
- verify signatures using constant-time comparison
- include event ID and timestamp
- reject replayed or stale events
- retry with bounded backoff
- make handlers idempotent
- never include secrets or unnecessary raw URLs

Potential events:
- `scan.completed`
- `scan.completed_with_warnings`
- `threat_report.submitted`
- `threat_report.reviewed`

## 5. Communication pipeline

Frontend → FastAPI → scan repository → worker → provider adapters → normalized agent results → risk engine → OpenRouter analyst → PostgreSQL → frontend polling.

The frontend never calls threat providers or OpenRouter directly.

## 6. Failure policy

- 429: respect retry-after and quota; bounded retry.
- 5xx: bounded retry with jitter.
- timeout: unavailable.
- invalid API key: mark integration misconfigured and alert operators.
- malformed response: adapter error; preserve other agent results.
- provider no-match: a successful negative lookup, not a guarantee of safety.

## 7. Privacy and provider disclosure

Disclose that URL/domain indicators may be shared with external intelligence providers. Minimize data sent. Consider stripping fragments and sensitive query parameters where this does not invalidate the lookup, and document the tradeoff.
