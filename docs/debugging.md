# TrustLens — Debugging and Troubleshooting Runbook

## 1. Logging standards

Use structured JSON logs. Every scan-related log should include:
- `timestamp`
- `level`
- `request_id`
- `scan_id`
- `agent_name` when applicable
- `provider` when applicable
- `event`
- `duration_ms`
- safe `error_code`

Never log:
- API keys
- authorization headers
- passwords
- session cookies
- raw user credentials
- full URLs containing sensitive query parameters
- full provider payloads unless safely redacted and necessary

Use Python `logging` or a structured logging library. Do not use `print()` in production code.

## 2. Error taxonomy

Suggested stable codes:
- `INVALID_URL`
- `URL_SCHEME_NOT_ALLOWED`
- `DESTINATION_NOT_ALLOWED`
- `DNS_RESOLUTION_FAILED`
- `REDIRECT_BLOCKED`
- `AGENT_TIMEOUT`
- `PROVIDER_RATE_LIMITED`
- `PROVIDER_UNAVAILABLE`
- `PROVIDER_AUTH_FAILED`
- `INVALID_AGENT_RESULT`
- `RISK_ASSESSMENT_INSUFFICIENT`
- `AI_TIMEOUT`
- `AI_INVALID_RESPONSE`
- `DATABASE_UNAVAILABLE`
- `SCAN_DEADLINE_EXCEEDED`

Return safe user-facing messages; keep detailed diagnostics in protected logs.

## 3. Common issues

### Backend does not start
Check:
- active virtual environment
- Python version
- installed requirements
- correct working directory
- environment file location
- import paths and package `__init__.py` files

Run:
```bash
python -m uvicorn app.main:app --reload
```
from the backend directory, assuming the package layout matches.

### Database connection fails
Check:
- PostgreSQL is running
- `DATABASE_URL` format
- credentials and database name
- network/firewall
- migrations applied

Do not print the complete connection string in logs.

### OpenRouter returns authentication error
Check:
- backend environment has `OPENROUTER_API_KEY`
- key is active
- model ID is supported by the account/provider
- request is sent to `https://openrouter.ai/api/v1`
- no frontend code contains the key

### OpenRouter returns malformed JSON
- inspect sanitized response metadata
- reduce output complexity
- validate with Pydantic
- use fallback explanation
- never parse with unsafe `eval`

### Agent times out
- identify provider and stage
- verify timeout configuration
- check DNS/connect/read timing separately
- mark unavailable
- do not convert timeout to clean result

### Scan remains processing
- inspect worker health
- inspect claimed job/lease
- inspect agent execution records
- check global deadline and cancellation
- implement stale-job recovery

### Frontend cannot reach backend
- verify backend host and port
- verify CORS allowlist
- inspect browser network panel
- check frontend API base URL
- verify route prefix `/api/v1`

### TLS errors
- distinguish invalid certificate from network timeout
- inspect hostname/SAN
- inspect chain validation
- do not disable certificate verification to make a check pass

## 4. Debugging workflow

1. Reproduce with a safe fixture.
2. Capture request/scan ID.
3. Inspect scan lifecycle.
4. Inspect the affected agent execution.
5. Inspect sanitized provider status.
6. Re-run unit test for the failing component.
7. Fix at the responsible layer.
8. Add regression test.
9. Confirm no security control was bypassed.
10. Record the resolution.

## 5. Operational safeguards

- Never enable verbose debug logs in public production without redaction.
- Do not expose stack traces to clients.
- Add health/readiness endpoints.
- Add provider health metrics.
- Alert on repeated provider authentication failures.
- Disable live scanning if egress restrictions cannot be verified.
