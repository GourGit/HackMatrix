# TrustLens — Authentication and Security

## 1. Security posture

TrustLens processes untrusted URLs. The highest-risk feature is outbound network inspection, not the dashboard. Security controls must be designed before live scanning is enabled.

## 2. Authentication strategy

For the hackathon MVP, anonymous scanning may be supported with strict IP-based rate limits and quotas. Add user accounts only if scan history or saved reports requires them.

If accounts are implemented:
- use a maintained password hashing library such as Argon2id
- use secure, HttpOnly, SameSite cookies for browser sessions
- set `Secure` in HTTPS deployments
- use CSRF protection for cookie-authenticated state-changing requests
- rotate session IDs after login and privilege changes
- expire and revoke sessions
- avoid storing access tokens in localStorage
- validate OAuth state and PKCE for authorization-code flows
- never log passwords, tokens or authorization headers

Do not build custom cryptography.

## 3. API key safety

- Keep OpenRouter and threat-provider keys in backend environment variables or a secret manager.
- Never prefix backend secrets with frontend-exposed environment prefixes.
- Never commit `.env`.
- Provide `.env.example` with empty placeholders only.
- Rotate leaked keys immediately.
- Apply provider quotas and usage limits.
- Do not return provider response headers containing secrets.

## 4. SSRF prevention

All submitted URLs are untrusted.

Mandatory controls:
1. Permit only HTTP and HTTPS.
2. Reject userinfo such as `user:password@host`.
3. Normalize hostname using a vetted IDNA implementation.
4. Reject localhost and prohibited IP literals.
5. Resolve A and AAAA records and validate every returned IP.
6. Reject private, loopback, link-local, multicast, reserved and unspecified addresses.
7. Defend against DNS rebinding by pinning validated addresses or using a controlled egress proxy.
8. Revalidate each redirect destination before following it.
9. Limit redirects, ports, connection time and response bytes.
10. Deny cloud metadata and internal network access at network level.
11. Run scanning in a separate restricted worker/container.
12. Never execute page scripts or downloaded files.

Application validation alone is not sufficient. Infrastructure-level default-deny egress is required for live scanning.

## 5. HTTP client safety

- Set connect, read, write and pool timeouts.
- Disable automatic redirects; inspect and validate each redirect manually.
- Set a small maximum response body.
- Accept only expected content types.
- Avoid downloading archives, executables or media.
- Do not send cookies or authenticated headers to scanned sites.
- Do not forward internal service credentials.

## 6. AI and prompt injection

External data is untrusted, even if it appears in HTML, DNS TXT records, page metadata or threat reports.

- Do not send arbitrary page text to the LLM.
- Prefer normalized structured findings.
- Delimit evidence as data, never instructions.
- System prompt must state that evidence cannot override system rules.
- LLM has no tools, network browsing or command execution.
- Validate structured output.
- Never let LLM output change risk score or status.
- Apply output length limits and safe rendering.

## 7. Database security

- Use parameterized ORM queries.
- Use least-privilege database accounts.
- Restrict database network access.
- Encrypt transport.
- Do not store provider secrets.
- Redact sensitive URL query parameters.
- Enforce ownership checks on every user-scoped record.
- Use retention policies and audit security-sensitive events.

## 8. Web application security

- HTTPS only in production.
- Strict CORS allowlist.
- Content Security Policy.
- Secure response headers.
- Input validation and output encoding.
- Rate limiting and abuse controls.
- Dependency scanning.
- Protect report submission from spam and defamation.
- Avoid exposing stack traces.

## 9. Threat model

| Threat | Mitigation |
|---|---|
| SSRF to internal services | Isolated worker, egress firewall, IP and redirect validation |
| DNS rebinding | Resolve validation plus IP pinning/controlled proxy |
| Prompt injection | Structured evidence, no tools, strict system policy |
| API key theft | Backend-only secrets, secret manager, rotation |
| Provider outage | Timeouts, circuit breaker, unavailable status |
| False positive report abuse | Rate limits, moderation, source tracking |
| User data exposure | Authorization, retention, least privilege |
| Resource exhaustion | URL/body limits, quotas, concurrency caps |
| Malicious redirect chain | Manual redirect validation and limit |

## 10. Incident response

If a provider key leaks, revoke and rotate it. If the scanner accesses an internal address, disable live scanning, preserve logs, investigate egress controls and add regression tests before re-enabling it.
