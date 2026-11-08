# HackMatrix — TrustLens
### Intelligent Website Security Assessment & Digital Trust Intelligence Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688.svg?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18.3.1-61DAFB.svg?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5.3-3178C6.svg?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4.1-38B2AC.svg?style=flat-square&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1.svg?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D.svg?style=flat-square&logo=redis&logoColor=white)](https://redis.io)
[![Docker](https://img.shields.io/badge/Docker_Compose-Supported-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com)
[![Alembic](https://img.shields.io/badge/Alembic-Migrations%20Aligned-6B46C1.svg?style=flat-square)](https://alembic.sqlalchemy.org)
[![Tests](https://img.shields.io/badge/Tests-99%20Passed-brightgreen.svg?style=flat-square&logo=pytest&logoColor=white)](backend/tests)

---

## Table of Contents

- [1. Project Introduction](#1-project-introduction)
  - [The Problem](#the-problem)
  - [The TrustLens Solution](#the-trustlens-solution)
  - [Target Audience](#target-audience)
  - [Key Differentiators](#key-differentiators)
- [2. Project Highlights](#2-project-highlights)
  - [Implemented Capabilities](#implemented-capabilities)
  - [Planned Enhancements](#planned-enhancements)
- [3. Complete Security Agent Documentation](#3-complete-security-agent-documentation)
  - [Orchestration Architecture](#orchestration-architecture)
  - [Agent 1: URL & Redirect Analyzer (`url-redirect`)](#agent-1-url--redirect-analyzer-url-redirect)
  - [Agent 2: Phishing & Brand Impersonation Analyzer (`phishing-brand`)](#agent-2-phishing--brand-impersonation-analyzer-phishing-brand)
  - [Agent 3: Certificate & TLS Intelligence Analyzer (`certificate-intelligence`)](#agent-3-certificate--tls-intelligence-analyzer-certificate-intelligence)
  - [Agent 4: Attack Surface & Service Analyzer (`safe-surface`)](#agent-4-attack-surface--service-analyzer-safe-surface)
  - [Agent 5: Privacy, Headers & Software Analyzer (`privacy-software`)](#agent-5-privacy-headers--software-analyzer-privacy-software)
  - [Agent 6: Threat Intelligence & Reputation Analyzer (`threat-intelligence`)](#agent-6-threat-intelligence--reputation-analyzer-threat-intelligence)
- [4. Complete AI / ML Documentation](#4-complete-ai--ml-documentation)
  - [Deterministic Foundation vs. Generative Debrief](#deterministic-foundation-vs-generative-debrief)
  - [The OpenRouter Claude-3-Haiku Analyst Integration](#the-openrouter-claude-3-haiku-analyst-integration)
  - [Evidence Sanitization & Guardrails](#evidence-sanitization--guardrails)
  - [Zero Hallucination Scoring Guarantee](#zero-hallucination-scoring-guarantee)
- [5. Technology Stack](#5-technology-stack)
- [6. System Architecture](#6-system-architecture)
  - [High-Level Architecture Diagram](#high-level-architecture-diagram)
  - [Assessment Lifecycle Flowchart](#assessment-lifecycle-flowchart)
- [7. Database Schema & Persistence](#7-database-schema--persistence)
  - [Entity-Relationship Diagram](#entity-relationship-diagram)
  - [Database Tables Reference](#database-tables-reference)
  - [Alembic Migration History](#alembic-migration-history)
- [8. Complete API Documentation](#8-complete-api-documentation)
  - [Authentication & Sessions](#authentication--sessions)
  - [Health & Readiness Probes](#health--readiness-probes)
  - [Assessments Workflow](#assessments-workflow)
  - [Scope Management](#scope-management)
  - [Findings & Review](#findings--review)
  - [Evidence & Artifacts](#evidence--artifacts)
  - [Indicators (IOCs)](#indicators-iocs)
- [9. Security Architecture](#9-security-architecture)
  - [Anti-SSRF & DNS Rebinding Defenses](#anti-ssrf--dns-rebinding-defenses)
  - [Egress Network Controls](#egress-network-controls)
  - [Tenant Isolation & RBAC](#tenant-isolation--rbac)
  - [Rate Limiting & Abuse Prevention](#rate-limiting--abuse-prevention)
- [10. Risk Scoring Engine & Methodology](#10-risk-scoring-engine--methodology)
  - [Deterministic Scoring Formula](#deterministic-scoring-formula)
  - [Risk Bands & Severity Classifications](#risk-bands--severity-classifications)
- [11. Installation & Local Development](#11-installation--local-development)
  - [Prerequisites](#prerequisites)
  - [Windows Setup (PowerShell)](#windows-setup-powershell)
  - [Linux / macOS Setup (Bash)](#linux--macos-setup-bash)
- [12. Docker Deployment](#12-docker-deployment)
  - [Single-Command Launch](#single-command-launch)
  - [Docker Compose Service Topology](#docker-compose-service-topology)
  - [Service Health Checks](#service-health-checks)
- [13. Testing & Quality Assurance](#13-testing--quality-assurance)
  - [Backend Test Matrix (99 Tests)](#backend-test-matrix-99-tests)
  - [Running Backend Tests](#running-backend-tests)
  - [Frontend Test & Build Verification](#frontend-test--build-verification)
- [14. Visual Documentation & UI Walkthrough](#14-visual-documentation--ui-walkthrough)
- [15. Repository Directory Structure](#15-repository-directory-structure)
- [16. Environment Variables Reference](#16-environment-variables-reference)
- [17. Limitations & Future Roadmap](#17-limitations--future-roadmap)
- [18. Contribution Guidelines](#18-contribution-guidelines)
- [19. License & Acknowledgements](#19-license--acknowledgements)

---

## 1. Project Introduction

**HackMatrix — TrustLens** is an open-source, production-grade cybersecurity and digital trust intelligence platform engineered to perform automated, deep-spectrum security assessments of web domains, web applications, and digital infrastructure.

```
+-----------------------------------------------------------------------------------------+
|                                HACKMATRIX — TRUSTLENS                                  |
|         Deterministic Security Analytics  *  SSRF-Guarded Egress  *  AI Debrief         |
+-----------------------------------------------------------------------------------------+
```

### The Problem

Modern web threat actors deploy phishing attacks, typosquatting domains, fraudulent cryptocurrency schemes, and credential-harvesting infrastructures at unprecedented velocity. Traditional URL scanners and reputation blacklists suffer from critical blind spots:

1. **The Green Lock Fallacy**: Modern threat actors easily obtain free, cryptographically valid Let's Encrypt certificates. A valid TLS certificate verifies domain control, **not** legitimacy.
2. **Obfuscated Redirect Loops**: Attack chains use multi-hop redirects across different cloud providers, IP addresses, and protocols to evade simple scrapers while attempting to trigger internal SSRF vulnerabilities.
3. **Delayed Blacklist Propagation**: Centralized reputation feeds frequently lag hours or days behind active zero-day campaigns.
4. **Opaque AI Hallucinations**: Scanning tools that rely purely on Large Language Models to "read" web code are prone to hallucinations, non-reproducible risk scores, and security prompt-injection attacks.

### The TrustLens Solution

TrustLens solves these challenges through an architectural separation of concerns:

- **100% Deterministic Security Analytics**: Assessments are driven by six specialized, concurrent Python `asyncio` security analyzer agents that inspect protocol behavior, cryptographic primitives, DNS topologies, TLS certificates, HTTP response headers, cookie flags, and source signatures.
- **Enterprise-Grade SSRF & Rebinding Defenses**: Every single network egress probe is strictly sanitized through a multi-tier safety pipeline that blocks private IP ranges, cloud metadata endpoints (`169.254.169.254`), IPv6 loopbacks, and DNS rebinding attacks.
- **Transparent, Explainable Risk Engine**: Findings contribute mathematically determined severity points (Critical: 40, High: 20, Medium: 8, Low: 3, Informational: 0) clamped between 0 and 100 into standard risk bands (`LOW`, `GUARDED`, `HIGH`, `CRITICAL`).
- **Strictly Advisory AI Executive Debrief**: An optional Large Language Model (`anthropic/claude-3-haiku` via OpenRouter) translates verified forensic evidence and structured findings into human-readable executive summaries. The AI model has **zero authority** over risk scores and cannot invent unproven vulnerabilities.

### Target Audience

- **Security Operations Center (SOC) & Incident Response Teams**: Rapidly triage suspicious URLs submitted by employees or detected in phishing emails.
- **Brand Protection & Legal Teams**: Monitor typosquatting and impersonation attacks across high-value enterprise trademarks.
- **DevSecOps & Web Infrastructure Engineers**: Continuously audit domain configurations, TLS/SSL cipher suites, obsolete software banners, and missing security headers.
- **General Public & Anonymous Visitors**: Safely evaluate suspicious links before interacting with them, supported by frictionless, privacy-preserving anonymous JWT sessions.

### Key Differentiators

| Feature | Generic URL Scanners | Pure AI / LLM Wrappers | HackMatrix — TrustLens |
|---|:---:|:---:|:---:|
| **Egress SSRF Protection** | ❌ Minimal / None | ❌ None | ✅ **Kernel/Socket-level IP validation & DNS pin** |
| **Redirect Tracing** | ⚠️ Unvalidated follow | ❌ Scrapes final only | ✅ **Step-by-step hop validation with downgrade detection** |
| **TLS Deep Inspection** | ⚠️ Checks expiry only | ❌ None | ✅ **Chain, ciphers, key size, SAN wildcards, SCT logs** |
| **Scoring Predictability** | ⚠️ Black-box heuristic | ❌ High hallucination risk | ✅ **100% Deterministic & reproducible point model** |
| **Active Port Scan Scoping** | ❌ None or unchecked | ❌ None | ✅ **Strict explicit opt-in authorization scopes** |
| **Evidence Auditability** | ❌ Fleeting JSON response | ❌ Fleeting prompt output | ✅ **PostgreSQL storage of raw evidence, hops, & findings** |

---

## 2. Project Highlights

### Implemented Capabilities

- [x] **Anonymous Visitor Access**: Automatic, zero-configuration anonymous visitor authentication issuing 24-hour cryptographically signed HS256 JWT tokens with isolated UUID tenants.
- [x] **Asynchronous Assessment Processing**: Background execution model returning immediate HTTP `202 Accepted` status with persistent polling and lifecycle state tracking (`pending` -> `running` -> `completed` / `failed`).
- [x] **Six Concurrent Security Agents**: High-performance `asyncio`-coordinated assessment pipeline executing redirect, brand, TLS, attack surface, privacy, and reputation analyses in parallel.
- [x] **Anti-SSRF & Network Safety Engine**: Pre-flight IP resolution, CIDR blocklist enforcement, cloud metadata shielding, and per-hop redirect re-validation.
- [x] **Deterministic Risk Scoring**: Formulaic points-to-band categorization adhering to version `2026-1` specifications.
- [x] **OpenRouter AI Debrief Integration**: Optional, sandboxed Claude-3-Haiku synthesis generating plain-English executive summaries from verified structured evidence.
- [x] **Analyst Findings & Review Workflow**: Full finding lifecycle tracking with patchable analyst statuses (`open`, `confirmed`, `false_positive`, `mitigated`) and audit trails.
- [x] **Structured Forensic Evidence Storage**: Relational persistence of raw HTTP headers, TLS certificate structures, redirect hops, cookie attributes, open service banners, and indicators of compromise (IOCs).
- [x] **Active Scan Authorization Scopes**: Cryptographically tracked authorization contracts permitting active port probing only when explicit domain control is attested.
- [x] **Modern Single-Page Interface**: Clean, responsive React 18 dashboard built with Vite, TypeScript, and Tailwind CSS, featuring real-time polling and dark-mode styling.
- [x] **Production Database Migrations**: Sequential, forward-only Alembic migration chain (`001_initial_schema` through `004_align_models_schema`) guaranteeing zero schema drift.
- [x] **Full Pytest Suite**: 99 unit, integration, and security regression tests covering 100% of core business logic and defense boundaries.

### Planned Enhancements

- [ ] Webhook notifications for enterprise SIEM integration (Splunk, Elastic, Microsoft Sentinel).
- [ ] Exportable PDF & Executive Compliance Reports (SOC 2, ISO 27001, PCI-DSS).
- [ ] Headless Chromium sandbox agent for dynamic DOM rendering, screenshot capture, and obfuscated JavaScript execution analysis.
- [ ] Distributed Celery/RabbitMQ task worker clustering for enterprise horizontal scanning scale.

---

## 3. Complete Security Agent Documentation

```
                                  +------------------------------------+
                                  |     Assessment Orchestration       |
                                  |     (backend/app/orchestrator)     |
                                  +-----------------+------------------+
                                                    |
         +------------------+-----------------------+------------------------+------------------+
         |                  |                       |                        |                  |
         v                  v                       v                        v                  v
+-----------------+ +-----------------+   +--------------------+   +-------------------+ +--------------------+
|  url-redirect   | | phishing-brand  |   | certificate-intel  |   |   safe-surface    | |  privacy-software  |
| (Redirects/SSRF)| | (Impersonation) |   | (TLS/SSL Cryptogr) |   | (Ports / Banners) | | (Headers & Cookies)|
+-----------------+ +-----------------+   +--------------------+   +-------------------+ +--------------------+
         |                  |                       |                        |                  |
         +------------------+-----------------------+------------------------+------------------+
                                                    |
                                                    v
                                         +---------------------+
                                         | threat-intelligence |
                                         | (Google SB / TLDs)  |
                                         +---------------------+
```

### Orchestration Architecture

Assessment execution is coordinated by the `AssessmentEngine` (`backend/app/orchestrator/engine.py`). When an assessment is initiated, the engine:
1. Validates the target URL and establishes an immutable `AssessmentContext`.
2. Verifies whether active scanning permissions have been granted via an attached `AuthorizationScope`.
3. Dispatches the six security agents concurrently using Python's `asyncio.gather()`.
4. Handles agent timeouts and transient failures gracefully; an individual agent failure does not abort other independent analyzers.
5. Persists raw `Evidence`, structured `Findings`, `RedirectHop` entities, and observation models to PostgreSQL.
6. Invokes the deterministic `ScoringEngine` to calculate the final numerical risk score and risk band.
7. Triggers the optional `OpenRouterAnalyst` to construct the natural-language executive debrief.

---

### Agent 1: URL & Redirect Analyzer (`url-redirect`)

* **Implementation**: `backend/app/agents/url_redirect.py` (`UrlRedirectAgent`)
* **Execution Mode**: Passive (Safe for all submitted URLs)
* **Primary Objective**: Safely traces HTTP redirect chains from the origin URL to the terminal destination while enforcing boundary constraints and identifying deceptive protocol shifts.
* **Analysis Logic & Heuristics**:
  - Traverses HTTP redirect headers (`301 Moved Permanently`, `302 Found`, `307 Temporary Redirect`, `308 Permanent Redirect`) up to a maximum safety ceiling of **10 hops**.
  - Re-validates every destination hostname against the SSRF resolver **prior** to initiating subsequent network connections.
  - Detects **HTTPS-to-HTTP protocol downgrades**, alerting when an encrypted session is steered into an unencrypted cleartext transport.
  - Identifies cross-domain redirections where a visitor is quietly moved across distinct registered domains.
  - Generates a `SUSPICIOUS_REDIRECT` finding if a redirect chain exceeds 5 consecutive hops.
  - Flags redirect loops and terminal destination resolution failures.
* **Findings Generated**:
  - `SUSPICIOUS_REDIRECT` (Severity: Medium) — Flagged on excessive redirect length or unexpected cross-domain hops.
  - `HTTPS_DOWNGRADE` (Severity: High) — Flagged when an initial HTTPS URL redirects to an insecure HTTP endpoint.
  - `REDIRECT_FAILED` (Severity: Low) — Recorded when intermediate connection resets or invalid redirect headers occur.
* **Evidence Produced**: A sequential collection of `RedirectHop` entities recording hop position, HTTP status code, source URL, target URL, resolved IP, and intermediate latency.

---

### Agent 2: Phishing & Brand Impersonation Analyzer (`phishing-brand`)

* **Implementation**: `backend/app/agents/phishing_brand.py` (`PhishingBrandAgent`)
* **Execution Mode**: Passive (HTTP GET body inspection)
* **Primary Objective**: Identifies credential harvesting, typosquatting domains, brand trademark spoofing, and cryptocurrency scam patterns.
* **Analysis Logic & Heuristics**:
  - **Fuzzy Brand Matching**: Evaluates target hostnames against a curated catalog of high-profile global targets (`paypal`, `apple`, `microsoft`, `google`, `amazon`, `facebook`, `netflix`, `chase`, `wellsfargo`, `bankofamerica`, `binance`, `coinbase`, `metamask`, `ledger`, `twitter`, `instagram`, `dropbox`) using **Levenshtein distance and similarity ratios**. Hostnames exhibiting high similarity (ratio > 0.82) without exact domain matches trigger typosquatting alerts.
  - **Credential Harvesting Form Detection**: Parses HTML document structures using regular expression pattern matchers to identify insecure `<form action="http://...">` submissions or forms containing `<input type="password">` hosted on unverified or third-party origins.
  - **Cryptocurrency Scam Heuristics**: When `FEATURE_CRYPTO_SCAM_DETECTION=True`, inspects page titles, meta descriptions, and body tokens for high-risk phrase clusters: `"double your crypto"`, `"airdrop giveaway"`, `"connect your wallet"`, `"send btc to get double"`, `"presale guaranteed returns"`.
* **Findings Generated**:
  - `SUSPICIOUS_BRAND` (Severity: High / Critical) — Flagged on near-match typosquatting or brand name collision in subdomains.
  - `SUSPICIOUS_FORM` (Severity: Medium) — Flagged when password or credential inputs submit over cleartext HTTP.
  - `CRYPTO_SCAM_INDICATOR` (Severity: High) — Flagged when deceptive cryptocurrency keyword combinations match high-confidence thresholds.
* **Evidence Produced**: Extracted brand matches, Levenshtein ratio scores, detected form attributes, input field names, and suspicious keyword occurrences.

---

### Agent 3: Certificate & TLS Intelligence Analyzer (`certificate-intelligence`)

* **Implementation**: `backend/app/agents/certificate_intel.py` (`CertificateIntelAgent`)
* **Execution Mode**: Passive (Direct TLS handshake inspection)
* **Primary Objective**: Audits cryptographic transport security, TLS configuration, certificate authority validity, and public key strength.
* **Analysis Logic & Heuristics**:
  - Establishes a raw SSL/TLS socket connection via `SafeTlsObservation` using a strict connect timeout.
  - **Validity Window Auditing**: Compares client timestamp against `notBefore` and `notAfter` dates, flagging expired certificates or certificates whose validity starts in the future.
  - **Hostname & Subject Alternative Name (SAN) Verification**: Evaluates the requested hostname against the certificate's Common Name (CN) and Subject Alternative Name wildcards (`*.example.com`).
  - **Root Trust Verification**: Inspects issuer details against trusted root certificate authorities. Self-signed certificates and untrusted internal CAs are immediately identified.
  - **Cryptographic Key Strength Inspection**: Enforces minimum key size standards:
    - RSA / DSA keys: **< 2048 bits** flagged as dangerously weak.
    - Elliptic Curve (EC) keys: **< 224 bits** flagged as insufficient.
  - **Signature Algorithm Analysis**: Flags obsolete, collision-vulnerable signature hashes (`MD5`, `SHA-1`).
  - **Protocol Deprecation**: Alerts on servers supporting obsolete or broken protocol suites (`SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`).
  - **Weak Cipher Suite Detection**: Detects ciphers using `RC4`, `DES`, `3DES`, `MD5`, `EXPORT`, or unauthenticated `NULL` encryption modes.
  - **Certificate Transparency (CT)**: Inspects the presence of embedded Signed Certificate Timestamps (SCTs) according to RFC 6962.
* **Findings Generated**:
  - `CERT_EXPIRED` (Severity: High) — Certificate validity timestamp has lapsed.
  - `CERT_NOT_YET_VALID` (Severity: Medium) — Certificate start date is in the future.
  - `CERT_HOSTNAME_MISMATCH` (Severity: High) — Domain name does not match CN or SAN entries.
  - `CERT_SELF_SIGNED` (Severity: High) — Certificate chain cannot be traced to a trusted public Root CA.
  - `WEAK_KEY_LENGTH` (Severity: High) — RSA key size is below 2048 bits.
  - `WEAK_SIGNATURE_ALGORITHM` (Severity: Medium) — Certificate signed using SHA-1 or MD5.
  - `OBSOLETE_TLS_VERSION` (Severity: High) — Server supports deprecated TLS 1.0 or 1.1.
  - `MISSING_SCT` (Severity: Informational) — Embedded Certificate Transparency logs absent.
* **Evidence Produced**: Detailed `CertificateObservation` record storing SHA-256 fingerprint, serial number, issuer, SAN list, negotiated cipher, TLS protocol version, and key length.

---

### Agent 4: Attack Surface & Service Analyzer (`safe-surface`)

* **Implementation**: `backend/app/agents/safe_surface.py` (`SafeSurfaceAgent`)
* **Execution Mode**: Active (Strictly requires explicit Authorization Scope)
* **Primary Objective**: Probes network-level service exposure and parses server banner signatures.
* **Analysis Logic & Heuristics**:
  - **Authorization Enforcement**: If the assessment is passive or no valid `scope_id` is supplied, active port scanning is **strictly bypassed**.
  - **Safe Port Allowlist**: When authorized, restricts TCP connection probes solely to user-authorized ports, rejecting out-of-scope probes.
  - **Sensitive Port Exposure**: Detects exposed administrative, database, and management interfaces commonly targeted by attackers (`8080` HTTP-Alt, `8443` HTTPS-Alt, `8888` Alternative Web, `9000` Portainer/SonarQube/PHP-FPM).
  - **Passive Server Banner Analysis**: Extracts the `Server` HTTP header and identifies outdated, end-of-life server engines with known CVE histories (e.g., `Apache/2.2`, `nginx/1.10`, `PHP/5.x`, `Microsoft-IIS/7.0`).
* **Findings Generated**:
  - `EXPOSED_MANAGEMENT_PORT` (Severity: Medium) — Management or alternate administrative ports found listening.
  - `OUTDATED_SERVER_SOFTWARE` (Severity: Low / Medium) — Server header advertises deprecated software with known vulnerabilities.
* **Evidence Produced**: `ServiceObservation` entities detailing opened ports, handshake response latency, protocol detection, and raw banner strings.

---

### Agent 5: Privacy, Headers & Software Analyzer (`privacy-software`)

* **Implementation**: `backend/app/agents/privacy_software.py` (`PrivacySoftwareAgent`)
* **Execution Mode**: Passive (HTTP response header and cookie parsing)
* **Primary Objective**: Validates mandatory browser defensive headers, evaluates cookie privacy hygiene, and detects vulnerable client-side libraries.
* **Analysis Logic & Heuristics**:
  - **Security Header Auditing**:
    - `Strict-Transport-Security` (HSTS): Checks presence and validates whether `max-age` is adequate (>= 15724800 seconds / 6 months) and includes subdomains.
    - `Content-Security-Policy` (CSP): Validates policy presence to mitigate Cross-Site Scripting (XSS) and data injection.
    - `X-Frame-Options` & `X-Content-Type-Options`: Verifies clickjacking and MIME-sniffing protections.
    - `Referrer-Policy`: Verifies policy prevents leaking sensitive URL paths in Referer headers.
  - **Cookie Security Hygiene**:
    - Inspects all `Set-Cookie` headers.
    - Flags cookies lacking the `Secure` flag on HTTPS connections.
    - Flags session-identifying cookies (e.g., `PHPSESSID`, `JSESSIONID`, `connect.sid`, `session`) lacking the `HttpOnly` flag.
    - Checks for explicit `SameSite` attributes (`Strict`, `Lax`, or `None`).
    - Hashes cookie names using SHA-256 in persisted evidence to ensure compliance with privacy regulations.
  - **Outdated Frontend Script Detection**:
    - Scans embedded `<script src="...">` tags for vulnerable, end-of-life JavaScript libraries, such as legacy jQuery versions (`jQuery 1.x`, `jQuery 2.x`).
* **Findings Generated**:
  - `MISSING_HSTS` (Severity: Low) — Strict-Transport-Security header is absent.
  - `MISSING_CSP` (Severity: Low) — Content-Security-Policy header is absent.
  - `INSECURE_COOKIE` (Severity: Medium) — Cookie lacks `Secure` or `HttpOnly` attributes.
  - `OUTDATED_JAVASCRIPT_LIBRARY` (Severity: Low) — Client-side scripts reference legacy vulnerable libraries.
* **Evidence Produced**: `CookieObservation` records containing privacy-hashed cookie names, flag states (`is_secure`, `is_httponly`, `samesite`), and full header audits.

---

### Agent 6: Threat Intelligence & Reputation Analyzer (`threat-intelligence`)

* **Implementation**: `backend/app/agents/threat_intel.py` (`ThreatIntelAgent`)
* **Execution Mode**: Passive (API lookup and heuristic rules)
* **Primary Objective**: Cross-references targets against external malicious reputation databases and detects domain registration patterns associated with abuse.
* **Analysis Logic & Heuristics**:
  - **Google Safe Browsing API v4 Integration**:
    - Queries `safebrowsing.googleapis.com/v4/threatMatches:find` when `SAFE_BROWSING_API_KEY` is configured.
    - Inspects threats across categories: `MALWARE`, `SOCIAL_ENGINEERING` (phishing), `UNWANTED_SOFTWARE`, and `POTENTIALLY_HARMFUL_APPLICATION`.
    - Implements graceful degradation: if the API key is not configured or the network request times out, the check skips without halting the pipeline.
  - **High-Abuse Top-Level Domain (TLD) Heuristics**:
    - Flags domains registered on free or historically abuse-dominated TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.buzz`, `.work`).
  - **IP-Based Hostname Detection**:
    - Flags websites addressed directly via raw IP addresses (`http://198.51.100.25/`) rather than fully qualified domain names, a common tactic in untargeted malware delivery campaigns.
* **Findings Generated**:
  - `KNOWN_MALICIOUS_THREAT` (Severity: Critical) — Confirmed match in Google Safe Browsing reputation database.
  - `HIGH_ABUSE_TLD` (Severity: Low) — Hostname resides on an abuse-heavy TLD.
  - `RAW_IP_TARGET` (Severity: Low) — Website accessed directly via IP address instead of domain.
* **Evidence Produced**: Raw Safe Browsing API match metadata, queried threat types, platform types, and TLD categorization.

---

## 4. Complete AI / ML Documentation

### Deterministic Foundation vs. Generative Debrief

TrustLens enforces a strict architectural boundary between **security measurement** and **natural language explanation**:

```
+-----------------------------------------------------------------------------------------+
|                                    ASSESSMENT ENGINE                                    |
|                                                                                         |
|   +-----------------------+                         +-------------------------------+   |
|   | 6 Deterministic       | ===> Structured ====>   | Deterministic Scoring Engine  |   |
|   | Security Agents       |      Evidence           | Base: 0  |  Points: 0-100     |   |
|   +-----------------------+                         +---------------+---------------+   |
|                                                                     |                   |
|                                                                     v                   |
|                                                            Deterministic Score          |
|                                                            (e.g., 68/100, HIGH)         |
|                                                                     |                   |
|                                                                     v                   |
|   +---------------------------------------------+   +---------------+---------------+   |
|   | OpenRouter Claude-3-Haiku Executive Analyst |   | Database Persistence          |   |
|   | (Strictly Advisory Natural-Language Debrief)|<==| (Evidence, Findings, Hops)     |   |
|   +---------------------------------------------+   +-------------------------------+   |
+-----------------------------------------------------------------------------------------+
```

### The OpenRouter Claude-3-Haiku Analyst Integration

* **Implementation**: `backend/app/integrations/openrouter.py` (`OpenRouterAnalyst`)
* **Default Model**: `anthropic/claude-3-haiku` (configurable via `OPENROUTER_MODEL`)
* **Role**: Acts as a junior cybersecurity analyst providing an executive summary, threat synthesis, and actionable remediation steps.
* **Strict Limitations**:
  - **No Scoring Authority**: The AI model **cannot** alter, augment, or reduce the assessment's numerical score or risk band.
  - **No Finding Generation**: The AI model cannot create new findings. It is only permitted to summarize findings verified by the deterministic agents.
  - **Graceful Offline Fallback**: If `OPENROUTER_API_KEY` is not provided, or if the OpenRouter API encounters rate limits or downtime, TrustLens automatically generates a deterministic, template-based debrief without degrading the assessment status.

### Evidence Sanitization & Guardrails

To prevent prompt injection and data exfiltration through untrusted website content:
1. **Raw HTML Stripping**: Raw website HTML is **never** sent to the AI model.
2. **Strict JSON Schema**: Only structured, validated metadata (finding codes, severity levels, TLS cipher names, HTTP status codes) are passed into the prompt template.
3. **Truncated Payloads**: Extracted text fragments (e.g., page titles) are truncated to 150 characters to prevent prompt stuffing.

### Zero Hallucination Scoring Guarantee

| Dimension | Deterministic Engine | AI Executive Debrief |
|---|---|---|
| **Risk Score (0–100)** | Calculated mathematically from finding severities | Reads and cites calculated score |
| **Risk Band** | Determined by fixed threshold mapping | Uses deterministic band label |
| **Finding Presence** | Determined by binary agent rules & signatures | Synthesizes only reported findings |
| **Failure Mode** | Graceful per-agent isolation | Fallback to deterministic summary |

---

## 5. Technology Stack

### Backend Services & Libraries

| Technology | Version / Spec | Purpose in Project |
|---|---|---|
| **Python** | 3.11 / 3.12 / 3.14 | Core backend runtime environment |
| **FastAPI** | 0.115.0 | High-performance asynchronous REST API framework |
| **Pydantic** | 2.9.2 | Schema validation, request coercion, and serialization |
| **SQLAlchemy** | 2.0.36 | Asynchronous Object-Relational Mapper (ORM) |
| **Asyncpg** | 0.29.0 | High-performance asynchronous PostgreSQL database driver |
| **Alembic** | 1.13.3 | Database migration management and version control |
| **HTTPX** | 0.27.2 | Asynchronous HTTP client with connection pooling and timeouts |
| **PyJWT** | 2.9.0 | Cryptographic JSON Web Token encoding and verification |
| **dnspython** | 2.6.1 | Asynchronous DNS resolution and DNS rebinding inspection |
| **slowapi** | 0.1.9 | IP and tenant rate limiting via Redis |
| **pytest** | 8.3.3 | Unit, integration, and security regression testing framework |
| **pytest-asyncio** | 0.24.0 | Asynchronous test execution runner |

### Frontend Application

| Technology | Version / Spec | Purpose in Project |
|---|---|---|
| **React** | 18.3.1 | Declarative component-based UI framework |
| **TypeScript** | 5.5.3 | Static typing, interface contracts, and compile-time safety |
| **Vite** | 5.4.2 | Next-generation frontend build tool and dev server |
| **Tailwind CSS** | 3.4.1 | Utility-first CSS framework for modern responsive UI |
| **Lucide React** | 0.344.0 | Icon system for cybersecurity status badges and indicators |

### Data Stores & Infrastructure

| Technology | Version / Spec | Purpose in Project |
|---|---|---|
| **PostgreSQL** | 16-alpine | Primary relational database for scopes, assessments, and evidence |
| **Redis** | 7-alpine | In-memory key-value store for rate limiting and task coordination |
| **Docker Compose** | v2 / Compose Spec | Multi-container orchestration, networking, and volume binding |

---

## 6. System Architecture

### High-Level Architecture Diagram

```mermaid
graph TD
    User([Web Browser / SOC Analyst]) -->|HTTPS / Port 80, 5173| Frontend[React + TypeScript Frontend]
    Frontend -->|REST API / JSON| API[FastAPI Backend Gateway]
    
    subgraph Security Boundary
        API -->|JWT & Rate Limiting| Auth[Auth & Rate Limit Middleware]
        Auth -->|Route Handler| Router[API Router /v1]
    end
    
    Router -->|Read / Write| PG[(PostgreSQL 16 Database)]
    Router -->|Rate Limits| Redis[(Redis 7 Cache)]
    
    Router -->|Async Dispatch| Orchestrator[Assessment Orchestrator]
    
    subgraph Egress Quarantine Layer
        Orchestrator --> Safety[Anti-SSRF & DNS Safety Layer]
        Safety -->|Safe Egress Only| Agents[6 Security Analyzer Agents]
    end
    
    Agents -->|HTTP Probes| Target[Target Web Domain]
    Agents -->|TLS Handshake| Target
    Agents -->|DNS Queries| DNS[(Public DNS Resolvers)]
    
    Agents -->|Raw Findings & Evidence| Orchestrator
    Orchestrator -->|Persist Results| PG
    Orchestrator -->|Structured Evidence| OpenRouter[OpenRouter AI / Claude-3-Haiku]
    OpenRouter -.->|Advisory Debrief| Orchestrator
```

### Assessment Lifecycle Flowchart

```mermaid
stateDiagram-v2
    [*] --> Submitted: POST /v1/assessments
    Submitted --> AttestationCheck: Verify User Attestation
    
    AttestationCheck --> Rejected: Attestation Missing (422)
    AttestationCheck --> ActiveScopeCheck: Attestation Valid
    
    ActiveScopeCheck --> ActiveScanAllowed: Valid Scope & Attestation
    ActiveScopeCheck --> PassiveScanOnly: No Scope (Passive Mode)
    
    PassiveScanOnly --> Pending: State = PENDING (202 Accepted)
    ActiveScanAllowed --> Pending: State = PENDING (202 Accepted)
    
    Pending --> Running: Background Task Dispatched (State = RUNNING)
    
    state Running {
        [*] --> DNS_SSRF_Check
        DNS_SSRF_Check --> ConcurrentAgents: IP is Public & Safe
        DNS_SSRF_Check --> TerminateSSRF: IP Private / Loopback (Aborted)
        
        state ConcurrentAgents {
            Agent_Redirect: url-redirect
            Agent_Phishing: phishing-brand
            Agent_Cert: certificate-intel
            Agent_Surface: safe-surface (Scoped)
            Agent_Privacy: privacy-software
            Agent_Threat: threat-intel
        }
        
        ConcurrentAgents --> ScoreCalculation: Aggregate Findings
    }
    
    Running --> AI_Debrief: Invoke OpenRouter (Optional)
    AI_Debrief --> Completed: State = COMPLETED
    Running --> Failed: Unrecoverable Error (State = FAILED)
    
    Completed --> [*]
    Failed --> [*]
```

---

## 7. Database Schema & Persistence

### Entity-Relationship Diagram

```mermaid
erDiagram
    AUTHORIZATION_SCOPES ||--o{ ASSESSMENTS : authorizes
    ASSESSMENTS ||--o{ AGENT_RUNS : executes
    ASSESSMENTS ||--o{ EVIDENCE : collects
    ASSESSMENTS ||--o{ FINDINGS : produces
    ASSESSMENTS ||--o{ REDIRECT_HOPS : records
    ASSESSMENTS ||--o{ CERTIFICATE_OBSERVATIONS : inspects
    ASSESSMENTS ||--o{ SERVICE_OBSERVATIONS : discovers
    ASSESSMENTS ||--o{ COOKIE_OBSERVATIONS : audits
    FINDINGS ||--o{ FINDING_EVIDENCE : references
    EVIDENCE ||--o{ FINDING_EVIDENCE : supports
    ASSESSMENTS ||--o{ AUDIT_EVENTS : logs

    AUTHORIZATION_SCOPES {
        uuid id PK
        uuid tenant_id
        varchar target_domain
        jsonb allowed_ports
        boolean active_scans_permitted
        varchar verification_token
        timestamp valid_from
        timestamp valid_until
    }

    ASSESSMENTS {
        uuid id PK
        uuid tenant_id
        uuid scope_id FK
        varchar target_url
        varchar status
        int risk_score
        varchar risk_band
        text executive_summary
        timestamp created_at
        timestamp updated_at
    }

    FINDINGS {
        uuid id PK
        uuid assessment_id FK
        varchar finding_code
        varchar severity
        varchar category
        varchar status
        text description
        text remediation
    }

    REDIRECT_HOPS {
        uuid id PK
        uuid assessment_id FK
        int position
        int status_code
        varchar source_url
        varchar target_url
        varchar resolved_ip
    }

    CERTIFICATE_OBSERVATIONS {
        uuid id PK
        uuid assessment_id FK
        varchar sha256_fingerprint
        varchar subject_cn
        varchar issuer_cn
        timestamp not_before
        timestamp not_after
        int key_length
        varchar tls_version
    }

    SERVICE_OBSERVATIONS {
        uuid id PK
        uuid assessment_id FK
        int port
        varchar protocol
        varchar banner
    }

    COOKIE_OBSERVATIONS {
        uuid id PK
        uuid assessment_id FK
        varchar cookie_name_hash
        boolean is_secure
        boolean is_httponly
        varchar samesite
    }
```

### Database Tables Reference

The TrustLens persistence layer consists of 12 distinct relational tables managed via SQLAlchemy ORM models:

1. **`authorization_scopes`**: Cryptographically tracks ownership verification tokens, authorized target domains, permitted TCP port arrays, and scan validity expiration dates.
2. **`assessments`**: Stores top-level assessment jobs, target URLs, status transitions (`pending`, `running`, `completed`, `failed`), numerical risk scores (0–100), risk bands, executive debrief text, and timestamps (`created_at`, `updated_at`).
3. **`agent_runs`**: Records individual execution cycles for each of the six agents, including start/end timestamps, individual status, and error dumps.
4. **`evidence`**: Stores structured forensic raw data payloads, SHA-256 evidence hashes, and collection metadata.
5. **`findings`**: Records categorized vulnerabilities and configuration weaknesses, assigned severities (`critical`, `high`, `medium`, `low`, `informational`), remediation advice, and analyst review states (`open`, `confirmed`, `false_positive`, `mitigated`).
6. **`finding_evidence`**: Join table mapping specific evidence records to their corresponding security findings.
7. **`redirect_hops`**: Preserves full HTTP redirect trajectories, tracking hop order position, HTTP status codes, source URLs, destination URLs, resolved IP addresses, and response latencies.
8. **`certificate_observations`**: Captures granular cryptographic metrics from TLS handshakes (fingerprints, SAN arrays, cipher names, key lengths, validity dates).
9. **`service_observations`**: Records ports detected listening during authorized scans along with banners and protocol signatures.
10. **`cookie_observations`**: Tracks cookie security flags (`Secure`, `HttpOnly`, `SameSite`) with SHA-256 hashed identifiers.
11. **`indicators`**: Records threat indicators (IOCs) such as suspicious hostnames, malicious URLs, and threat types.
12. **`audit_events`**: Immutable append-only audit trail capturing security-sensitive actions (e.g., analyst finding status updates, scope verifications).

### Alembic Migration History

Database changes are managed strictly using linear Alembic migrations (`backend/migrations/versions/`):

- **`001_initial_schema`** (`641042aa15c7`): Creates base tables (`authorization_scopes`, `assessments`, `findings`, `evidence`, observations, audit tables).
- **`002_allow_nullable_scope_id`** (`d975ad3d463b`): Modifies `assessments.scope_id` to be `NULLABLE` allowing public passive scans without requiring active authorization scopes.
- **`003_assessments_updated_at`** (`a1b2c3d4e5f6`): Adds the `updated_at` column with `server_default=now()` to `assessments` matching ORM requirements.
- **`004_align_models_schema`** (`b2c3d4e5f6a7`): Aligns all ORM columns: adds `position` to `redirect_hops`, `rule_version` to `findings`, and synchronizes observation schemas.

---

## 8. Complete API Documentation

Base URL: `http://localhost:8000` (or `/api` via Nginx frontend proxy)

### Authentication & Sessions

#### `POST /v1/auth/anonymous`
Creates an anonymous visitor session, generating an isolated tenant UUID and returning a signed HS256 JWT valid for 24 hours.

**Request:**
```bash
curl -X POST http://localhost:8000/v1/auth/anonymous \
  -H "Content-Type: application/json"
```

**Response (HTTP 200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 86400,
  "tenant_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "is_anonymous": true
}
```

---

### Health & Readiness Probes

#### `GET /health`
Liveness probe verifying that the FastAPI web server process is responsive.

**Response (HTTP 200 OK):**
```json
{
  "status": "ok",
  "service": "trustlens-api",
  "version": "1.0.0"
}
```

#### `GET /ready`
Readiness probe verifying operational connectivity to PostgreSQL, Redis, and local storage volumes.

**Response (HTTP 200 OK):**
```json
{
  "status": "ready",
  "database": "connected",
  "redis": "connected",
  "storage": "writable"
}
```

---

### Assessments Workflow

#### `POST /v1/assessments`
Submits a target website URL for security evaluation. Returns immediate HTTP `202 Accepted` while analysis executes asynchronously.

**Request Headers:**
- `Authorization: Bearer <TOKEN>` (Required)

**Request Body:**
```json
{
  "target_url": "https://example.com",
  "authorization": {
    "attested": true,
    "scope_id": null
  }
}
```

**Response (HTTP 202 Accepted):**
```json
{
  "id": "c4a7d1e8-782b-4d33-9112-882200334455",
  "target_url": "https://example.com",
  "status": "pending",
  "created_at": "2026-11-08T18:00:00Z"
}
```

#### `GET /v1/assessments/{assessment_id}`
Retrieves the real-time status, risk score, findings, and executive summary for an assessment.

**Response (HTTP 200 OK — Completed State):**
```json
{
  "id": "c4a7d1e8-782b-4d33-9112-882200334455",
  "target_url": "https://example.com",
  "status": "completed",
  "risk_score": 11,
  "risk_band": "LOW",
  "executive_summary": "TrustLens completed security analysis for https://example.com. No critical brand impersonation or malicious threats were detected. The domain serves a valid TLS certificate, though recommendations include adding HSTS and CSP headers.",
  "findings": [
    {
      "id": "f1a2b3c4-d5e6-7890-a1b2-c3d4e5f6a7b8",
      "finding_code": "MISSING_HSTS",
      "severity": "low",
      "category": "privacy",
      "status": "open",
      "description": "Strict-Transport-Security header is missing from HTTP response.",
      "remediation": "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on the web server."
    },
    {
      "id": "e2f3a4b5-c6d7-8901-b2c3-d4e5f6a7b8c9",
      "finding_code": "MISSING_CSP",
      "severity": "low",
      "category": "privacy",
      "status": "open",
      "description": "Content-Security-Policy header is absent.",
      "remediation": "Define a Content-Security-Policy restricting unauthorized script execution."
    }
  ],
  "redirect_hops": [
    {
      "position": 0,
      "status_code": 301,
      "source_url": "http://example.com/",
      "target_url": "https://example.com/",
      "resolved_ip": "93.184.216.34"
    }
  ],
  "created_at": "2026-11-08T18:00:00Z",
  "updated_at": "2026-11-08T18:00:04Z"
}
```

---

### Scope Management

#### `POST /v1/scopes`
Registers an authorization scope contract permitting active port scanning.

**Request:**
```json
{
  "target_domain": "my-authorized-domain.com",
  "allowed_ports": [80, 443, 8080, 8443],
  "active_scans_permitted": true,
  "valid_until": "2026-12-31T23:59:59Z"
}
```

#### `GET /v1/scopes/{scope_id}`
Retrieves the verification state and DNS token for an authorization scope.

---

### Findings & Review

#### `GET /v1/findings`
Lists all security findings for the authenticated tenant with optional filters (`category`, `severity`, `status`).

#### `PATCH /v1/findings/{finding_id}/review`
Allows a security analyst to update finding review status with an audit justification.

**Request:**
```json
{
  "status": "false_positive",
  "rationale": "Legacy server header retained intentionally behind modern WAF proxy.",
  "reviewer": "analyst@example.com"
}
```

---

### Evidence & Artifacts

#### `GET /v1/evidence/{evidence_id}`
Retrieves structured forensic evidence metadata by ID.

#### `GET /v1/evidence/{evidence_id}/artifact`
Streams raw captured evidence artifacts (e.g., extracted certificate bytes or header logs).

---

### Indicators (IOCs)

#### `POST /v1/indicators`
Registers an observed threat indicator (IOC) such as a confirmed phishing domain or malware host.

#### `GET /v1/indicators`
Queries the repository of recorded threat indicators.

---

## 9. Security Architecture

TrustLens was architected from inception to adhere to rigorous application security standards. Scanning untrusted third-party URLs exposes scanners to severe security risks; TrustLens mitigates these through layered defenses:

```
+-----------------------------------------------------------------------------------------+
|                                TRUSTLENS DEFENSE MATRIX                                 |
+-----------------------------------------------------------------------------------------+
| 1. DNS Pre-Flight Validation  ==> Resolves A/AAAA records before connection             |
| 2. Anti-SSRF CIDR Shield      ==> Blocks 0/8, 10/8, 127/8, 169.254/16, 172.16/12, etc.  |
| 3. DNS Rebinding Pinning      ==> Locks resolved IP throughout outbound request stream  |
| 4. Redirect Hop Re-check      ==> Re-resolves and validates target on every HTTP 3xx    |
| 5. Socket-Level Timeouts      ==> Strict 3.0s connect / 5.0s read caps against slowloris|
| 6. Tenant-Scoped Isolation    ==> Multi-tenant JWT claim checks enforced at SQL layer   |
+-----------------------------------------------------------------------------------------+
```

### Anti-SSRF & DNS Rebinding Defenses

Implemented in `backend/app/core/safety.py`:
- **Private IP Blacklist**: Rejects any target resolving to:
  - `0.0.0.0/8` (Local system)
  - `10.0.0.0/8` (Private RFC 1918)
  - `100.64.0.0/10` (Carrier-grade NAT)
  - `127.0.0.0/8` (Loopback)
  - `169.254.0.0/16` (Link-local & Cloud Metadata endpoint `169.254.169.254`)
  - `172.16.0.0/12` (Private RFC 1918)
  - `192.168.0.0/16` (Private RFC 1918)
  - `::1/128`, `fc00::/7`, `fe80::/10` (IPv6 Loopback, ULA, and Link-local)
- **Mixed DNS Rejection**: If a DNS query resolves to multiple IP records (e.g., one public IP and one internal RFC 1918 IP), the resolver **aborts immediately**, rejecting the hostname as an active DNS rebinding attack.
- **IP Literal Filtering**: Direct IP targets in URLs are validated against the CIDR blocklist prior to DNS resolution.

### Egress Network Controls

Implemented in `backend/app/core/egress.py` (`SafeEgressLayer`):
- All outbound HTTP requests use controlled timeouts (default 5.0s connect, 10.0s read).
- Outbound socket connections bypass internal platform networks.
- Redirects are processed manually rather than automatically followed by the HTTP client, ensuring that every hop undergoes full SSRF re-validation.

### Tenant Isolation & RBAC

- Every assessment, scope, finding, and evidence record is keyed to a `tenant_id` UUID in PostgreSQL.
- API endpoints enforce row-level access control based on the `tenant_id` claim in the verified caller's JWT.
- Anonymous visitor sessions are assigned unique, isolated tenant IDs, preventing unauthorized access across distinct visitor sessions.

### Rate Limiting & Abuse Prevention

- Integrated using `slowapi` backed by Redis (with memory fallback).
- Endpoints enforce strict request limits per IP address and tenant token (e.g., maximum 10 assessment submissions per minute per IP for anonymous users).

---

## 10. Risk Scoring Engine & Methodology

### Deterministic Scoring Formula

TrustLens calculates risk scores using an additive penalty points model implemented in `backend/app/core/scoring.py`. The scoring logic is deterministic, transparent, and reproducible:

$$\text{Raw Score} = \sum_{f \in \text{Findings}} \text{Weight}(\text{Severity}_f)$$

$$\text{Final Risk Score} = \min(100, \max(0, \text{Raw Score}))$$

#### Finding Severity Weight Schedule

| Severity Level | Point Contribution | Description |
|---|:---:|---|
| **Critical** | `+40` | Active malware, confirmed phishing, Safe Browsing match |
| **High** | `+20` | Typosquatting, expired/self-signed cert, HTTPS downgrade |
| **Medium** | `+8` | Insecure cookie, weak key length, excessive redirects |
| **Low** | `+3` | Missing HSTS/CSP, outdated banner, abuse-heavy TLD |
| **Informational** | `+0` | Missing SCT log, standard configuration notes |

### Risk Bands & Severity Classifications

The numerical score (0 to 100) is translated into standardized risk bands defined by rule version `2026-1`:

```
+---------------+----------------+-------------------+--------------------+
|  LOW (0 - 19) | GUARDED (20-49)|   HIGH (50 - 74)  | CRITICAL (75 - 100)|
|  Clean Target | Minor Weakness | Elevated Threat   | Dangerous / Attack |
+---------------+----------------+-------------------+--------------------+
```

- **`LOW` (0–19 points)**: Normal posture. No significant threats detected; minor configuration improvements suggested.
- **`GUARDED` (20–49 points)**: Caution advised. Sub-optimal configuration, missing security headers, or weakly configured cookies detected.
- **`HIGH` (50–74 points)**: Dangerous. Active SSL/TLS invalidity, suspicious redirect patterns, or high brand similarity detected.
- **`CRITICAL` (75–100 points)**: Extreme risk. Target matches confirmed threat intelligence databases or active credential harvesting.

---

## 11. Installation & Local Development

### Prerequisites

Ensure the following tools are installed on your host machine:
- **Python**: 3.11, 3.12, or 3.14
- **Node.js**: v18.0.0+ (v20+ LTS recommended) & `npm`
- **Docker & Docker Compose**: (Recommended for running PostgreSQL and Redis)
- **Git**

---

### Windows Setup (PowerShell)

#### 1. Clone the Repository
```powershell
git clone https://github.com/GourGit/HackMatrix.git
cd HackMatrix
```

#### 2. Start PostgreSQL & Redis Infrastructure
```powershell
docker compose up -d db redis
```

#### 3. Setup Backend
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

# Copy environment variables
Copy-Item ..\.env.example .env

# Apply database migrations
alembic upgrade head

# Start FastAPI development server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

#### 4. Setup Frontend (In a New Terminal)
```powershell
cd c:\Users\GOUR SUNDAR BASAK\Desktop\HackMatrix\frontend
npm install
npm run dev
```
The frontend interface will be accessible at: `http://localhost:5173`

---

### Linux / macOS Setup (Bash)

#### 1. Clone the Repository
```bash
git clone https://github.com/GourGit/HackMatrix.git
cd HackMatrix
```

#### 2. Start PostgreSQL & Redis Infrastructure
```bash
docker compose up -d db redis
```

#### 3. Setup Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Copy environment variables
cp ../.env.example .env

# Apply database migrations
alembic upgrade head

# Start FastAPI development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### 4. Setup Frontend (In a New Terminal)
```bash
cd frontend
npm install
npm run dev
```
The application will be live at `http://localhost:5173`.

---

## 12. Docker Deployment

### Single-Command Launch

Deploy the complete multi-service production topology using Docker Compose:

```bash
docker compose up --build -d
```

To monitor logs in real time:
```bash
docker compose logs -f backend
```

To shut down services cleanly:
```bash
docker compose down
```

### Docker Compose Service Topology

The `docker-compose.yml` orchestrates four isolated services:

```mermaid
graph LR
    subgraph Host Network
        Port80[Port 80]
        Port8000[Port 8000]
    end

    Port80 --> Frontend[hackmatrix-frontend\nNginx + Static React Build]
    Port8000 --> Backend[hackmatrix-backend\nFastAPI Uvicorn]
    
    Frontend -.->|Proxy /api/| Backend
    Backend --> DB[(hackmatrix-db\nPostgreSQL 16)]
    Backend --> RedisCache[(hackmatrix-redis\nRedis 7)]
```

- **`frontend`**: Serves the compiled production React application via Nginx on port `80`. Proxies API calls to the backend container.
- **`backend`**: Runs the FastAPI application with Uvicorn on port `8000`. Executes database migrations automatically on startup via `alembic upgrade head`.
- **`db`**: PostgreSQL 16 database running on port `5432` with a persistent named Docker volume (`postgres_data`).
- **`redis`**: Redis 7 cache running on port `6379` for rate limiting and cache storage.

### Service Health Checks

All containers include built-in health probes:
- **Backend**: Inspects `http://127.0.0.1:8000/ready` every 10 seconds.
- **Database**: Runs `pg_isready -U postgres` every 5 seconds.
- **Redis**: Runs `redis-cli ping` every 5 seconds.

---

## 13. Testing & Quality Assurance

TrustLens incorporates a comprehensive automated test suite consisting of **99 automated tests** covering unit logic, integration boundaries, database migrations, and security defenses.

### Backend Test Matrix (99 Tests)

| Test Suite File | Test Count | Scope & Focus Areas |
|---|:---:|---|
| `tests/test_agents.py` | 10 | Execution logic of all 6 security agents |
| `tests/test_anonymous_auth.py` | 6 | JWT token issuance, session isolation, anonymous auth |
| `tests/test_assessment_attestation.py` | 5 | Attestation validation, 422 rejections, scope checks |
| `tests/test_dns_safety.py` | 3 | Mixed DNS records, IPv6 loopback, and rebinding rejection |
| `tests/test_evidence_findings.py` | 5 | Evidence persistence, finding links, observation models |
| `tests/test_health.py` | 2 | `/health` liveness and `/ready` dependency readiness probes |
| `tests/test_indicators_audit.py` | 4 | Threat IOC tracking and append-only audit event logging |
| `tests/test_migrations.py` | 2 | Forward Alembic migration execution (`001` through `004`) |
| `tests/test_openrouter.py` | 7 | Claude-3-Haiku integration, sanitization, fallback modes |
| `tests/test_orchestrator.py` | 6 | Engine workflow, timeout recovery, context lifecycle |
| `tests/test_orchestrator_execution.py` | 13 | End-to-end background task orchestration |
| `tests/test_routes.py` | 12 | REST route validation, HTTP status codes, payloads |
| `tests/test_url_validator.py` | 24 | Anti-SSRF URL parsing, CIDR blocking, private ranges |
| **Total** | **99** | **100% Pass Rate Across Complete Test Suite** |

### Running Backend Tests

Run the full test suite with verbose output:
```powershell
# From the backend directory
pytest -v
```

Run specific security regression tests:
```powershell
pytest tests/test_url_validator.py tests/test_dns_safety.py -v
```

### Frontend Test & Build Verification

Verify that the frontend builds without TypeScript or bundling errors:
```powershell
# From the frontend directory
npm run build
```

---

## 14. Visual Documentation & UI Walkthrough

```
+-----------------------------------------------------------------------------------------+
|                                    USER INTERFACE                                       |
+-----------------------------------------------------------------------------------------+
```

### 1. Assessment Submission Dashboard
The main interface allows users to submit target URLs, toggle active scanning options, and attest domain ownership.

```
+-----------------------------------------------------------------------------------------+
|  [ TrustLens Logo ]    HackMatrix — Digital Trust Platform               (Anon Visitor) |
|-----------------------------------------------------------------------------------------|
|                                                                                         |
|   Enter Target URL to Assess:                                                           |
|   [ https://example-suspicious-login.com                             ] [ Assess URL ]   |
|                                                                                         |
|   [X] I attest that I am authorized to perform this assessment (Passive Security Scan)  |
|                                                                                         |
+-----------------------------------------------------------------------------------------+
```
*(Screenshot Placeholder: `docs/screenshots/01_assessment_dashboard.png`)*

---

### 2. Live Assessment Progress & Agent Execution Grid
Real-time status updates indicate the execution progress of each security agent.

```
+-----------------------------------------------------------------------------------------+
|  Assessment: c4a7d1e8-782b-4d33-9112-882200334455                Status: [ RUNNING ]    |
|-----------------------------------------------------------------------------------------|
|  [✓] url-redirect          [✓] phishing-brand         [✓] certificate-intel             |
|  [✓] safe-surface          [...] privacy-software     [...] threat-intelligence         |
+-----------------------------------------------------------------------------------------+
```
*(Screenshot Placeholder: `docs/screenshots/02_live_agent_grid.png`)*

---

### 3. Detailed Results & Risk Badge Breakdown
Completed assessments display the numerical risk score, risk band badge, and executive summary debrief.

```
+-----------------------------------------------------------------------------------------+
|  Risk Score: [ 68 / 100 ]                                           Risk Band: [ HIGH ] |
|-----------------------------------------------------------------------------------------|
|  Executive Summary:                                                                     |
|  TrustLens identified significant security concerns for this target. A potential        |
|  phishing credential harvesting form was detected, and the SSL certificate expires in   |
|  2 days. Furthermore, the domain resides on an abuse-heavy TLD.                         |
|                                                                                         |
|  Security Findings:                                                                     |
|  [ HIGH ]   SUSPICIOUS_BRAND        Typosquatting detected against 'PayPal' (0.89 ratio)|
|  [ HIGH ]   SUSPICIOUS_FORM         Password input submitting over unencrypted HTTP     |
|  [ LOW  ]   MISSING_HSTS            Strict-Transport-Security header is absent          |
+-----------------------------------------------------------------------------------------+
```
*(Screenshot Placeholder: `docs/screenshots/03_assessment_results.png`)*

---

## 15. Repository Directory Structure

```
HackMatrix/
├── .env.example                       # Reference environment variables template
├── .gitignore                         # Git exclusion rules (venv, node_modules, .env)
├── docker-compose.yml                 # Multi-container orchestration definition
├── README.md                          # Master documentation (this document)
├── backend/                           # FastAPI Application Root
│   ├── alembic.ini                    # Alembic configuration
│   ├── requirements.txt               # Pinned Python backend dependencies
│   ├── app/
│   │   ├── main.py                    # Application entry point, middleware, lifespans
│   │   ├── agents/                    # 6 Deterministic Security Analyzer Agents
│   │   │   ├── base.py                # BaseAgent abstract class & contracts
│   │   │   ├── certificate_intel.py   # TLS/SSL & Cryptographic analyzer
│   │   │   ├── phishing_brand.py      # Brand impersonation & Levenshtein heuristics
│   │   │   ├── privacy_software.py    # Headers, cookies, & script analyzer
│   │   │   ├── safe_surface.py        # Scoped port probing & banner analysis
│   │   │   ├── threat_intel.py        # Google Safe Browsing & TLD checks
│   │   │   └── url_redirect.py        # SSRF-guarded redirect hop tracer
│   │   ├── api/                       # REST Route Handlers
│   │   │   ├── v1/
│   │   │   │   ├── assessments.py     # Assessment creation, polling, and status
│   │   │   │   ├── auth.py            # Anonymous visitor authentication
│   │   │   │   ├── evidence.py        # Forensic evidence & artifact routes
│   │   │   │   ├── findings.py        # Findings review & status patches
│   │   │   │   ├── indicators.py      # IOC indicators & threat registry
│   │   │   │   └── scopes.py          # Active scan authorization scopes
│   │   │   └── routes/
│   │   │       └── health.py          # /health & /ready probes
│   │   ├── core/                      # Foundational Engine Logic
│   │   │   ├── config.py              # Pydantic BaseSettings management
│   │   │   ├── database.py            # SQLAlchemy async engine & session maker
│   │   │   ├── egress.py              # Safe network egress & socket wrappers
│   │   │   ├── safety.py              # Anti-SSRF, DNS validation, & CIDR blocks
│   │   │   └── scoring.py             # Deterministic risk scoring formula
│   │   ├── integrations/
│   │   │   └── openrouter.py          # Claude-3-Haiku AI Analyst Integration
│   │   ├── models/                    # SQLAlchemy Database ORM Models
│   │   │   ├── assessment.py          # Assessment & AgentRun models
│   │   │   ├── evidence.py            # Evidence & Observation models
│   │   │   ├── finding.py             # Finding & FindingEvidence models
│   │   │   └── scope.py               # AuthorizationScope & AuditEvent models
│   │   ├── orchestrator/
│   │   │   └── engine.py              # Asyncio coordinator & workflow engine
│   │   └── schemas/                   # Pydantic Request & Response Schemas
│   │       ├── assessment.py          # Assessment input/output models
│   │       ├── evidence.py            # Evidence data contracts
│   │       ├── finding.py             # Finding data contracts
│   │       └── scope.py               # Scope validation schemas
│   ├── migrations/                    # Alembic Database Migrations
│   │   ├── env.py                     # Alembic async environment runner
│   │   └── versions/
│   │       ├── 001_initial_schema.py
│   │       ├── 002_allow_nullable_scope_id.py
│   │       ├── 003_assessments_updated_at.py
│   │       └── 004_align_models_schema.py
│   └── tests/                         # Pytest Automated Test Suite (99 Tests)
│       ├── test_agents.py
│       ├── test_anonymous_auth.py
│       ├── test_assessment_attestation.py
│       ├── test_dns_safety.py
│       ├── test_evidence_findings.py
│       ├── test_health.py
│       ├── test_indicators_audit.py
│       ├── test_migrations.py
│       ├── test_openrouter.py
│       ├── test_orchestrator.py
│       ├── test_orchestrator_execution.py
│       ├── test_routes.py
│       └── test_url_validator.py
└── frontend/                          # React + TypeScript Frontend Root
    ├── index.html                     # HTML page template
    ├── package.json                   # Frontend npm dependencies
    ├── postcss.config.js              # PostCSS configuration
    ├── tailwind.config.js             # Tailwind CSS theme configuration
    ├── tsconfig.json                  # TypeScript compiler settings
    ├── vite.config.ts                 # Vite bundler configuration
    └── src/
        ├── App.tsx                    # Top-level application component
        ├── main.tsx                   # React DOM entry point
        ├── api/
        │   └── client.ts              # In-memory JWT storage & HTTP client
        ├── components/                # Reusable UI Components
        │   ├── AssessmentForm.tsx     # Submission input form & attestation check
        │   ├── AssessmentResults.tsx  # Score cards, findings, & AI debrief
        │   ├── Header.tsx             # Navbar & visitor session status
        │   └── LiveScanProgress.tsx   # Real-time agent progress indicator
        └── types/
            └── index.ts               # Shared TypeScript interfaces & types
```

---

## 16. Environment Variables Reference

A documented `.env.example` template is provided in the repository root:

```bash
# ==============================================================================
# HACKMATRIX / TRUSTLENS CONFIGURATION TEMPLATE
# ==============================================================================

# Database Persistence (PostgreSQL)
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/trustlens

# Redis Cache & Rate Limiting
REDIS_URL=redis://localhost:6379/0

# Security & Cryptography
SECRET_KEY=change-this-in-production-to-a-secure-random-32-byte-hex-string
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Network Egress & SSRF Protection
ALLOW_PRIVATE_IPS=False
EGRESS_CONNECT_TIMEOUT_SECONDS=5.0
EGRESS_READ_TIMEOUT_SECONDS=10.0
MAX_REDIRECT_HOPS=10

# AI Debrief Integration (OpenRouter)
OPENROUTER_API_KEY=
OPENROUTER_MODEL=anthropic/claude-3-haiku
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1

# External Threat Intelligence
SAFE_BROWSING_API_KEY=

# Feature Flags
FEATURE_CRYPTO_SCAM_DETECTION=True
FEATURE_ACTIVE_PORT_SCANNING=True
```

---

## 17. Limitations & Future Roadmap

### Honest System Constraints

1. **No Client-Side JavaScript Execution**: TrustLens analyzes static HTML responses and server headers. Highly complex single-page apps (SPAs) that render DOM elements exclusively through client-side JavaScript execution without server-side rendering may not expose form elements to the static HTML parser.
2. **Deterministic Risk Heuristics**: The risk score is determined by observable network-level and configuration indicators. It provides a measure of risk, but no automated scan can provide an absolute guarantee that a website is benign or malicious.
3. **External Rate Limits**: When `SAFE_BROWSING_API_KEY` is not provided or API quotas are exhausted, reputation analysis falls back strictly to internal heuristic TLD and raw IP checks.

### Future Roadmap

- [ ] **Headless Browser Crawler**: Introduce a sandboxed Playwright/Puppeteer worker to render JavaScript-heavy web applications and capture visual screenshots.
- [ ] **Automated PDF Export**: Generate branded, audit-ready compliance PDF reports for enterprise risk documentation.
- [ ] **Expanded Threat Intelligence Feeds**: Add connectors for VirusTotal, AlienVault OTX, and URLhaus.
- [ ] **Continuous Monitoring**: Allow enterprise users to register domains for periodic daily/weekly health and reputation checks.

---

## 18. Contribution Guidelines

We welcome community contributions to HackMatrix — TrustLens! To maintain stability and security:

1. **Fork the Repository**: Create your feature branch from `main`:
   ```bash
   git checkout -b feature/amazing-agent
   ```
2. **Adhere to Code Standards**:
   - Ensure all Python code is formatted with `black` and adheres to `flake8` guidelines.
   - Maintain strict typing in frontend TypeScript components.
3. **Preserve Security Controls**:
   - Never disable or bypass SSRF checks, IP literal validation, or scope checks.
4. **Add Automated Tests**:
   - Every new feature or agent heuristic must be accompanied by comprehensive tests in `backend/tests/`.
5. **Run the Full Test Suite**:
   ```bash
   pytest -v
   ```
6. **Submit a Pull Request**: Provide a clear description of changes, referenced issues, and test verification output.

---

## 19. License & Acknowledgements

### License

This project is open-source under the terms of the MIT License. See the repository for details.

### Acknowledgements

- Built with [FastAPI](https://fastapi.tiangolo.com) for high-performance Python asynchronous APIs.
- Frontend powered by [React](https://react.dev), [Vite](https://vitejs.dev), and [Tailwind CSS](https://tailwindcss.com).
- Threat intelligence powered by [Google Safe Browsing](https://developers.google.com/safe-browsing).
- Executive debriefs supported via [OpenRouter](https://openrouter.ai).
- Icons provided by [Lucide Icons](https://lucide.dev).

---

<p align="center">
  <b>HackMatrix — TrustLens</b> &bull; Built with security, transparency, and deterministic precision.
</p>
