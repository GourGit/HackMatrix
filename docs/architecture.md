# Architecture

TrustLens is an asynchronous, evidence-first assessment service.

`Client → API → authorization/scope gate → job orchestrator → six agents → evidence store + relational database → scoring/correlation → API/dashboard`

## Components

- **API gateway** authenticates users, validates URL submissions, enforces tenant and authorization scope, and queues work.
- **Safety gateway** resolves DNS, blocks unsafe address classes, enforces egress policy, throttling, redirect validation, and target/port allowlists.
- **Orchestrator** creates a snapshot of scope and rule versions, schedules agents, handles retries, and finalizes incomplete jobs safely.
- **Agents** run isolated with least-privilege network policy and emit signed/hashed evidence references.
- **Evidence store** keeps encrypted raw artifacts and normalized extracts. The database stores metadata, hashes, access policy, and lineage.
- **Scoring and correlation** use only accepted normalized findings; outputs remain explainable and versioned.

## Certificate pipeline

The Certificate Intelligence Agent captures peer certificates and chain context, validates hostname/SAN, expiry, issuer/CA trust, chain construction, key size/algorithm and TLS protocol/cipher. It queries OCSP and/or CRL only through approved resolvers and records unavailable as unknown. CT checks capture SCT presence and matching log evidence where accessible. No revocation result is inferred from network failure.

## Safe assessment pipeline

HTTP requests use a dedicated egress service, strict method allowlist (`GET`, `HEAD`), size/time limits, credential stripping, and secret redaction. Service discovery is disabled by default and enabled only with an explicit authorization record listing hostnames/IPs, ports, window, and rate limits. Banner/version detection is observational and never triggers exploit validation.

## Data and resilience

Use a relational store for entities and a content-addressed object store for evidence. Encrypt in transit/at rest, separate tenant access, append audit events, and retain only necessary artifacts. Jobs are idempotent; each retry receives a new execution record linked to the same assessment.
