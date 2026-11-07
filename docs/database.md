# Database Schema

Use UUID primary keys, UTC timestamps, tenant IDs on all tenant-owned records, soft deletion where required, and append-only audit events.

## Core tables

| Table | Key columns |
|---|---|
| `authorization_scopes` | `id`, `tenant_id`, `subject_id`, `targets_json`, `allowed_ports_json`, `valid_from`, `valid_until`, `attestation`, `status` |
| `assessments` | `id`, `tenant_id`, `scope_id`, `submitted_url`, `normalized_url`, `status`, `score`, `score_band`, `score_version`, `created_at`, `completed_at` |
| `agent_runs` | `id`, `assessment_id`, `agent_name`, `status`, `rule_version`, `started_at`, `ended_at`, `error_code` |
| `findings` | `id`, `assessment_id`, `agent_run_id`, `type`, `severity`, `confidence`, `score_impact`, `status`, `asset`, `summary`, `rule_version`, `observed_at` |
| `evidence` | `id`, `assessment_id`, `agent_run_id`, `kind`, `source_uri`, `content_hash`, `storage_ref`, `collected_at`, `collector_version`, `redaction_version`, `retention_until` |
| `finding_evidence` | `finding_id`, `evidence_id` |
| `redirect_hops` | `id`, `assessment_id`, `position`, `from_url`, `to_url`, `status_code`, `evidence_id` |
| `certificate_observations` | `id`, `assessment_id`, `host`, `leaf_fingerprint`, `chain_json`, `ca_status`, `hostname_status`, `ct_status`, `revocation_status`, `crypto_json`, `evidence_id` |
| `service_observations` | `id`, `assessment_id`, `host`, `port`, `protocol`, `banner`, `version_hint`, `authorization_scope_id`, `evidence_id` |
| `cookie_observations` | `id`, `assessment_id`, `name_hash`, `domain`, `path`, `secure`, `http_only`, `same_site`, `max_age`, `third_party_context`, `evidence_id` |
| `indicators` | `id`, `tenant_id`, `type`, `value_normalized`, `confidence`, `sharing_policy`, `review_status`, `source_evidence_id`, `created_at` |
| `audit_events` | `id`, `tenant_id`, `actor_id`, `action`, `entity_type`, `entity_id`, `metadata_json`, `occurred_at` |

Store sensitive cookie values, response bodies, and credentials nowhere; store redacted or hashed representations only. Index assessment/status, findings/type/severity, evidence/content_hash, indicators/type/value, and scoped service observations. Foreign keys enforce provenance from findings to agent runs and evidence.
