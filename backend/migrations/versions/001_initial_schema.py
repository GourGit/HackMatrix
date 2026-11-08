"""initial_schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-08 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. authorization_scopes
    op.create_table(
        'authorization_scopes',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('subject_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('targets_json', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('allowed_ports_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=False),
        sa.Column('attestation', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_authorization_scopes_tenant_id', 'authorization_scopes', ['tenant_id'])
    op.create_index('ix_authorization_scopes_subject_id', 'authorization_scopes', ['subject_id'])
    op.create_index('ix_authorization_scopes_tenant_status', 'authorization_scopes', ['tenant_id', 'status'])

    # 2. assessments
    op.create_table(
        'assessments',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('scope_id', sa.UUID(as_uuid=True), sa.ForeignKey('authorization_scopes.id', ondelete='CASCADE'), nullable=False),
        sa.Column('submitted_url', sa.Text(), nullable=False),
        sa.Column('normalized_url', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='queued'),
        sa.Column('score', sa.Integer(), nullable=True),
        sa.Column('score_band', sa.String(length=20), nullable=True),
        sa.Column('score_version', sa.String(length=30), nullable=True),
        sa.Column('error_code', sa.String(length=100), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('checks_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_assessments_tenant_id', 'assessments', ['tenant_id'])
    op.create_index('ix_assessments_scope_id', 'assessments', ['scope_id'])
    op.create_index('ix_assessments_tenant_status', 'assessments', ['tenant_id', 'status'])
    op.create_index('ix_assessments_created_at', 'assessments', ['created_at'])

    # 3. agent_runs
    op.create_table(
        'agent_runs',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', sa.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_name', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='queued'),
        sa.Column('error_code', sa.String(length=100), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('check_availability_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_agent_runs_assessment_id', 'agent_runs', ['assessment_id'])
    op.create_index('ix_agent_runs_assessment_agent', 'agent_runs', ['assessment_id', 'agent_name'])

    # 4. evidence
    op.create_table(
        'evidence',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', sa.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_run_id', sa.UUID(as_uuid=True), sa.ForeignKey('agent_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(length=40), nullable=False),
        sa.Column('source_uri', sa.Text(), nullable=False),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_ref', sa.Text(), nullable=False),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('collector_version', sa.String(length=30), nullable=False),
        sa.Column('redaction_version', sa.String(length=30), nullable=False, server_default='1.0'),
        sa.Column('retention_until', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_evidence_assessment_id', 'evidence', ['assessment_id'])
    op.create_index('ix_evidence_agent_run_id', 'evidence', ['agent_run_id'])
    op.create_index('ix_evidence_content_hash', 'evidence', ['content_hash'])

    # 5. findings
    op.create_table(
        'findings',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', sa.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_run_id', sa.UUID(as_uuid=True), sa.ForeignKey('agent_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('score_impact', sa.Float(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='active'),
        sa.Column('decision', sa.String(length=30), nullable=True),
        sa.Column('reviewer_id', sa.UUID(as_uuid=True), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=True),
        sa.Column('asset', sa.Text(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('rule_version', sa.String(length=30), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_findings_assessment_id', 'findings', ['assessment_id'])
    op.create_index('ix_findings_agent_run_id', 'findings', ['agent_run_id'])
    op.create_index('ix_findings_type_severity', 'findings', ['type', 'severity'])
    op.create_index('ix_findings_assessment_type', 'findings', ['assessment_id', 'type'])
    op.create_index('ix_findings_reviewer_id', 'findings', ['reviewer_id'])

    # 6. finding_evidence (junction)
    op.create_table(
        'finding_evidence',
        sa.Column('finding_id', sa.UUID(as_uuid=True), sa.ForeignKey('findings.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('evidence_id', sa.UUID(as_uuid=True), sa.ForeignKey('evidence.id', ondelete='CASCADE'), primary_key=True),
    )

    # 7. redirect_hops
    op.create_table(
        'redirect_hops',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', sa.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_run_id', sa.UUID(as_uuid=True), sa.ForeignKey('agent_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('hop_number', sa.Integer(), nullable=False),
        sa.Column('source_url', sa.Text(), nullable=False),
        sa.Column('target_url', sa.Text(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('resolved_ip', sa.String(length=64), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=False),
        sa.Column('evidence_id', sa.UUID(as_uuid=True), sa.ForeignKey('evidence.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_redirect_hops_assessment_id', 'redirect_hops', ['assessment_id'])
    op.create_index('ix_redirect_hops_assessment_hop', 'redirect_hops', ['assessment_id', 'hop_number'])

    # 8. certificate_observations
    op.create_table(
        'certificate_observations',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', sa.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_run_id', sa.UUID(as_uuid=True), sa.ForeignKey('agent_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('subject_cn', sa.String(length=255), nullable=True),
        sa.Column('issuer_cn', sa.String(length=255), nullable=True),
        sa.Column('sans_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=True),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=True),
        sa.Column('fingerprint_sha256', sa.String(length=64), nullable=True),
        sa.Column('serial_number', sa.String(length=128), nullable=True),
        sa.Column('chain_valid', sa.Boolean(), nullable=True),
        sa.Column('ct_present', sa.Boolean(), nullable=True),
        sa.Column('ocsp_status', sa.String(length=30), nullable=True),
        sa.Column('tls_version', sa.String(length=20), nullable=True),
        sa.Column('cipher', sa.String(length=100), nullable=True),
        sa.Column('evidence_id', sa.UUID(as_uuid=True), sa.ForeignKey('evidence.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_certificate_observations_assessment_id', 'certificate_observations', ['assessment_id'])

    # 9. service_observations
    op.create_table(
        'service_observations',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', sa.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_run_id', sa.UUID(as_uuid=True), sa.ForeignKey('agent_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(length=20), nullable=False),
        sa.Column('state', sa.String(length=20), nullable=False),
        sa.Column('service_name', sa.String(length=100), nullable=True),
        sa.Column('product', sa.String(length=255), nullable=True),
        sa.Column('version', sa.String(length=100), nullable=True),
        sa.Column('banner', sa.Text(), nullable=True),
        sa.Column('cpe', sa.String(length=255), nullable=True),
        sa.Column('evidence_id', sa.UUID(as_uuid=True), sa.ForeignKey('evidence.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_service_observations_assessment_port', 'service_observations', ['assessment_id', 'port'])

    # 10. cookie_observations
    op.create_table(
        'cookie_observations',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('assessment_id', sa.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('agent_run_id', sa.UUID(as_uuid=True), sa.ForeignKey('agent_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name_hash', sa.String(length=64), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('path', sa.String(length=255), nullable=True),
        sa.Column('secure', sa.Boolean(), nullable=False),
        sa.Column('http_only', sa.Boolean(), nullable=False),
        sa.Column('same_site', sa.String(length=20), nullable=True),
        sa.Column('max_age', sa.Integer(), nullable=True),
        sa.Column('expires', sa.DateTime(timezone=True), nullable=True),
        sa.Column('evidence_id', sa.UUID(as_uuid=True), sa.ForeignKey('evidence.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_cookie_observations_assessment_id', 'cookie_observations', ['assessment_id'])

    # 11. indicators
    op.create_table(
        'indicators',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('type', sa.String(length=40), nullable=False),
        sa.Column('value_normalized', sa.String(length=2048), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('sharing_policy', sa.String(length=20), nullable=False, server_default='private'),
        sa.Column('review_status', sa.String(length=20), nullable=False, server_default='pending_review'),
        sa.Column('source_evidence_id', sa.UUID(as_uuid=True), sa.ForeignKey('evidence.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_indicators_tenant_id', 'indicators', ['tenant_id'])
    op.create_index('ix_indicators_type_value', 'indicators', ['type', 'value_normalized'])
    op.create_index('ix_indicators_tenant_type', 'indicators', ['tenant_id', 'type'])

    # 12. audit_events
    op.create_table(
        'audit_events',
        sa.Column('id', sa.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('actor_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('entity_type', sa.String(length=100), nullable=False),
        sa.Column('entity_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('metadata_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('occurred_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_audit_events_tenant_id', 'audit_events', ['tenant_id'])
    op.create_index('ix_audit_events_actor_id', 'audit_events', ['actor_id'])
    op.create_index('ix_audit_events_entity', 'audit_events', ['entity_type', 'entity_id'])
    op.create_index('ix_audit_events_tenant_action', 'audit_events', ['tenant_id', 'action'])
    op.create_index('ix_audit_events_occurred_at', 'audit_events', ['occurred_at'])


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('indicators')
    op.drop_table('cookie_observations')
    op.drop_table('service_observations')
    op.drop_table('certificate_observations')
    op.drop_table('redirect_hops')
    op.drop_table('finding_evidence')
    op.drop_table('findings')
    op.drop_table('evidence')
    op.drop_table('agent_runs')
    op.drop_table('assessments')
    op.drop_table('authorization_scopes')

