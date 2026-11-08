"""align models schema for observations and redirect hops

Revision ID: 004_align_models_schema
Revises: 003_assessments_updated_at
Create Date: 2026-11-08 22:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '004_align_models_schema'
down_revision: Union[str, Sequence[str], None] = '003_assessments_updated_at'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. redirect_hops ─────────────────────────────────────────────────
    op.add_column('redirect_hops', sa.Column('position', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('redirect_hops', sa.Column('from_url', sa.Text(), nullable=False, server_default=''))
    op.add_column('redirect_hops', sa.Column('to_url', sa.Text(), nullable=False, server_default=''))
    op.alter_column('redirect_hops', 'agent_run_id', existing_type=sa.UUID(as_uuid=True), nullable=True)
    op.alter_column('redirect_hops', 'hop_number', existing_type=sa.Integer(), nullable=True)
    op.alter_column('redirect_hops', 'source_url', existing_type=sa.Text(), nullable=True)
    op.alter_column('redirect_hops', 'target_url', existing_type=sa.Text(), nullable=True)
    op.alter_column('redirect_hops', 'resolved_ip', existing_type=sa.String(length=64), nullable=True)
    op.alter_column('redirect_hops', 'duration_ms', existing_type=sa.Integer(), nullable=True)
    op.create_index('ix_redirect_hops_assessment_position', 'redirect_hops', ['assessment_id', 'position'])

    # ── 2. agent_runs ────────────────────────────────────────────────────
    op.add_column('agent_runs', sa.Column('rule_version', sa.String(length=30), nullable=True))

    # ── 3. certificate_observations ──────────────────────────────────────
    op.add_column('certificate_observations', sa.Column('host', sa.String(length=255), nullable=False, server_default=''))
    op.add_column('certificate_observations', sa.Column('leaf_fingerprint', sa.String(length=128), nullable=False, server_default=''))
    op.add_column('certificate_observations', sa.Column('chain_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('certificate_observations', sa.Column('ca_status', sa.String(length=20), nullable=False, server_default='unknown'))
    op.add_column('certificate_observations', sa.Column('hostname_status', sa.String(length=20), nullable=False, server_default='unknown'))
    op.add_column('certificate_observations', sa.Column('ct_status', sa.String(length=20), nullable=False, server_default='unknown'))
    op.add_column('certificate_observations', sa.Column('revocation_status', sa.String(length=20), nullable=False, server_default='unknown'))
    op.add_column('certificate_observations', sa.Column('crypto_json', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.alter_column('certificate_observations', 'agent_run_id', existing_type=sa.UUID(as_uuid=True), nullable=True)
    op.create_index('ix_cert_obs_assessment_host', 'certificate_observations', ['assessment_id', 'host'])

    # ── 4. service_observations ──────────────────────────────────────────
    op.add_column('service_observations', sa.Column('host', sa.String(length=255), nullable=False, server_default=''))
    op.add_column('service_observations', sa.Column('version_hint', sa.String(length=100), nullable=True))
    op.add_column(
        'service_observations',
        sa.Column('authorization_scope_id', sa.UUID(as_uuid=True), sa.ForeignKey('authorization_scopes.id', ondelete='SET NULL'), nullable=True),
    )
    op.alter_column('service_observations', 'agent_run_id', existing_type=sa.UUID(as_uuid=True), nullable=True)
    op.alter_column('service_observations', 'state', existing_type=sa.String(length=20), nullable=True)
    op.create_index('ix_service_obs_assessment_host_port', 'service_observations', ['assessment_id', 'host', 'port'])
    op.create_index('ix_service_obs_scope', 'service_observations', ['authorization_scope_id'])

    # ── 5. cookie_observations ───────────────────────────────────────────
    op.add_column('cookie_observations', sa.Column('third_party_context', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.alter_column('cookie_observations', 'agent_run_id', existing_type=sa.UUID(as_uuid=True), nullable=True)
    op.create_index('ix_cookie_obs_assessment_hash', 'cookie_observations', ['assessment_id', 'name_hash'])


def downgrade() -> None:
    # ── 5. cookie_observations ───────────────────────────────────────────
    op.drop_index('ix_cookie_obs_assessment_hash', table_name='cookie_observations')
    op.alter_column('cookie_observations', 'agent_run_id', existing_type=sa.UUID(as_uuid=True), nullable=False)
    op.drop_column('cookie_observations', 'third_party_context')

    # ── 4. service_observations ──────────────────────────────────────────
    op.drop_index('ix_service_obs_scope', table_name='service_observations')
    op.drop_index('ix_service_obs_assessment_host_port', table_name='service_observations')
    op.alter_column('service_observations', 'state', existing_type=sa.String(length=20), nullable=False)
    op.alter_column('service_observations', 'agent_run_id', existing_type=sa.UUID(as_uuid=True), nullable=False)
    op.drop_column('service_observations', 'authorization_scope_id')
    op.drop_column('service_observations', 'version_hint')
    op.drop_column('service_observations', 'host')

    # ── 3. certificate_observations ──────────────────────────────────────
    op.drop_index('ix_cert_obs_assessment_host', table_name='certificate_observations')
    op.alter_column('certificate_observations', 'agent_run_id', existing_type=sa.UUID(as_uuid=True), nullable=False)
    op.drop_column('certificate_observations', 'crypto_json')
    op.drop_column('certificate_observations', 'revocation_status')
    op.drop_column('certificate_observations', 'ct_status')
    op.drop_column('certificate_observations', 'hostname_status')
    op.drop_column('certificate_observations', 'ca_status')
    op.drop_column('certificate_observations', 'chain_json')
    op.drop_column('certificate_observations', 'leaf_fingerprint')
    op.drop_column('certificate_observations', 'host')

    # ── 2. agent_runs ────────────────────────────────────────────────────
    op.drop_column('agent_runs', 'rule_version')

    # ── 1. redirect_hops ─────────────────────────────────────────────────
    op.drop_index('ix_redirect_hops_assessment_position', table_name='redirect_hops')
    op.alter_column('redirect_hops', 'duration_ms', existing_type=sa.Integer(), nullable=False)
    op.alter_column('redirect_hops', 'resolved_ip', existing_type=sa.String(length=64), nullable=False)
    op.alter_column('redirect_hops', 'target_url', existing_type=sa.Text(), nullable=False)
    op.alter_column('redirect_hops', 'source_url', existing_type=sa.Text(), nullable=False)
    op.alter_column('redirect_hops', 'hop_number', existing_type=sa.Integer(), nullable=False)
    op.alter_column('redirect_hops', 'agent_run_id', existing_type=sa.UUID(as_uuid=True), nullable=False)
    op.drop_column('redirect_hops', 'to_url')
    op.drop_column('redirect_hops', 'from_url')
    op.drop_column('redirect_hops', 'position')

