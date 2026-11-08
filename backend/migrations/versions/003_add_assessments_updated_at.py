"""add updated_at to assessments

Revision ID: 003_assessments_updated_at
Revises: 002_allow_nullable_scope_id
Create Date: 2026-11-08 22:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic (must be <= 32 chars).
revision: str = '003_assessments_updated_at'
down_revision: Union[str, Sequence[str], None] = '002_allow_nullable_scope_id'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'assessments',
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('assessments', 'updated_at')

