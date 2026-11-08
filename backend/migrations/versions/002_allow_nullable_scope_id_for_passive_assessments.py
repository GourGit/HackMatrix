"""allow nullable scope_id for passive assessments

Revision ID: 002_allow_nullable_scope_id
Revises: 001_initial_schema
Create Date: 2026-11-08 20:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002_allow_nullable_scope_id'
down_revision: Union[str, Sequence[str], None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        'assessments',
        'scope_id',
        existing_type=sa.UUID(as_uuid=True),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        'assessments',
        'scope_id',
        existing_type=sa.UUID(as_uuid=True),
        nullable=False,
    )

