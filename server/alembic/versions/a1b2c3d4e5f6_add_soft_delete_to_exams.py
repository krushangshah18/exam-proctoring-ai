"""add soft delete to exams

Revision ID: a1b2c3d4e5f6
Revises: 815b15263e07
Create Date: 2026-03-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '815b15263e07'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('exams', sa.Column('is_deleted', sa.Boolean(), server_default='false', nullable=True))
    op.add_column('exams', sa.Column('deleted_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column('exams', 'deleted_at')
    op.drop_column('exams', 'is_deleted')
