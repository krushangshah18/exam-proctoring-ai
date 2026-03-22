"""add session extension and review fields

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-19 00:01:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('exam_sessions', sa.Column('terminated_at', sa.DateTime(), nullable=True))
    op.add_column('exam_sessions', sa.Column('time_extension_seconds', sa.Integer(), server_default='0', nullable=False))
    op.add_column('resume_requests', sa.Column('reviewed_at', sa.DateTime(), nullable=True))
    op.add_column('resume_requests', sa.Column('time_extension_minutes', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('resume_requests', 'time_extension_minutes')
    op.drop_column('resume_requests', 'reviewed_at')
    op.drop_column('exam_sessions', 'time_extension_seconds')
    op.drop_column('exam_sessions', 'terminated_at')
