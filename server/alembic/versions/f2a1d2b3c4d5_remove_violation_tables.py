"""remove violation tables

Revision ID: f2a1d2b3c4d5
Revises: c1d2e3f4a5b6
Create Date: 2026-03-27 17:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f2a1d2b3c4d5'
down_revision: Union[str, Sequence[str], None] = 'c1d2e3f4a5b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_table('risk_snapshots')
    op.drop_table('model_verifications')
    op.drop_table('evidences')
    op.drop_table('violations')
    op.drop_table('violation_types')


def downgrade() -> None:
    """Downgrade schema."""
    op.create_table(
        'violation_types',
        sa.Column('code', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('default_score', sa.Integer(), nullable=True),
        sa.Column('default_message', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code'),
    )
    op.create_table(
        'violations',
        sa.Column('session_id', sa.UUID(), nullable=True),
        sa.Column('violation_type_id', sa.UUID(), nullable=True),
        sa.Column('client_confidence', sa.Float(), nullable=True),
        sa.Column('server_confidence', sa.Float(), nullable=True),
        sa.Column('final_verdict', sa.String(), nullable=True),
        sa.Column('occurred_at', sa.DateTime(), nullable=True),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['exam_sessions.id']),
        sa.ForeignKeyConstraint(['violation_type_id'], ['violation_types.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'evidences',
        sa.Column('violation_id', sa.UUID(), nullable=True),
        sa.Column('file_path', sa.Text(), nullable=False),
        sa.Column('file_hash', sa.Text(), nullable=False),
        sa.Column('mime_type', sa.String(), nullable=True),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['violation_id'], ['violations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'model_verifications',
        sa.Column('violation_id', sa.UUID(), nullable=False),
        sa.Column('model_name', sa.String(), nullable=False),
        sa.Column('model_version', sa.String(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('verdict', sa.String(), nullable=False),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['violation_id'], ['violations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'risk_snapshots',
        sa.Column('session_id', sa.UUID(), nullable=True),
        sa.Column('trigger_violation_id', sa.UUID(), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['exam_sessions.id']),
        sa.ForeignKeyConstraint(['trigger_violation_id'], ['violations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
