"""add proctor_alerts and proctor_warnings tables

Revision ID: d1e2f3a4b5c6
Revises: c1d2e3f4a5b6
Create Date: 2026-04-01 00:00:00.000000

Adds:
  - proctor_alerts   (engine writes one row per alert event directly to RDS)
  - proctor_warnings (engine writes one row per warning event directly to RDS)

These tables replace the pattern of polling the engine's
/session/{pc_id}/log and /report/{id} HTTP endpoints for historical data.
The engine writes to these tables at the moment each event fires, so data
persists even if the engine EC2 instance is recycled or restarted.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'd1e2f3a4b5c6'
down_revision = 'c1d2e3f4a5b6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'proctor_alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('message', sa.String(), nullable=False),
        sa.Column('alert_key', sa.String(), nullable=True),
        sa.Column('elapsed_s', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('time_str', sa.String(), nullable=True),
        sa.Column('score_added', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('proof_s3_key', sa.String(), nullable=True),
        sa.Column('proof_type', sa.String(), nullable=True),
        sa.Column('occurred_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['session_id'], ['exam_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_proctor_alert_session', 'proctor_alerts', ['session_id'])

    op.create_table(
        'proctor_warnings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('message', sa.String(), nullable=False),
        sa.Column('elapsed_s', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('time_str', sa.String(), nullable=True),
        sa.Column('occurred_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['session_id'], ['exam_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_proctor_warning_session', 'proctor_warnings', ['session_id'])


def downgrade() -> None:
    op.drop_index('idx_proctor_warning_session', table_name='proctor_warnings')
    op.drop_table('proctor_warnings')
    op.drop_index('idx_proctor_alert_session', table_name='proctor_alerts')
    op.drop_table('proctor_alerts')
