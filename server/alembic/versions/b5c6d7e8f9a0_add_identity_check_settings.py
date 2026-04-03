"""add identity check settings to engine_settings

Revision ID: b5c6d7e8f9a0
Revises: a408ac074e9f
Create Date: 2026-04-03 00:00:00.000000

Adds identity_check_count, identity_check_retries, identity_check_retry_delay
to engine_settings for configurable in-exam identity verification.
"""

from alembic import op
import sqlalchemy as sa

revision = 'b5c6d7e8f9a0'
down_revision = ('4a5b6c7d8e9f', 'a408ac074e9f')
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('engine_settings', sa.Column('identity_check_count',       sa.Integer(), nullable=False, server_default='5'))
    op.add_column('engine_settings', sa.Column('identity_check_retries',     sa.Integer(), nullable=False, server_default='3'))
    op.add_column('engine_settings', sa.Column('identity_check_retry_delay', sa.Float(),   nullable=False, server_default='5.0'))


def downgrade() -> None:
    op.drop_column('engine_settings', 'identity_check_retry_delay')
    op.drop_column('engine_settings', 'identity_check_retries')
    op.drop_column('engine_settings', 'identity_check_count')
