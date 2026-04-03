"""add object vote settings to engine_settings

Revision ID: c2d3e4f5a6b7
Revises: b5c6d7e8f9a0
Create Date: 2026-04-03 00:00:00.000000

Adds phone_min_votes, book_min_votes, headphone_min_votes, earbud_min_votes,
object_min_votes, object_window to engine_settings for admin-configurable
object detection temporal vote thresholds.
"""

from alembic import op
import sqlalchemy as sa

revision = 'c2d3e4f5a6b7'
down_revision = 'b5c6d7e8f9a0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('engine_settings', sa.Column('phone_min_votes',     sa.Integer(), nullable=False, server_default='9'))
    op.add_column('engine_settings', sa.Column('book_min_votes',      sa.Integer(), nullable=False, server_default='10'))
    op.add_column('engine_settings', sa.Column('headphone_min_votes', sa.Integer(), nullable=False, server_default='9'))
    op.add_column('engine_settings', sa.Column('earbud_min_votes',    sa.Integer(), nullable=False, server_default='9'))
    op.add_column('engine_settings', sa.Column('object_min_votes',    sa.Integer(), nullable=False, server_default='5'))
    op.add_column('engine_settings', sa.Column('object_window',       sa.Integer(), nullable=False, server_default='15'))


def downgrade() -> None:
    op.drop_column('engine_settings', 'object_window')
    op.drop_column('engine_settings', 'object_min_votes')
    op.drop_column('engine_settings', 'earbud_min_votes')
    op.drop_column('engine_settings', 'headphone_min_votes')
    op.drop_column('engine_settings', 'book_min_votes')
    op.drop_column('engine_settings', 'phone_min_votes')
