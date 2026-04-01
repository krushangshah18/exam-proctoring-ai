"""add ec2 management fields to engine_containers

Revision ID: f2b3c4d5e6f7
Revises: e1f2a3b4c5d6
Create Date: 2026-04-01 00:00:00.000000

Adds ec2_instance_id, ec2_region, container_name, container_port to
engine_containers so the backend can start/stop/restart EC2 instances
and individual Docker containers via boto3 + SSM.
"""

from alembic import op
import sqlalchemy as sa

revision = 'f2b3c4d5e6f7'
down_revision = 'e1f2a3b4c5d6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('engine_containers', sa.Column('ec2_instance_id', sa.String(), nullable=True))
    op.add_column('engine_containers', sa.Column('ec2_region', sa.String(), nullable=True))
    op.add_column('engine_containers', sa.Column('container_name', sa.String(), nullable=True))
    op.add_column('engine_containers', sa.Column('container_port', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('engine_containers', 'container_port')
    op.drop_column('engine_containers', 'container_name')
    op.drop_column('engine_containers', 'ec2_region')
    op.drop_column('engine_containers', 'ec2_instance_id')
