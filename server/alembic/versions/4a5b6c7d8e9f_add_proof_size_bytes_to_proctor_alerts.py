"""add proof_size_bytes to proctor_alerts

Revision ID: 4a5b6c7d8e9f
Revises: d1e2f3a4b5c6
Create Date: 2026-04-03 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "4a5b6c7d8e9f"
down_revision: Union[str, Sequence[str], None] = "d1e2f3a4b5c6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "proctor_alerts",
        sa.Column("proof_size_bytes", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("proctor_alerts", "proof_size_bytes")
