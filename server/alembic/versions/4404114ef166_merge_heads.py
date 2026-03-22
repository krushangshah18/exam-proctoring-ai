"""merge_heads

Revision ID: 4404114ef166
Revises: 15aed84e2a0f, 5f534be479bc
Create Date: 2026-02-14 00:42:44.819399

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4404114ef166'
down_revision: Union[str, Sequence[str], None] = ('15aed84e2a0f', '5f534be479bc')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
