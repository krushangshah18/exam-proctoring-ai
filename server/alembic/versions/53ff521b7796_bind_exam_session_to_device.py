"""bind exam session to device

Revision ID: 53ff521b7796
Revises: a0aca29c21e8
Create Date: 2026-02-11 14:33:01.046860

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '53ff521b7796'
down_revision: Union[str, Sequence[str], None] = 'a0aca29c21e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
