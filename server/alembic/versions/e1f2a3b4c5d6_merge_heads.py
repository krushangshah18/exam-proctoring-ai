"""merge heads

Revision ID: e1f2a3b4c5d6
Revises: d1e2f3a4b5c6, f2a1d2b3c4d5
Create Date: 2026-04-01 00:00:00.000000

"""
from typing import Sequence, Union

revision: str = 'e1f2a3b4c5d6'
down_revision: Union[str, Sequence[str]] = ('d1e2f3a4b5c6', 'f2a1d2b3c4d5')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
