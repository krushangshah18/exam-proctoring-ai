"""
Engine container allocator — simple global slot pool.

There is a shared pool of slots across all active containers (default 3 per container).
Any student on any exam can use any container — the limit is total concurrent sessions,
not per-exam.

pick_any_container() returns the active container URL with the fewest current sessions.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from app.core import log
from app.db import models


class EngineCapacityError(Exception):
    """Raised when all engine containers are full or unreachable."""


def pick_any_container(db: Session) -> Optional[str]:
    """
    Return the active container URL with the fewest current active sessions.
    Returns None if no active containers are configured.
    """
    containers = (
        db.query(models.EngineContainer)
        .filter(models.EngineContainer.is_active == True)
        .all()
    )
    if not containers:
        return None

    best_url: Optional[str] = None
    best_count: int = 999

    for container in containers:
        active_count = (
            db.query(models.ExamSession)
            .filter(
                models.ExamSession.proctor_engine_url == container.url,
                models.ExamSession.status.in_(["CREATED", "ACTIVE", "DISCONNECTED"]),
            )
            .count()
        )
        if active_count < best_count:
            best_count = active_count
            best_url = container.url

    return best_url
