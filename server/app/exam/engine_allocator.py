"""
Engine container allocator.

Rules:
  - Total containers: C  (currently 2, port 8000 + 8001)
  - 1 LIVE exam  → gets ALL containers  (6 student slots total)
  - 2 LIVE exams → 1 container each     (3 slots each)
  - 3+ LIVE exams → no capacity, reject

When exam A already holds both containers and exam B goes LIVE:
  - Exam A's assignment is reduced to 1 container (DB row removed)
  - Exam B is assigned the freed container
  - Existing active sessions on exam A are unaffected — their
    proctor_engine_url is already stored in ExamSession and used directly.
    Only routing for *new* student connections changes.

When a LIVE exam ends:
  - Its container assignments are deleted
  - Remaining LIVE exams are rebalanced: if only 1 remains it gets everything

Thread safety: all mutations happen inside a single DB transaction.
The caller holds the DB session.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.core import log
from app.db import models
from app.db.enums import ExamStatus


# ── Public API ────────────────────────────────────────────────────────────────

class EngineCapacityError(Exception):
    """Raised when no engine containers are available to assign."""


def allocate_for_exam(exam_id: uuid.UUID, db: Session) -> list[str]:
    """
    Assign containers to a newly-LIVE exam.
    Returns the list of assigned container URLs.
    Raises EngineCapacityError if no containers are available.
    """
    all_containers = (
        db.query(models.EngineContainer)
        .filter(models.EngineContainer.is_active == True)
        .all()
    )
    if not all_containers:
        raise EngineCapacityError("No engine containers configured.")

    total = len(all_containers)

    # Containers already assigned to other LIVE exams
    assigned_ids = {
        row.container_id
        for row in db.query(models.ExamEngineAssignment).all()
        if row.exam_id != exam_id
    }
    free = [c for c in all_containers if c.id not in assigned_ids]

    if not free:
        # All containers are taken — try to steal one from the exam with the most
        # containers (the "only live exam" that currently owns everything).
        stolen = _steal_one_container(db, exam_id, all_containers, assigned_ids)
        if stolen is None:
            raise EngineCapacityError(
                "All proctoring engine slots are in use. "
                "End an existing live exam before starting a new one."
            )
        free = [stolen]

    # Assign all free containers to this exam
    urls = []
    for container in free:
        assignment = models.ExamEngineAssignment(
            id=uuid.uuid4(),
            exam_id=exam_id,
            container_id=container.id,
        )
        db.add(assignment)
        urls.append(container.url)
        log.info("Container %s assigned to exam %s", container.url, exam_id)

    return urls


def release_for_exam(exam_id: uuid.UUID, db: Session) -> None:
    """
    Release all container assignments for an exam that just ended.
    Then rebalance remaining LIVE exams so a sole survivor gets everything.
    """
    assignments = (
        db.query(models.ExamEngineAssignment)
        .filter(models.ExamEngineAssignment.exam_id == exam_id)
        .all()
    )
    for a in assignments:
        log.info("Container assignment released: exam %s → container %s", exam_id, a.container_id)
        db.delete(a)

    db.flush()   # apply deletes before rebalance query

    _rebalance(db)


def get_container_urls_for_exam(exam_id: uuid.UUID, db: Session) -> list[str]:
    """Return the list of container URLs currently assigned to an exam."""
    rows = (
        db.query(models.ExamEngineAssignment, models.EngineContainer)
        .join(models.EngineContainer,
              models.ExamEngineAssignment.container_id == models.EngineContainer.id)
        .filter(models.ExamEngineAssignment.exam_id == exam_id)
        .all()
    )
    return [container.url for _, container in rows]


def pick_least_loaded_container(exam_id: uuid.UUID, db: Session) -> Optional[str]:
    """
    From the containers assigned to this exam, pick the one with the fewest
    active ExamSessions currently using it.
    Returns None if no containers are assigned.
    """
    rows = (
        db.query(models.ExamEngineAssignment, models.EngineContainer)
        .join(models.EngineContainer,
              models.ExamEngineAssignment.container_id == models.EngineContainer.id)
        .filter(models.ExamEngineAssignment.exam_id == exam_id,
                models.EngineContainer.is_active == True)
        .all()
    )
    if not rows:
        return None

    # Count active sessions on each container URL
    best_url: Optional[str] = None
    best_count: int = 999

    for _, container in rows:
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


# ── Internal helpers ──────────────────────────────────────────────────────────

def _steal_one_container(
    db: Session,
    new_exam_id: uuid.UUID,
    all_containers: list,
    assigned_ids: set,
) -> Optional[models.EngineContainer]:
    """
    Find an exam that holds more than 1 container and take one from it.
    Returns the freed container, or None if no excess exists.
    """
    # Count containers per exam (excluding the new exam itself)
    from collections import Counter
    assignments = (
        db.query(models.ExamEngineAssignment)
        .filter(models.ExamEngineAssignment.exam_id != new_exam_id)
        .all()
    )
    count_by_exam: Counter = Counter(a.exam_id for a in assignments)

    # Find an exam with >1 container
    donor_exam_id = next(
        (eid for eid, cnt in count_by_exam.items() if cnt > 1), None
    )
    if donor_exam_id is None:
        return None

    # Remove the last assignment from the donor exam
    donor_assignment = (
        db.query(models.ExamEngineAssignment)
        .filter(models.ExamEngineAssignment.exam_id == donor_exam_id)
        .order_by(models.ExamEngineAssignment.created_at.desc())
        .first()
    )
    if not donor_assignment:
        return None

    container = db.query(models.EngineContainer).get(donor_assignment.container_id)
    db.delete(donor_assignment)
    log.info(
        "Container %s stolen from exam %s for new exam %s",
        container.url if container else "?", donor_exam_id, new_exam_id,
    )
    return container


def _rebalance(db: Session) -> None:
    """
    After a LIVE exam ends, give all unassigned containers to the sole remaining
    LIVE exam (if there is only one).
    """
    # Find remaining LIVE exams with assignments
    live_exam_ids = {
        row.exam_id
        for row in db.query(models.ExamEngineAssignment).all()
    }
    if len(live_exam_ids) != 1:
        return   # 0 = all done, 2+ = already balanced

    sole_exam_id = next(iter(live_exam_ids))

    # Find containers not yet assigned
    assigned_container_ids = {
        row.container_id
        for row in db.query(models.ExamEngineAssignment).all()
    }
    free_containers = (
        db.query(models.EngineContainer)
        .filter(
            models.EngineContainer.is_active == True,
            ~models.EngineContainer.id.in_(assigned_container_ids),
        )
        .all()
    )
    for container in free_containers:
        assignment = models.ExamEngineAssignment(
            id=uuid.uuid4(),
            exam_id=sole_exam_id,
            container_id=container.id,
        )
        db.add(assignment)
        log.info(
            "Rebalance: container %s reassigned to sole exam %s",
            container.url, sole_exam_id,
        )
