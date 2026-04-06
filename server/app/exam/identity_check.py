"""
In-exam identity verification.

At exam start (proctor-connect), N random check timestamps are scheduled,
spread evenly across the exam duration (divided into N equal windows with
a 2-minute grace period at each end).

Each check:
  1. Silently grabs a JPEG snapshot from the engine via GET /snapshot/{pc_id}
  2. Runs validate_single_face + generate_embedding + verify_same_person
  3. If the silent check PASSES  → nothing visible to the student
  4. If the silent check FAILS   → push IDENTITY_PROMPT SSE → student sees banner
     → retry up to `retries` times with `retry_delay_s` gap
  5. If ALL retries fail          → set terminated_reason + push TERMINATED SSE

Technical failures (snapshot unavailable, face not detectable) always pass
(benefit of the doubt) — we only terminate on confirmed identity mismatch.
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, UTC

from app.core import log, validate_single_face, generate_embedding, verify_same_person
from app.exam.proctor_proxy import fetch_snapshot

# session_id (str) → running asyncio.Task
_identity_tasks: dict[str, asyncio.Task] = {}

# Grace period at each end of the exam — no checks within first/last 2 minutes
_GRACE_S = 120


def schedule_identity_checks(
    session_id: str,
    user_face_embedding: str,
    start_time: datetime,
    duration_minutes: int,
    extension_seconds: int,
    proctor_engine_url: str,
    proctor_pc_id: str,
    check_count: int,
    retry_count: int,
    retry_delay_s: float,
) -> None:
    """
    Schedule N identity checks spread across the remaining exam time.
    Safe to call on reconnect — cancels any previous task first.

    All timing is relative to NOW so reconnects don't replay past checks.
    """
    # Cancel any existing task for this session (reconnect / appeal resume)
    cancel_identity_checks(session_id)

    total_seconds = duration_minutes * 60 + extension_seconds
    # Normalise start_time to UTC-aware
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=UTC)

    elapsed_s = max(0.0, (datetime.now(UTC) - start_time).total_seconds())
    remaining_s = total_seconds - elapsed_s

    active_zone = remaining_s - _GRACE_S  # leave grace at the end
    if active_zone <= 0 or check_count <= 0:
        log.info("Identity checks skipped (too little time left): session=%s", session_id)
        return

    # Divide the active zone into N equal windows; pick a random point in each.
    # Also skip the grace period at the start (already elapsed is handled by
    # using remaining_s as the reference).
    window = active_zone / check_count
    offsets: list[float] = []
    for i in range(check_count):
        lo = i * window
        hi = (i + 1) * window
        offsets.append(random.uniform(lo, hi))

    offsets.sort()
    log.info(
        "Identity checks scheduled: session=%s count=%d offsets=%s",
        session_id,
        len(offsets),
        [f"{o:.0f}s" for o in offsets],
    )

    task = asyncio.create_task(
        _run_check_loop(
            session_id=session_id,
            user_face_embedding=user_face_embedding,
            offsets=offsets,
            proctor_engine_url=proctor_engine_url,
            proctor_pc_id=proctor_pc_id,
            retry_count=retry_count,
            retry_delay_s=retry_delay_s,
        )
    )
    _identity_tasks[session_id] = task


def cancel_identity_checks(session_id: str) -> None:
    """Cancel the running task for a session (call on submit / terminate / reconnect)."""
    task = _identity_tasks.pop(session_id, None)
    if task and not task.done():
        task.cancel()
        log.info("Identity check task cancelled: session=%s", session_id)


# ── Internal async task ───────────────────────────────────────────────────────

async def _run_check_loop(
    session_id: str,
    user_face_embedding: str,
    offsets: list[float],
    proctor_engine_url: str,
    proctor_pc_id: str,
    retry_count: int,
    retry_delay_s: float,
) -> None:
    try:
        elapsed = 0.0
        for delay in offsets:
            await asyncio.sleep(delay - elapsed)
            elapsed = delay
            terminated = await _perform_single_check(
                session_id=session_id,
                user_face_embedding=user_face_embedding,
                proctor_engine_url=proctor_engine_url,
                proctor_pc_id=proctor_pc_id,
                retry_count=retry_count,
                retry_delay_s=retry_delay_s,
            )
            if terminated:
                return  # Session ended — no more checks
    except asyncio.CancelledError:
        pass
    finally:
        _identity_tasks.pop(session_id, None)


async def _perform_single_check(
    session_id: str,
    user_face_embedding: str,
    proctor_engine_url: str,
    proctor_pc_id: str,
    retry_count: int,
    retry_delay_s: float,
) -> bool:
    """
    Run one verification cycle.
    Returns True if the session was terminated, False otherwise.
    """
    from app.exam.events import push_event

    # ── Step 1: silent check ─────────────────────────────────────────────────
    matched = await _check_face(proctor_engine_url, proctor_pc_id, user_face_embedding)
    if matched:
        log.debug("Identity check passed silently: session=%s", session_id)
        return False

    log.info("Identity check FAILED (silent attempt): session=%s — prompting student", session_id)

    # ── Step 2: notify student and retry ────────────────────────────────────
    await push_event(session_id, "IDENTITY_PROMPT", {
        "type": "IDENTITY_PROMPT",
        "message": "Please look directly into the camera for a quick verification.",
    })

    for attempt in range(retry_count):
        await asyncio.sleep(retry_delay_s)
        matched = await _check_face(proctor_engine_url, proctor_pc_id, user_face_embedding)
        if matched:
            log.info(
                "Identity check recovered on retry %d/%d: session=%s",
                attempt + 1, retry_count, session_id,
            )
            await push_event(session_id, "IDENTITY_PROMPT_CLEAR", {
                "type": "IDENTITY_PROMPT_CLEAR",
            })
            return False

    # ── Step 3: all retries exhausted — terminate ────────────────────────────
    log.warning(
        "Identity check TERMINATED (all %d retries failed): session=%s",
        retry_count, session_id,
    )
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _terminate_session_db, session_id)
    await push_event(session_id, "TERMINATED", {
        "type": "TERMINATED",
        "reason": "identity_mismatch",
        "message": "Session terminated: identity could not be verified.",
    })
    return True


async def _check_face(
    engine_url: str,
    pc_id: str,
    stored_embedding: str,
) -> bool:
    """
    Fetch snapshot → extract face → compare embedding.

    Returns True  (pass) when:
      - Snapshot unavailable (engine error)        → benefit of the doubt
      - Face not detectable / multiple faces       → benefit of the doubt
      - Embeddings match (cosine > 0.6, dist < 0.81)

    Returns False (fail) only when a clear, usable face does NOT match.
    """
    try:
        jpeg_bytes = await fetch_snapshot(engine_url, pc_id)
    except Exception as exc:
        log.warning("Identity check: snapshot unavailable (pc_id=%s): %s", pc_id, exc)
        return True  # Benefit of the doubt — engine or network hiccup

    loop = asyncio.get_running_loop()
    try:
        face_box = await loop.run_in_executor(None, validate_single_face, jpeg_bytes)
        new_embedding = await loop.run_in_executor(None, generate_embedding, jpeg_bytes, face_box)
        return verify_same_person(stored_embedding, new_embedding)
    except ValueError as exc:
        # validate_single_face raises ValueError when 0 or >1 faces found
        log.info("Identity check: face not usable (pc_id=%s): %s", pc_id, exc)
        return True  # Benefit of the doubt — don't penalise for lighting / angle
    except Exception as exc:
        log.warning("Identity check: unexpected comparison error (pc_id=%s): %s", pc_id, exc)
        return True  # Benefit of the doubt


def _terminate_session_db(session_id: str) -> None:
    """Write TERMINATED status to DB from an async context via a sync DB call."""
    from app.db.session import SessionLocal
    from app.db import models
    from app.db.enums import SessionStatus

    try:
        db = SessionLocal()
        try:
            session = db.query(models.ExamSession).filter(
                models.ExamSession.id == session_id
            ).first()
            if session and session.status not in (
                SessionStatus.TERMINATED.value,
                SessionStatus.ENDED.value,
            ):
                session.status = SessionStatus.TERMINATED.value
                session.terminated_reason = "Identity verification failed after repeated attempts"
                db.commit()
                log.info("Identity check: session=%s marked TERMINATED in DB", session_id)
        finally:
            db.close()
    except Exception as exc:
        log.error("Identity check: DB termination failed session=%s: %s", session_id, exc)
