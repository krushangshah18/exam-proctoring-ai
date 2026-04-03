# app/core/exam_guard.py

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, UTC

from app.db.session import get_db
from app.auth.dependencies import get_current_user
from app.db import models
from app.db.enums import SessionStatus
from app.core import log


def exam_guard(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """
    Protect exam endpoints
    """

    # 1️⃣ Get device from JWT
    device_fp = request.state.device_id

    if not device_fp:
        log.warning(
            "exam_guard: missing device fingerprint user_id=%s client_ip=%s",
            getattr(user, "id", None),
            getattr(request.client, "host", None),
        )
        raise HTTPException(
            status_code=401,
            detail="Device not authenticated"
        )

    # 2️⃣ Check device exists & trusted
    device = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == user.id,
            models.UserDevice.fingerprint == device_fp,
            models.UserDevice.revoked == False,
            models.UserDevice.trusted == True
        )
        .first()
    )

    if not device:
        log.warning(
            "exam_guard: untrusted device (fingerprint=%s user_id=%s)",
            device_fp,
            user.id,
        )
        raise HTTPException(
            status_code=403,
            detail="Untrusted device"
        )

    # 3️⃣ Check active exam session
    session = (
        db.query(models.ExamSession)
        .filter(
            models.ExamSession.user_id == user.id,
            models.ExamSession.status == SessionStatus.ACTIVE.value
        )
        .first()
    )

    if not session:
        log.warning(
            "exam_guard: no active exam session (user_id=%s)",
            user.id,
        )
        raise HTTPException(
            status_code=403,
            detail="No active exam session"
        )

    # 4️⃣ Device binding check
    if session.device_fingerprint != device_fp:
        log.warning(
            "exam_guard: device mismatch (user_id=%s session_id=%s expected=%s got=%s)",
            user.id,
            session.id,
            session.device_fingerprint,
            device_fp,
        )
        raise HTTPException(
            status_code=403,
            detail="Exam device mismatch"
        )

    # 5️⃣ Session expiry check — use personal deadline, not exam.end_window.
    # Admin-granted time extensions (time_extension_seconds) allow a student to
    # continue past the exam's end_window, so we compute the personal deadline as:
    #   start_time + duration_minutes + time_extension_seconds
    if session.start_time:
        from datetime import timedelta
        start = session.start_time.replace(tzinfo=UTC) if session.start_time.tzinfo is None else session.start_time
        personal_deadline = (
            start
            + timedelta(minutes=session.exam.duration_minutes)
            + timedelta(seconds=session.time_extension_seconds or 0)
        )
        if personal_deadline < datetime.now(UTC):
            session.status = SessionStatus.ENDED.value
            try:
                db.commit()
            except Exception as e:
                log.exception(
                    "exam_guard: failed to mark session ENDED on expiry (session_id=%s user_id=%s): %s",
                    session.id,
                    user.id,
                    e,
                )
                db.rollback()
            raise HTTPException(
                status_code=403,
                detail="Exam session expired"
            )

    # 6️⃣ Store for route usage
    request.state.exam_session = session

    return session
