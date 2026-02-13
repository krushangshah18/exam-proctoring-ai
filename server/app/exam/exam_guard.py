# app/core/exam_guard.py

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.session import get_db
from app.auth.dependencies import get_current_user
from app.db import models
from app.db.enums import SessionStatus


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
        raise HTTPException(
            status_code=403,
            detail="No active exam session"
        )

    # 4️⃣ Device binding check
    if session.device_fingerprint != device_fp:
        raise HTTPException(
            status_code=403,
            detail="Exam device mismatch"
        )

    # 5️⃣ Session expiry check (optional)
    if session.expires_at and session.expires_at < datetime.utcnow():
        session.status = SessionStatus.ENDED.value
        db.commit()

        raise HTTPException(
            status_code=403,
            detail="Exam session expired"
        )

    # 6️⃣ Store for route usage
    request.state.exam_session = session

    return session
