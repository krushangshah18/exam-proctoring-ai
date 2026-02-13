# app/exam/routes.py

from datetime import datetime, UTC

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import models, get_db
from app.db.enums import SessionStatus

from app.core import log
from app.auth.dependencies import get_current_user
from app.exam.exam_guard import exam_guard


router = APIRouter(prefix="/exam", tags=["Exam"])


# =====================================================
# START EXAM
# =====================================================

@router.post("/start/{exam_id}")
def start_exam(
    exam_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Start exam and bind device
    """

    # ---------------- Check Existing Session ----------------

    active = (
        db.query(models.ExamSession)
        .filter(
            models.ExamSession.user_id == current_user.id,
            models.ExamSession.status == SessionStatus.ACTIVE.value,
        )
        .first()
    )

    if active:
        raise HTTPException(
            status_code=400,
            detail="You already have an active exam"
        )

    # ---------------- Get Device ----------------

    device_fp = request.state.device_id

    if not device_fp:
        raise HTTPException(
            status_code=401,
            detail="Device not authenticated"
        )

    # ---------------- Verify Trusted Device ----------------

    device = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == current_user.id,
            models.UserDevice.fingerprint == device_fp,
            models.UserDevice.revoked == False,
            models.UserDevice.trusted == True
        )
        .first()
    )

    if not device:
        raise HTTPException(
            status_code=403,
            detail="Untrusted device. Verify first."
        )

    # ---------------- Create Session ----------------

    session = models.ExamSession(
        user_id=current_user.id,
        exam_id=exam_id,

        status=SessionStatus.ACTIVE.value,
        started_at=datetime.now(UTC),

        device_fingerprint=device_fp,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )

    db.add(session)
    db.commit()
    db.refresh(session)

    log.info(
        "Exam started user=%s exam=%s device=%s",
        current_user.id,
        exam_id,
        device_fp
    )

    return {
        "message": "Exam started",
        "session_id": str(session.id)
    }


# =====================================================
# SUBMIT ANSWER (PROTECTED)
# =====================================================

@router.post("/submit")
def submit_answer(
    request: Request,
    session=Depends(exam_guard),
    db: Session = Depends(get_db),
):
    """
    Submit answer (protected by exam guard)
    """

    # session already verified by middleware

    log.info(
        "Answer submitted session=%s user=%s",
        session.id,
        session.user_id
    )

    return {
        "message": "Answer submitted",
        "session_id": str(session.id)
    }


# =====================================================
# HEARTBEAT (KEEP SESSION ALIVE)
# =====================================================

@router.post("/heartbeat")
def heartbeat(
    request: Request,
    session=Depends(exam_guard),
    db: Session = Depends(get_db),
):
    """
    Keep exam session alive
    """

    session.last_seen = datetime.now(UTC)
    db.commit()

    return {
        "status": "alive",
        "session_id": str(session.id)
    }


# =====================================================
# END EXAM
# =====================================================

@router.post("/end")
def end_exam(
    request: Request,
    session=Depends(exam_guard),
    db: Session = Depends(get_db),
):
    """
    End active exam
    """

    session.status = SessionStatus.ENDED.value
    session.ended_at = datetime.now(UTC)

    db.commit()

    log.info(
        "Exam ended session=%s user=%s",
        session.id,
        session.user_id
    )

    return {
        "message": "Exam ended",
        "session_id": str(session.id)
    }
