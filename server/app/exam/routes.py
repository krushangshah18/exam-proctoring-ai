# app/exam/routes.py

import asyncio
import json
from datetime import datetime, UTC, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel

from app.db import models, get_db
from app.db.enums import SessionStatus, ResumeStatus, LateJoinPolicy, ExamStatus
from app.core import log, validate_single_face, generate_embedding, verify_same_person
from app.auth.dependencies import get_current_user
from app.exam.exam_guard import exam_guard
from app.exam.events import get_queue, remove_queue


router = APIRouter(prefix="/exam", tags=["Exam"])


# =====================================================
# STUDENT EXAM DASHBOARD & GATES
# =====================================================

@router.get("/upcoming")
def get_upcoming_exams(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Fetch upcoming exams assigned to the student that they have NOT yet submitted.
    Excludes exams where:
      - invite.used is True, OR
      - the student already has an ENDED session (covers browser-close before /exam/end)
    """
    # Subquery: exam IDs where this student already has an ENDED session
    ended_exam_ids = (
        db.query(models.ExamSession.exam_id)
        .filter(
            models.ExamSession.user_id == current_user.id,
            models.ExamSession.status == SessionStatus.ENDED.value,
        )
        .subquery()
    )

    invites = (
        db.query(models.ExamInvite, models.Exam)
        .join(models.Exam, models.Exam.id == models.ExamInvite.exam_id)
        .filter(
            func.lower(models.ExamInvite.student_email) == func.lower(current_user.email),
            models.ExamInvite.used == False,
            models.Exam.status.in_([ExamStatus.SCHEDULED.value, ExamStatus.LIVE.value]),
            models.Exam.is_deleted == False,
            ~models.Exam.id.in_(ended_exam_ids),
        )
        .order_by(models.Exam.start_window.asc())
        .all()
    )

    result = []
    for invite, exam in invites:
        result.append({
            "id": str(exam.id),
            "title": exam.title,
            "exam_mode": exam.exam_mode,
            "start_window": exam.start_window,
            "end_window": exam.end_window,
            "duration_minutes": exam.duration_minutes,
            "hard_join_deadline": exam.hard_join_deadline,
            "status": exam.status
        })

    return result


@router.get("/history")
def get_exam_history(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Return all past exams for the student:
    - Exams where the invite is used (submitted), OR
    - Exams that have ENDED/CANCELLED, OR
    - Exams where the student has a ENDED/TERMINATED session
    Ordered newest first.
    """
    # Get all invites for this student
    invites = (
        db.query(models.ExamInvite, models.Exam)
        .join(models.Exam, models.Exam.id == models.ExamInvite.exam_id)
        .filter(
            func.lower(models.ExamInvite.student_email) == func.lower(current_user.email),
            models.Exam.is_deleted == False,
        )
        .order_by(models.Exam.start_window.desc())
        .all()
    )

    result = []
    for invite, exam in invites:
        # Find session for this exam
        session = db.query(models.ExamSession).filter(
            models.ExamSession.user_id == current_user.id,
            models.ExamSession.exam_id == exam.id,
        ).first()

        session_status = session.status if session else None
        is_history = (
            invite.used
            or exam.status in (ExamStatus.ENDED.value, ExamStatus.CANCELLED.value)
            or session_status in (SessionStatus.ENDED.value, SessionStatus.TERMINATED.value)
        )

        if not is_history:
            continue

        # Compute duration taken
        duration_taken_seconds = None
        if session and session.start_time and session.end_time:
            start = session.start_time.replace(tzinfo=UTC) if session.start_time.tzinfo is None else session.start_time
            end = session.end_time.replace(tzinfo=UTC) if session.end_time.tzinfo is None else session.end_time
            duration_taken_seconds = int((end - start).total_seconds())

        violation_count = 0
        if session:
            violation_count = db.query(models.Violation).filter(
                models.Violation.session_id == session.id
            ).count()

        result.append({
            "id": str(exam.id),
            "title": exam.title,
            "exam_mode": exam.exam_mode,
            "exam_status": exam.status,
            "start_window": exam.start_window,
            "end_window": exam.end_window,
            "duration_minutes": exam.duration_minutes,
            "invite_used": invite.used,
            "session_status": session_status,
            "session_start_time": session.start_time if session else None,
            "session_end_time": session.end_time if session else None,
            "duration_taken_seconds": duration_taken_seconds,
            "risk_score": session.risk_score if session else 0,
            "violation_count": violation_count,
            "time_extension_seconds": session.time_extension_seconds if session else 0,
            "terminated_reason": session.terminated_reason if session else None,
        })

    return result


@router.get("/{exam_id}/status")
def get_exam_status(
    exam_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Fetch exam info and gateway state."""
    exam = db.query(models.Exam).filter(models.Exam.id == exam_id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    invite = db.query(models.ExamInvite).filter(
        models.ExamInvite.exam_id == exam_id,
        func.lower(models.ExamInvite.student_email) == func.lower(current_user.email)
    ).first()

    if not invite:
        raise HTTPException(status_code=403, detail="You are not invited to this exam")

    now = datetime.now(UTC)
    start_time = exam.start_window.replace(tzinfo=UTC) if exam.start_window.tzinfo is None else exam.start_window
    hard_deadline = (
        exam.hard_join_deadline.replace(tzinfo=UTC)
        if exam.hard_join_deadline and exam.hard_join_deadline.tzinfo is None
        else exam.hard_join_deadline
    )

    is_late = bool(hard_deadline and now > hard_deadline)

    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id
    ).first()

    session_status = session.status if session else None

    active_resume_request = None
    if session:
        rr = (
            db.query(models.ResumeRequest)
            .filter(models.ResumeRequest.session_id == session.id)
            .order_by(models.ResumeRequest.created_at.desc())
            .first()
        )
        if rr:
            active_resume_request = {
                "status": rr.status,
                "reason": rr.reason,
                "review_note": rr.review_note,
                "time_extension_minutes": rr.time_extension_minutes,
            }

    allowed_to_enter = start_time <= now + timedelta(minutes=15)
    time_until_open_ms = max(0, int((start_time - timedelta(minutes=15) - now).total_seconds() * 1000))
    allowed_to_start = start_time <= now

    return {
        "id": str(exam.id),
        "title": exam.title,
        "exam_mode": exam.exam_mode,
        "duration_minutes": exam.duration_minutes,
        "start_window": exam.start_window,
        "end_window": exam.end_window,
        "hard_join_deadline": exam.hard_join_deadline,
        "late_join_policy": exam.late_join_policy,
        "flag_threshold": exam.flag_threshold,
        "allow_late_extension": exam.allow_late_extension,
        "max_late_minutes": exam.max_late_minutes,
        "is_late": is_late,
        "session_status": session_status,
        "active_resume_request": active_resume_request,
        "allowed_to_enter": allowed_to_enter,
        "allowed_to_start": allowed_to_start,
        "time_until_open_ms": time_until_open_ms,
        "config": exam.config
    }


@router.get("/{exam_id}/session-active")
def get_session_active(
    exam_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Returns the authoritative session state for the active exam page.
    Used to compute a server-anchored timer on mount/reconnect.
    """
    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="No session found for this exam")

    exam = db.query(models.Exam).filter(models.Exam.id == exam_id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    # Latest resume request
    latest_rr = (
        db.query(models.ResumeRequest)
        .filter(models.ResumeRequest.session_id == session.id)
        .order_by(models.ResumeRequest.created_at.desc())
        .first()
    )

    return {
        "session_id": str(session.id),
        "status": session.status,
        "start_time": session.start_time,
        "end_time": session.end_time,
        "duration_minutes": exam.duration_minutes,
        "time_extension_seconds": session.time_extension_seconds or 0,
        "terminated_reason": session.terminated_reason,
        "terminated_by": session.terminated_by,
        "server_now": datetime.now(UTC).isoformat(),
        "active_resume_request": {
            "status": latest_rr.status,
            "reason": latest_rr.reason,
            "review_note": latest_rr.review_note,
            "time_extension_minutes": latest_rr.time_extension_minutes,
        } if latest_rr else None,
    }


@router.get("/{exam_id}/session-summary")
def get_session_summary(
    exam_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Returns session summary for the completion page."""
    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="No session found")

    exam = db.query(models.Exam).filter(models.Exam.id == exam_id).first()

    # Compute duration taken
    duration_taken_seconds = None
    if session.start_time and session.end_time:
        start = session.start_time.replace(tzinfo=UTC) if session.start_time.tzinfo is None else session.start_time
        end = session.end_time.replace(tzinfo=UTC) if session.end_time.tzinfo is None else session.end_time
        duration_taken_seconds = int((end - start).total_seconds())

    # Violation count
    violation_count = db.query(models.Violation).filter(
        models.Violation.session_id == session.id
    ).count()

    return {
        "session_id": str(session.id),
        "status": session.status,
        "start_time": session.start_time,
        "end_time": session.end_time,
        "duration_taken_seconds": duration_taken_seconds,
        "duration_minutes": exam.duration_minutes if exam else None,
        "time_extension_seconds": session.time_extension_seconds or 0,
        "risk_score": session.risk_score or 0,
        "violation_count": violation_count,
        "terminated_reason": session.terminated_reason,
    }


# =====================================================
# SSE — REAL-TIME EXAM EVENTS
# =====================================================

@router.get("/{exam_id}/events")
async def session_events(
    exam_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Server-Sent Events stream for the active exam page.
    Pushes: RESUME_APPROVED | RESUME_DENIED | TIME_EXTENDED | TERMINATED | ping
    Client connects with fetch + ReadableStream (not EventSource) so it can
    send an Authorization header.
    """
    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
    ).first()

    if not session:
        raise HTTPException(status_code=404, detail="No session found for this exam")

    session_id = str(session.id)

    async def event_generator():
        queue = get_queue(session_id)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=25)
                    payload = json.dumps(event["data"])
                    yield f"event: {event['type']}\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive ping
                    yield "event: ping\ndata: {}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            remove_queue(session_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# =====================================================
# STUDENT EXAM GATES — LOCK SESSION
# =====================================================

@router.post("/{exam_id}/lock-session")
def lock_concurrent_sessions(
    exam_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Lock the session to the current device.
    Returns 409 if another device has an ACTIVE exam session.
    """
    current_fingerprint = request.state.device_id

    if not current_fingerprint:
        raise HTTPException(status_code=401, detail="Device not identified")

    # Block Device B if Device A has an ACTIVE exam session on a different device
    active_on_other = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
        models.ExamSession.status == SessionStatus.ACTIVE.value,
        models.ExamSession.device_fingerprint != current_fingerprint,
    ).first()

    if active_on_other:
        raise HTTPException(
            status_code=409,
            detail="This exam is already active on another device. Please use that device or wait for the session to disconnect."
        )

    # Revoke all other refresh tokens for this user
    other_tokens = db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id == current_user.id,
        models.RefreshToken.device_fingerprint != current_fingerprint,
        models.RefreshToken.revoked == False
    ).all()
    for token in other_tokens:
        token.revoked = True

    # Revoke all other devices
    other_devices = db.query(models.UserDevice).filter(
        models.UserDevice.user_id == current_user.id,
        models.UserDevice.fingerprint != current_fingerprint,
        models.UserDevice.revoked == False
    ).all()
    for device in other_devices:
        device.revoked = True

    db.commit()

    log.info(
        "Student %s locked session for exam %s. Revoked %d tokens and %d devices.",
        current_user.id, exam_id, len(other_tokens), len(other_devices)
    )

    return {"message": "All other sessions locked successfully"}


# =====================================================
# ENVIRONMENT CHECKS: FACE VERIFICATION
# =====================================================

@router.post("/{exam_id}/verify-face")
async def verify_exam_face(
    exam_id: str,
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Verify student identity against stored face embedding."""
    if not current_user.face_embedding:
        raise HTTPException(status_code=400, detail="User profile lacks a face embedding to compare against.")

    try:
        data = await image.read()
        if not data:
            raise HTTPException(status_code=400, detail="Empty image file received.")

        face_box = validate_single_face(data)
        new_embedding = generate_embedding(data, face_box)
        is_same = verify_same_person(current_user.face_embedding, new_embedding)

        if not is_same:
            return {"verified": False, "message": "Face does not match profile"}

        return {"verified": True, "message": "Identity confirmed"}

    except ValueError as e:
        log.exception("Face verification failed for user %s: %s", current_user.id, e)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception("Face verification error for user %s: %s", current_user.id, e)
        raise HTTPException(status_code=500, detail="Internal server error during face verification.")


# =====================================================
# APPEALS & RESUME REQUESTS
# =====================================================

class AppealRequest(BaseModel):
    reason: str


@router.post("/{exam_id}/appeal")
def submit_appeal(
    exam_id: str,
    data: AppealRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Submit a justification/appeal for Late Join or Termination."""
    exam = db.query(models.Exam).filter(models.Exam.id == exam_id).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id
    ).first()

    if not session:
        # Create a placeholder session for late-join scenario
        session = models.ExamSession(
            user_id=current_user.id,
            exam_id=exam.id,
            status=SessionStatus.CREATED.value,
            device_fingerprint="PENDING_DEVICE",
            ip_address="0.0.0.0"
        )
        db.add(session)
        db.commit()
        db.refresh(session)
    else:
        if session.status == SessionStatus.ACTIVE.value:
            raise HTTPException(status_code=400, detail="Cannot appeal while session is active")

    existing_rr = db.query(models.ResumeRequest).filter(
        models.ResumeRequest.session_id == session.id,
        models.ResumeRequest.status == ResumeStatus.PENDING.value
    ).first()

    if existing_rr:
        raise HTTPException(status_code=400, detail="An appeal is already pending.")

    rr = models.ResumeRequest(
        session_id=session.id,
        reason=data.reason,
        status=ResumeStatus.PENDING.value
    )
    db.add(rr)
    db.commit()

    log.info("Appeal filed by %s for session %s.", current_user.id, session.id)

    return {"message": "Appeal submitted successfully", "status": "PENDING"}


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
    """Start exam and bind device. Handles reconnection from DISCONNECTED state."""

    active = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id
    ).first()

    if active:
        if active.status == SessionStatus.ACTIVE.value:
            raise HTTPException(status_code=400, detail="You already have an active exam")
        if active.status == SessionStatus.ENDED.value:
            raise HTTPException(status_code=403, detail="You have already submitted this exam.")

    exam = db.query(models.Exam).filter(
        models.Exam.id == exam_id,
        models.Exam.is_deleted == False,
    ).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    if exam.status not in (ExamStatus.SCHEDULED.value, ExamStatus.LIVE.value):
        raise HTTPException(
            status_code=403,
            detail=f"This exam is not currently available (status: {exam.status})."
        )

    now = datetime.now(UTC)
    start_time = (
        exam.start_window.replace(tzinfo=UTC)
        if exam.start_window.tzinfo is None
        else exam.start_window
    )
    hard_deadline = (
        exam.hard_join_deadline.replace(tzinfo=UTC)
        if exam.hard_join_deadline and exam.hard_join_deadline.tzinfo is None
        else exam.hard_join_deadline
    )

    # Reconnecting from DISCONNECTED — skip late/appeal checks (session already valid)
    is_reconnect = active and active.status == SessionStatus.DISCONNECTED.value

    if not is_reconnect:
        is_late = hard_deadline and now > hard_deadline and (
            not active or active.status == SessionStatus.CREATED.value
        )

        if is_late:
            if exam.allow_late_extension and exam.max_late_minutes and exam.max_late_minutes > 0:
                max_cutoff = start_time + timedelta(minutes=exam.max_late_minutes)
                if now > max_cutoff:
                    raise HTTPException(
                        status_code=403,
                        detail=f"The maximum late join window ({exam.max_late_minutes} minutes past exam start) has passed.",
                    )

            if exam.late_join_policy == LateJoinPolicy.DENY.value:
                raise HTTPException(status_code=403, detail="Hard deadline passed. Late joins are not permitted.")
            elif exam.late_join_policy == LateJoinPolicy.REVIEW.value:
                if not active:
                    raise HTTPException(status_code=403, detail="Late join requires an approved appeal.")
                rr = db.query(models.ResumeRequest).filter(
                    models.ResumeRequest.session_id == active.id,
                    models.ResumeRequest.status == ResumeStatus.APPROVED.value,
                ).first()
                if not rr:
                    raise HTTPException(status_code=403, detail="Your late join appeal has not been approved yet.")

        # Resume from termination
        if active and active.status == SessionStatus.TERMINATED.value:
            rr = db.query(models.ResumeRequest).filter(
                models.ResumeRequest.session_id == active.id,
                models.ResumeRequest.status == ResumeStatus.APPROVED.value
            ).first()
            if not rr:
                raise HTTPException(status_code=403, detail="Your termination appeal has not been approved yet.")

    # Device checks
    device_fp = request.state.device_id
    if not device_fp:
        raise HTTPException(status_code=401, detail="Device not authenticated")

    device = db.query(models.UserDevice).filter(
        models.UserDevice.user_id == current_user.id,
        models.UserDevice.fingerprint == device_fp,
        models.UserDevice.revoked == False,
        models.UserDevice.trusted == True
    ).first()

    if not device:
        raise HTTPException(status_code=403, detail="Untrusted device. Verify first.")

    # Create or reactivate session
    if active:
        session = active
        session.status = SessionStatus.ACTIVE.value
        session.device_fingerprint = device_fp
        session.ip_address = request.client.host
        session.user_agent = request.headers.get("user-agent")
        if not session.start_time:
            session.start_time = datetime.now(UTC)
    else:
        session = models.ExamSession(
            user_id=current_user.id,
            exam_id=exam_id,
            status=SessionStatus.ACTIVE.value,
            start_time=datetime.now(UTC),
            device_fingerprint=device_fp,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent"),
        )
        db.add(session)

    db.commit()
    db.refresh(session)

    log.info(
        "Exam started/resumed user=%s exam=%s device=%s reconnect=%s",
        current_user.id, exam_id, device_fp, is_reconnect
    )

    return {
        "message": "Exam started",
        "session_id": str(session.id),
        "is_reconnect": is_reconnect,
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
    log.info("Answer submitted session=%s user=%s", session.id, session.user_id)
    return {"message": "Answer submitted", "session_id": str(session.id)}


# =====================================================
# HEARTBEAT (KEEP SESSION ALIVE)
# =====================================================

@router.post("/heartbeat")
def heartbeat(
    request: Request,
    session=Depends(exam_guard),
    db: Session = Depends(get_db),
):
    """Keep exam session alive and check if it has been terminated."""
    if session.status == SessionStatus.TERMINATED.value:
        return {
            "status": "terminated",
            "terminated_reason": session.terminated_reason,
            "terminated_by": session.terminated_by,
            "session_id": str(session.id)
        }

    session.last_heartbeat = datetime.now(UTC)
    db.commit()

    return {"status": "alive", "session_id": str(session.id)}


# =====================================================
# END EXAM
# =====================================================

@router.post("/end")
def end_exam(
    request: Request,
    session=Depends(exam_guard),
    db: Session = Depends(get_db),
):
    """End active exam."""
    session.status = SessionStatus.ENDED.value
    session.end_time = datetime.now(UTC)

    invite = db.query(models.ExamInvite).filter(
        func.lower(models.ExamInvite.student_email) == session.user.email.lower(),
        models.ExamInvite.exam_id == session.exam_id,
    ).first()
    if invite:
        invite.used = True

    db.commit()

    log.info("Exam ended session=%s user=%s", session.id, session.user_id)

    return {"message": "Exam ended", "session_id": str(session.id)}
