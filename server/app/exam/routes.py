# app/exam/routes.py

import asyncio
import io
import json
import os
import time
from datetime import datetime, UTC, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel

from app.db import models, get_db
from app.db.enums import SessionStatus, ResumeStatus, LateJoinPolicy, ExamStatus
from app.core import log, system_logger, validate_single_face, generate_embedding, verify_same_person
from app.auth.dependencies import get_current_user
from app.exam.exam_guard import exam_guard
from app.exam.events import get_queue, remove_queue

# ── Object detection model (lazy-loaded singleton) ────────────────────────────
_object_model = None

# Rate-limit SSE idle warnings (global across all connections).
_sse_idle_last_warn_at: float = 0.0

def _get_object_model():
    global _object_model
    if _object_model is None:
        from ultralytics import YOLO
        model_path = os.path.join(os.path.dirname(__file__), "..", "..", "finalBestV5.pt")
        model_path = os.path.abspath(model_path)
        _object_model = YOLO(model_path)
    return _object_model

_OBJ_LABELS = {0: "person", 1: "book", 2: "cell phone", 3: "headphone", 4: "earbud"}
_PROHIBITED  = {1, 2, 3, 4}   # everything except person

# Fallback tab-switch counter — used when the engine is not connected so tab
# switches still trigger termination without an engine session.
# Keyed by str(session.id). Reset on termination or session end.
_tab_switch_fallback: dict[str, int] = {}

router = APIRouter(prefix="/exam", tags=["Exam"])


# =====================================================
# RESUME STATE UTILITY
# =====================================================

def get_resume_state(session, db) -> str | None:
    """
    Derive the student's resume/appeal state for a TERMINATED session.

    Returns one of:
      "CAN_APPLY"   — terminated, no appeal filed yet
      "PENDING"     — appeal filed, awaiting admin review
      "APPROVED"    — appeal approved (session should be CREATED, transitional)
      "DENIED"      — appeal denied; no re-entry
      "NOT_APPLIED" — student explicitly dismissed / tab closed
      "AGAIN"       — TERMINATED again after a previous approval; no appeals left
      None          — session not terminated (not relevant)
    """
    if not session or session.status != SessionStatus.TERMINATED.value:
        return None

    latest_rr = (
        db.query(models.ResumeRequest)
        .filter(models.ResumeRequest.session_id == session.id)
        .order_by(models.ResumeRequest.created_at.desc())
        .first()
    )

    if not latest_rr:
        # Check if any sibling session (same user+exam) had an approved appeal.
        # This handles Fix-B: new session created on appeal approval has no RR of
        # its own, but the student has already used their one appeal chance.
        prior_approved = (
            db.query(models.ResumeRequest)
            .join(models.ExamSession, models.ExamSession.id == models.ResumeRequest.session_id)
            .filter(
                models.ExamSession.user_id == session.user_id,
                models.ExamSession.exam_id == session.exam_id,
                models.ExamSession.id != session.id,
                models.ResumeRequest.status == ResumeStatus.APPROVED.value,
            )
            .first()
        )
        return "AGAIN" if prior_approved else "CAN_APPLY"

    status = latest_rr.status
    if status == ResumeStatus.APPROVED.value:
        return "AGAIN"
    if status == ResumeStatus.PENDING.value:
        return "PENDING"
    if status == ResumeStatus.DENIED.value:
        return "DENIED"
    if status == ResumeStatus.NOT_APPLIED.value:
        return "NOT_APPLIED"

    return "CAN_APPLY"


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

    # Batch-load all sessions at once to avoid N+1 queries
    exam_ids = [exam.id for _, exam in invites]
    all_sessions = (
        db.query(models.ExamSession)
        .filter(
            models.ExamSession.user_id == current_user.id,
            models.ExamSession.exam_id.in_(exam_ids),
        )
        .order_by(models.ExamSession.created_at.desc())
        .all()
    )
    # Keep newest session per exam (dict keyed by exam_id str)
    sessions_by_exam: dict = {}
    for s in all_sessions:
        key = str(s.exam_id)
        if key not in sessions_by_exam:
            sessions_by_exam[key] = s

    result = []
    for invite, exam in invites:
        session = sessions_by_exam.get(str(exam.id))

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
    ).order_by(models.ExamSession.created_at.desc()).first()

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
        elif session.status == SessionStatus.CREATED.value:
            # Fix B: new CREATED session (from terminated approval) has no direct RR.
            # Look for an approved appeal on any sibling session for this user+exam.
            cross_rr = (
                db.query(models.ResumeRequest)
                .join(models.ExamSession, models.ExamSession.id == models.ResumeRequest.session_id)
                .filter(
                    models.ExamSession.user_id == current_user.id,
                    models.ExamSession.exam_id == exam_id,
                    models.ResumeRequest.status == ResumeStatus.APPROVED.value,
                )
                .order_by(models.ResumeRequest.created_at.desc())
                .first()
            )
            if cross_rr:
                active_resume_request = {
                    "status": cross_rr.status,
                    "reason": cross_rr.reason,
                    "review_note": cross_rr.review_note,
                    "time_extension_minutes": cross_rr.time_extension_minutes,
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
        "session_terminated_by": session.terminated_by if session else None,
        "session_terminated_reason": session.terminated_reason if session else None,
        "active_resume_request": active_resume_request,
        "allowed_to_enter": allowed_to_enter,
        "allowed_to_start": allowed_to_start,
        "time_until_open_ms": time_until_open_ms,
        "config": exam.config,
        "detection_config": exam.detection_config,
        "resume_state": get_resume_state(session, db),
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
    ).order_by(models.ExamSession.created_at.desc()).first()

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
        "title": exam.title,
        "exam_mode": exam.exam_mode,
        "flag_threshold": exam.flag_threshold,
        "tab_switch_terminate_count": getattr(db.query(models.EngineSettings).first(), "tab_switch_terminate_count", 3),
        "config": exam.config,
        "active_resume_request": {
            "status": latest_rr.status,
            "reason": latest_rr.reason,
            "review_note": latest_rr.review_note,
            "time_extension_minutes": latest_rr.time_extension_minutes,
        } if latest_rr else None,
        "resume_state": get_resume_state(session, db),
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
    ).order_by(models.ExamSession.created_at.desc()).first()

    if not session:
        raise HTTPException(status_code=404, detail="No session found")

    exam = db.query(models.Exam).filter(models.Exam.id == exam_id).first()

    # Compute duration taken
    duration_taken_seconds = None
    if session.start_time and session.end_time:
        start = session.start_time.replace(tzinfo=UTC) if session.start_time.tzinfo is None else session.start_time
        end = session.end_time.replace(tzinfo=UTC) if session.end_time.tzinfo is None else session.end_time
        duration_taken_seconds = int((end - start).total_seconds())

    return {
        "session_id": str(session.id),
        "status": session.status,
        "start_time": session.start_time,
        "end_time": session.end_time,
        "duration_taken_seconds": duration_taken_seconds,
        "duration_minutes": exam.duration_minutes if exam else None,
        "time_extension_seconds": session.time_extension_seconds or 0,
        "risk_score": session.risk_score or 0,
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
    ).order_by(models.ExamSession.created_at.desc()).first()

    if not session:
        raise HTTPException(status_code=404, detail="No session found for this exam")

    session_id = str(session.id)

    async def event_generator():
        queue = get_queue(session_id)
        timeouts_in_row = 0
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=25)
                    payload = json.dumps(event["data"])
                    timeouts_in_row = 0
                    yield f"event: {event['type']}\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive ping
                    timeouts_in_row += 1
                    # If the queue has been idle for a while, emit a single diagnostic
                    # so we can detect stuck event delivery pipelines.
                    if timeouts_in_row == 10:
                        global _sse_idle_last_warn_at
                        now = time.time()
                        if now - _sse_idle_last_warn_at >= 300:
                            _sse_idle_last_warn_at = now
                            system_logger.warning(
                                "session_events idle: no events for ~%ss session_id=%s exam_id=%s",
                                timeouts_in_row * 25,
                                session_id,
                                exam_id,
                            )
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
# ENVIRONMENT CHECKS: OBJECT DETECTION
# =====================================================

@router.post("/{exam_id}/check-objects")
async def check_objects(
    exam_id: str,
    image: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    """
    Run a single YOLO inference pass on the submitted frame.
    Rules:
      - Exactly 1 person must be visible.
      - No prohibited objects (book, cell_phone, headphone, earbud).
    Returns { passed, person_count, detected_objects, issues }
    """
    try:
        data = await image.read()
        if not data:
            raise HTTPException(status_code=400, detail="Empty image received.")

        import numpy as np
        import cv2
        nparr = np.frombuffer(data, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if frame is None:
            raise HTTPException(status_code=400, detail="Could not decode image.")

        model = _get_object_model()
        results = model(frame, verbose=False)[0]

        person_count = 0
        detected_prohibited: list[str] = []

        for box in results.boxes:
            cls_id = int(box.cls[0].item())
            conf   = float(box.conf[0].item())
            if cls_id == 0 and conf >= 0.30:
                person_count += 1
            elif cls_id in _PROHIBITED and conf >= 0.40:
                label = _OBJ_LABELS.get(cls_id, f"object_{cls_id}")
                if label not in detected_prohibited:
                    detected_prohibited.append(label)

        issues: list[str] = []
        if person_count == 0:
            issues.append("No person detected. Please sit in front of the camera.")
        elif person_count > 1:
            issues.append(f"{person_count} people detected. Only 1 person is allowed in the frame.")
        for obj in detected_prohibited:
            issues.append(f"Prohibited item detected: {obj}. Please remove it from view.")

        return {
            "passed": len(issues) == 0,
            "person_count": person_count,
            "detected_objects": detected_prohibited,
            "issues": issues,
        }

    except HTTPException as e:
        # Expected validation failures; keep at debug to avoid log noise.
        log.debug("check_objects re-raising HTTPException status=%s detail=%s", e.status_code, e.detail)
        raise
    except Exception as e:
        log.exception("Object check failed for user %s: %s", current_user.id, e)
        raise HTTPException(status_code=500, detail="Object detection failed.")


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
    ).order_by(models.ExamSession.created_at.desc()).first()

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
        # Type 1 & 2: student submitted or timer expired — no appeal allowed
        if session.status == SessionStatus.ENDED.value:
            raise HTTPException(status_code=403, detail="This exam has already been submitted. No appeal is allowed.")

    # Enforce one-appeal-per-termination rule — check RR BEFORE the CREATED status
    # guard so that CREATED+PENDING correctly returns "already pending" not "already approved".
    any_rr = (
        db.query(models.ResumeRequest)
        .filter(models.ResumeRequest.session_id == session.id)
        .order_by(models.ResumeRequest.created_at.desc())
        .first()
    )
    if any_rr:
        if any_rr.status == ResumeStatus.PENDING.value:
            raise HTTPException(status_code=400, detail="An appeal is already pending.")
        if any_rr.status == ResumeStatus.DENIED.value:
            raise HTTPException(status_code=403, detail="Your appeal was already reviewed and denied. No further appeals are allowed.")
        if any_rr.status == ResumeStatus.APPROVED.value:
            raise HTTPException(status_code=400, detail="Your appeal has already been approved. Proceed to rejoin.")
        # NOT_APPLIED means they previously dismissed — allow re-appeal as long as they can still appeal

    # CREATED with no direct RR: either Fix B new-session (cross-session approved) or
    # unexpected state. Block re-appeal in both sub-cases.
    if not any_rr and session.status == SessionStatus.CREATED.value:
        cross_approved = (
            db.query(models.ResumeRequest)
            .join(models.ExamSession, models.ExamSession.id == models.ResumeRequest.session_id)
            .filter(
                models.ExamSession.user_id == current_user.id,
                models.ExamSession.exam_id == exam_id,
                models.ResumeRequest.status == ResumeStatus.APPROVED.value,
            )
            .first()
        )
        raise HTTPException(
            status_code=400,
            detail="Your appeal has already been approved. Proceed to rejoin."
            if cross_approved else
            "Your appeal is already in progress. Please wait for admin review."
        )

    # Fix B: cross-session AGAIN check — a sibling session for this user+exam already
    # has an APPROVED appeal, meaning the student has used their one appeal chance.
    if not any_rr and session.status == SessionStatus.TERMINATED.value:
        prior_approved = (
            db.query(models.ResumeRequest)
            .join(models.ExamSession, models.ExamSession.id == models.ResumeRequest.session_id)
            .filter(
                models.ExamSession.user_id == current_user.id,
                models.ExamSession.exam_id == exam_id,
                models.ExamSession.id != session.id,
                models.ResumeRequest.status == ResumeStatus.APPROVED.value,
            )
            .first()
        )
        if prior_approved:
            raise HTTPException(status_code=403, detail="No further appeals are allowed. You have already used your one appeal.")

    rr = models.ResumeRequest(
        session_id=session.id,
        reason=data.reason,
        status=ResumeStatus.PENDING.value
    )
    db.add(rr)
    db.commit()

    log.info("Appeal filed by %s for session %s.", current_user.id, session.id)

    return {"message": "Appeal submitted successfully", "status": "PENDING"}


@router.post("/{exam_id}/dismiss-appeal")
def dismiss_appeal(
    exam_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Student explicitly dismisses the appeal (Back to Dashboard / tab close beacon).
    Creates a NOT_APPLIED ResumeRequest row to mark the decision.
    Only valid for TERMINATED sessions with no existing active appeal.
    """
    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
    ).order_by(models.ExamSession.created_at.desc()).first()

    if not session:
        raise HTTPException(status_code=404, detail="No session found for this exam")

    if session.status != SessionStatus.TERMINATED.value:
        raise HTTPException(status_code=400, detail="Session is not terminated")

    # Check resume state — only allow dismiss if CAN_APPLY (no existing RR)
    resume_state = get_resume_state(session, db)
    if resume_state not in ("CAN_APPLY", "NOT_APPLIED"):
        # Already has a PENDING/APPROVED/DENIED/AGAIN RR — can't dismiss
        return {"message": "Nothing to dismiss", "resume_state": resume_state}

    if resume_state == "NOT_APPLIED":
        # Already dismissed — idempotent
        return {"message": "Already dismissed", "resume_state": "NOT_APPLIED"}

    rr = models.ResumeRequest(
        session_id=session.id,
        reason="Student dismissed — chose not to appeal",
        status=ResumeStatus.NOT_APPLIED.value,
    )
    db.add(rr)
    db.commit()

    log.info("Appeal dismissed by %s for session %s (exam %s).", current_user.id, session.id, exam_id)
    return {"message": "Appeal dismissed", "resume_state": "NOT_APPLIED"}


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
    ).order_by(models.ExamSession.created_at.desc()).first()

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

    # CREATED from appeal approval — skip late/appeal checks (Fix B: new session after termination)
    # This CREATED session was born from review_resume_request, not a fresh late join.
    is_appeal_resume = False
    if active and active.status == SessionStatus.CREATED.value:
        is_appeal_resume = bool(
            db.query(models.ResumeRequest)
            .join(models.ExamSession, models.ExamSession.id == models.ResumeRequest.session_id)
            .filter(
                models.ExamSession.user_id == current_user.id,
                models.ExamSession.exam_id == exam_id,
                models.ResumeRequest.status == ResumeStatus.APPROVED.value,
            )
            .first()
        )

    if not is_reconnect and not is_appeal_resume:
        is_late = hard_deadline and now > hard_deadline and (
            not active or active.status == SessionStatus.CREATED.value
        )

        if is_late:
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
            latest_rr = (
                db.query(models.ResumeRequest)
                .filter(models.ResumeRequest.session_id == active.id)
                .order_by(models.ResumeRequest.created_at.desc())
                .first()
            )
            # AGAIN: already used their one appeal; second termination → no re-entry
            if latest_rr and latest_rr.status == ResumeStatus.APPROVED.value:
                raise HTTPException(status_code=403, detail="No further appeals are allowed.")
            # Explicitly denied or dismissed → no re-entry
            if latest_rr and latest_rr.status in (
                ResumeStatus.DENIED.value, ResumeStatus.NOT_APPLIED.value
            ):
                raise HTTPException(status_code=403, detail="Your appeal has been closed. No further access is allowed.")
            # No RR or PENDING → not yet approved
            if not latest_rr or latest_rr.status == ResumeStatus.PENDING.value:
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
            join_time = datetime.now(UTC)
            session.start_time = join_time

            # For late-join CREATED sessions the admin extension is pre-stored on
            # the session but the mode-specific base penalty hasn't been applied yet
            # (because we didn't know the actual join time at appeal-submission time).
            # Apply the same penalty logic used for new sessions below.
            from app.db.enums import ExamMode as _ExamMode
            def _to_utc(dt):
                return dt.replace(tzinfo=UTC) if dt and dt.tzinfo is None else dt

            admin_extension_s = session.time_extension_seconds or 0

            if exam.exam_mode == _ExamMode.FIXED.value:
                exam_start_utc = _to_utc(exam.start_window)
                base_s = int((exam_start_utc - join_time).total_seconds())
                # base_s is negative for late joiners (loses time vs shared deadline)
                session.time_extension_seconds = base_s + admin_extension_s
            else:  # FLEXIBLE
                hjd = _to_utc(exam.hard_join_deadline)
                if hjd and join_time > hjd:
                    end_utc = _to_utc(exam.end_window)
                    remaining_s = (end_utc - join_time).total_seconds()
                    bonus_s = (exam.max_late_minutes or 0) * 60 if exam.allow_late_extension else 0
                    total_s = remaining_s + bonus_s
                    base_s = int(total_s - exam.duration_minutes * 60)
                    session.time_extension_seconds = base_s + admin_extension_s
        if is_reconnect or session.proctor_pc_id:
            # Clear the stale engine session — the old WebRTC connection is dead.
            # Covers both: DISCONNECTED reconnect and TERMINATED→CREATED (appeal approved).
            # The engine self-cleans when the ICE state goes to disconnected/failed.
            # proctor-connect will write fresh values once the student re-establishes
            # the WebRTC offer, so the DB never points at a dead engine slot.
            old_pc_id = session.proctor_pc_id
            session.proctor_pc_id = None
            session.proctor_engine_url = None
            if old_pc_id:
                log.info("Reconnect/resume: cleared stale engine session pc_id=%s for session=%s",
                         old_pc_id, session.id)
    else:
        join_time = datetime.now(UTC)
        session = models.ExamSession(
            user_id=current_user.id,
            exam_id=exam_id,
            status=SessionStatus.ACTIVE.value,
            start_time=join_time,
            device_fingerprint=device_fp,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent"),
        )
        db.add(session)

        # ── Set mode-aware time extension ────────────────────────────────────
        from app.db.enums import ExamMode as _ExamMode
        def _to_utc(dt):
            return dt.replace(tzinfo=UTC) if dt and dt.tzinfo is None else dt

        if exam.exam_mode == _ExamMode.FIXED.value:
            # All students share deadline = start_window + duration
            # extension encodes the offset: deadline = join_time + duration + extension
            exam_start_utc = _to_utc(exam.start_window)
            extension_s = int((exam_start_utc - join_time).total_seconds())
            if extension_s < 0:  # late joiner loses time
                session.time_extension_seconds = extension_s
        else:  # FLEXIBLE
            hjd = _to_utc(exam.hard_join_deadline)
            if hjd and join_time > hjd:
                # Late joiner: remaining time = end_window - join + bonus
                end_utc = _to_utc(exam.end_window)
                remaining_s = (end_utc - join_time).total_seconds()
                bonus_s = (exam.max_late_minutes or 0) * 60 if exam.allow_late_extension else 0
                total_s = remaining_s + bonus_s
                extension_s = int(total_s - exam.duration_minutes * 60)  # negative
                session.time_extension_seconds = extension_s

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

    # Cancel any pending identity checks for this session
    from app.exam.identity_check import cancel_identity_checks
    cancel_identity_checks(str(session.id))

    invite = db.query(models.ExamInvite).filter(
        func.lower(models.ExamInvite.student_email) == session.user.email.lower(),
        models.ExamInvite.exam_id == session.exam_id,
    ).first()
    if invite:
        invite.used = True

    db.commit()

    log.info("Exam ended session=%s user=%s", session.id, session.user_id)

    # Pull final risk data from engine (best-effort — don't fail the submit)
    if session.proctor_pc_id and session.proctor_engine_url:
        import asyncio as _asyncio
        from app.exam.proctor_proxy import fetch_session_log as _fetch_log
        try:
            log_data = _asyncio.run(
                _fetch_log(session.proctor_engine_url, session.proctor_pc_id)
            )
            risk = log_data.get("risk", {})
            session.risk_score = int(risk.get("final_score", session.risk_score or 0))
            report_id = log_data.get("report_id") or log_data.get("session_id") or log_data.get("id")
            if report_id:
                session.proctor_report_id = report_id
            db.commit()
            log.info("Engine report pulled on exam end: session=%s score=%s", session.id, session.risk_score)
        except Exception as _e:
            log.warning("Could not pull engine report on exam end (session=%s): %s", session.id, _e)

    return {"message": "Exam ended", "session_id": str(session.id)}


# =====================================================
# PROCTOR ENGINE PROXY ROUTES
# =====================================================

class ProctorOfferBody(BaseModel):
    sdp: str
    type: str


class ProctorIceBody(BaseModel):
    candidate: str
    sdpMid: str | None = None
    sdpMLineIndex: int | None = None


class ProctorViolationBody(BaseModel):
    reason: str = "tab_switch"   # "tab_switch" | "window_blur"


@router.get("/{exam_id}/engine-status")
async def engine_status(
    exam_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Pre-flight check called from the system-check page before the student starts the exam.
    Checks the global pool of engine containers — not per-exam assignment.

    Response: {available: bool, reason: str, message: str}
    Reasons: "ok" | "no_engine" | "unreachable" | "at_capacity"
    """
    import httpx

    containers = (
        db.query(models.EngineContainer)
        .filter(models.EngineContainer.is_active == True)
        .all()
    )

    if not containers:
        return {
            "available": False,
            "reason": "no_engine",
            "message": "No proctoring engine is configured. Please contact your administrator.",
        }

    any_reachable = False
    any_has_capacity = False

    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=4.0, read=5.0, write=4.0, pool=4.0)) as client:
        for container in containers:
            try:
                resp = await client.get(f"{container.url}/capacity")
                resp.raise_for_status()
                data = resp.json()
                any_reachable = True
                if data.get("available", False):
                    any_has_capacity = True
                    break
            except httpx.ConnectError:
                log.warning("Engine container unreachable: %s", container.url)
            except httpx.TimeoutException:
                log.warning("Engine container timed out: %s", container.url)
            except Exception as exc:
                log.warning("Engine capacity check failed (%s): %s", container.url, exc)

    if not any_reachable:
        return {
            "available": False,
            "reason": "unreachable",
            "message": "The proctoring engine is currently unavailable. Please contact your administrator.",
        }

    if not any_has_capacity:
        return {
            "available": False,
            "reason": "at_capacity",
            "message": "All proctoring slots are currently in use. Please wait a few minutes and try again.",
        }

    return {"available": True, "reason": "ok", "message": ""}


@router.post("/{exam_id}/proctor-connect")
async def proctor_connect(
    exam_id: str,
    body: ProctorOfferBody,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    WebRTC offer proxy — student calls this after /exam/start succeeds.
    Proxies the offer to the correct engine container, saves pc_id and
    engine_url back onto the ExamSession row.
    """
    from app.exam.engine_allocator import pick_any_container
    from app.exam.proctor_proxy import proxy_offer, build_engine_detection_config

    exam = db.query(models.Exam).filter(
        models.Exam.id == exam_id,
        models.Exam.is_deleted == False,
    ).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
        models.ExamSession.status == SessionStatus.ACTIVE.value,
    ).first()
    if not session:
        raise HTTPException(status_code=403, detail="No active exam session. Call /exam/start first.")

    # Pick the least-loaded container from the global pool
    engine_url = pick_any_container(db)
    if not engine_url:
        raise HTTPException(
            status_code=503,
            detail="No proctoring engine is configured. Contact your administrator.",
        )

    # Build merged config (exam admin toggles + system admin thresholds)
    engine_settings = db.query(models.EngineSettings).first()
    if not engine_settings:
        raise HTTPException(status_code=503, detail="Engine settings not initialised.")

    detection_config = build_engine_detection_config(exam.detection_config, engine_settings)

    try:
        answer = await proxy_offer(
            engine_url,
            body.sdp,
            body.type,
            detection_config,
            initial_score=session.risk_score or 0.0,
            metadata={
                "external_exam_session_id": str(session.id),
                "external_exam_id": str(exam.id),
                "external_user_id": str(current_user.id),
                "external_student_name": current_user.full_name,
                "external_student_email": current_user.email,
                "exam_duration_minutes": exam.duration_minutes,
            },
        )
    except Exception as e:
        import httpx as _httpx
        if isinstance(e, _httpx.HTTPStatusError) and e.response.status_code == 503:
            try:
                err_body = e.response.json()
                if err_body.get("error") == "MODEL_CALIBRATION_ACTIVE":
                    raise HTTPException(
                        status_code=503,
                        detail="MODEL_CALIBRATION_ACTIVE",
                    )
            except HTTPException:
                raise
            except Exception:
                pass
        log.error("Engine /offer failed (url=%s exam=%s): %s", engine_url, exam_id, e)
        raise HTTPException(status_code=503, detail="Proctoring engine is unreachable. Exam cannot start.")

    pc_id = answer.get("device_id")
    if not pc_id:
        raise HTTPException(status_code=502, detail="Engine did not return a session ID.")

    session.proctor_pc_id = pc_id
    session.proctor_engine_url = engine_url
    db.commit()

    log.info("Proctor session created: exam=%s user=%s pc_id=%s engine=%s",
             exam_id, current_user.id, pc_id, engine_url)

    # ── Schedule in-exam identity checks ────────────────────────────────────
    if current_user.face_embedding and engine_settings and session.start_time:
        from app.exam.identity_check import schedule_identity_checks
        schedule_identity_checks(
            session_id=str(session.id),
            user_face_embedding=current_user.face_embedding,
            start_time=session.start_time,
            duration_minutes=exam.duration_minutes,
            extension_seconds=session.time_extension_seconds or 0,
            proctor_engine_url=engine_url,
            proctor_pc_id=pc_id,
            check_count=engine_settings.identity_check_count,
            retry_count=engine_settings.identity_check_retries,
            retry_delay_s=engine_settings.identity_check_retry_delay,
        )

    return {**answer, "engine_url": engine_url}


@router.post("/{exam_id}/proctor-ice")
async def proctor_ice(
    exam_id: str,
    body: ProctorIceBody,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Trickle ICE candidate proxy."""
    from app.exam.proctor_proxy import proxy_ice_candidate

    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
        models.ExamSession.status == SessionStatus.ACTIVE.value,
    ).first()
    if not session or not session.proctor_pc_id:
        raise HTTPException(status_code=404, detail="No active proctor session")

    candidate_dict = {
        "candidate":     body.candidate,
        "sdpMid":        body.sdpMid,
        "sdpMLineIndex": body.sdpMLineIndex,
    }
    await proxy_ice_candidate(session.proctor_engine_url, session.proctor_pc_id, candidate_dict)
    return {"ok": True}


@router.post("/{exam_id}/proctor-violation")
async def proctor_violation(
    exam_id: str,
    body: ProctorViolationBody,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Report a focus event (tab switch / window blur) to the engine.
    If the engine auto-terminates (3 switches), marks the ExamSession TERMINATED.
    """
    from app.exam.proctor_proxy import proxy_tab_switch
    from app.exam.events import push_event_sync

    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
        models.ExamSession.status == SessionStatus.ACTIVE.value,
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="No active session")

    # ── Fallback path: engine not connected — count in-memory, terminate via DB ──
    if not session.proctor_pc_id:
        if body.reason != "tab_switch":
            # Non-tab-switch violations without an engine session are just acknowledged
            return {"ok": True, "risk": None}

        sess_key = str(session.id)
        count = _tab_switch_fallback.get(sess_key, 0) + 1
        _tab_switch_fallback[sess_key] = count

        es = db.query(models.EngineSettings).first()
        terminate_count = (es.tab_switch_terminate_count if es else None) or 3

        terminated = count >= terminate_count
        if terminated:
            reason = f"Tab switched {count} times (limit: {terminate_count})"
            session.status         = SessionStatus.TERMINATED.value
            session.terminated_reason = reason
            session.terminated_by  = "SYSTEM_RISK"
            session.terminated_at  = datetime.now(UTC)
            session.end_time       = session.end_time or session.terminated_at
            db.commit()
            push_event_sync(str(session.id), "TERMINATED", {"cause": "system", "reason": reason})
            _tab_switch_fallback.pop(sess_key, None)
            from app.exam.identity_check import cancel_identity_checks
            cancel_identity_checks(sess_key)
            log.info("Session terminated by fallback tab-switch counter: session=%s count=%d", session.id, count)

        return {"ok": True, "risk": {"terminated": terminated, "tab_count": count, "tab_limit": terminate_count}}

    # ── Normal path: proxy to engine ─────────────────────────────────────────────
    try:
        result = await proxy_tab_switch(session.proctor_engine_url, session.proctor_pc_id)
    except Exception as e:
        log.warning("Tab switch proxy failed (session=%s): %s", session.id, e)
        return {"ok": False, "risk": None}

    # If engine terminated the session, reflect that in our DB
    risk = result.get("risk", {})
    if risk.get("terminated"):
        session.status = SessionStatus.TERMINATED.value
        session.terminated_reason = risk.get("reason", "Exam policy violated")
        session.terminated_by = "SYSTEM_RISK"
        session.terminated_at = datetime.now(UTC)
        session.end_time = session.end_time or session.terminated_at
        db.commit()

        # Push termination event through ProctorAI's own SSE so the active page
        # gets notified via its existing SSE connection
        push_event_sync(str(session.id), "TERMINATED", {
            "cause":  "system",
            "reason": session.terminated_reason,
        })
        from app.exam.identity_check import cancel_identity_checks
        cancel_identity_checks(str(session.id))
        log.info("Session terminated by engine (tab switch): session=%s", session.id)

    return result


@router.get("/{exam_id}/proctor-events")
async def proctor_events(
    exam_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    SSE proxy — streams engine risk events to the student's active page.
    Events are forwarded as-is from the engine's /stream/{pc_id}.
    On session_end from engine, also terminates the ProctorAI session.
    """
    from app.exam.proctor_proxy import stream_engine_events
    from app.exam.events import push_event_sync

    session = db.query(models.ExamSession).filter(
        models.ExamSession.user_id == current_user.id,
        models.ExamSession.exam_id == exam_id,
        models.ExamSession.status.in_([
            SessionStatus.ACTIVE.value,
            SessionStatus.DISCONNECTED.value,
        ]),
    ).first()
    if not session or not session.proctor_pc_id:
        raise HTTPException(status_code=404, detail="No active proctor session")

    pc_id = session.proctor_pc_id
    engine_url = session.proctor_engine_url
    session_id_str = str(session.id)

    async def event_stream():
        import json as _json
        from app.db.session import SessionLocal
        parse_fail_count = 0
        async for chunk in stream_engine_events(engine_url, pc_id):
            yield chunk

            # Parse the event to sync DB state
            if '"type"' not in chunk:
                continue
            try:
                raw = chunk.strip()
                if raw.startswith("data: "):
                    raw = raw[6:]
                event_data = _json.loads(raw)
            except Exception as _e:
                parse_fail_count += 1
                # Avoid log spam: only log early/bursty parse failures.
                if parse_fail_count <= 3 or parse_fail_count % 50 == 0:
                    log.warning(
                        "proctor_events: SSE chunk parse failed session_id=%s pc_id=%s fail_count=%s error=%s chunk_prefix=%r",
                        session_id_str,
                        pc_id,
                        parse_fail_count,
                        _e,
                        chunk[:200],
                    )
                continue

            event_type = event_data.get("type")

            # Update risk_score in DB on every alert/warning
            if event_type in ("alert", "warning"):
                risk_info = event_data.get("risk", {})
                new_score = risk_info.get("score")
                if new_score is not None:
                    _db = SessionLocal()
                    try:
                        _sess = _db.query(models.ExamSession).filter(
                            models.ExamSession.id == session_id_str
                        ).first()
                        if _sess:
                            _sess.risk_score = int(new_score)
                            _db.commit()
                    except Exception as _e:
                        log.warning("Failed to update risk_score: %s", _e)
                    finally:
                        _db.close()

            # Engine auto-terminated the session (alert with terminated: true)
            if event_data.get("terminated") and event_type == "alert":
                _db = SessionLocal()
                try:
                    _sess = _db.query(models.ExamSession).filter(
                        models.ExamSession.id == session_id_str
                    ).first()
                    if _sess and _sess.status == SessionStatus.ACTIVE.value:
                        _sess.status = SessionStatus.TERMINATED.value
                        _sess.terminated_reason = event_data.get("message", "Terminated by proctoring engine")
                        _sess.terminated_by = "SYSTEM_RISK"
                        _sess.terminated_at = datetime.now(UTC)
                        _sess.end_time = _sess.end_time or _sess.terminated_at
                        _db.commit()
                        push_event_sync(session_id_str, "TERMINATED", {
                            "cause": "system",
                            "reason": _sess.terminated_reason,
                        })
                        from app.exam.identity_check import cancel_identity_checks
                        cancel_identity_checks(session_id_str)
                        log.info("Session %s terminated by engine via SSE", session_id_str)
                except Exception as _e:
                    log.warning("Failed to sync engine termination: %s", _e)
                finally:
                    _db.close()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
