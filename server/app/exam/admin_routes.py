import secrets
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, BackgroundTasks, status, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone, timedelta, UTC
from pydantic import BaseModel

from app.db import models, get_db
from app.db.enums import ExamStatus, UserRole, SessionStatus, ResumeStatus
from app.auth.dependencies import require_role
from app.core import log, send_email, settings
from app.exam.schemas import ExamCreateRequest, ExamUpdateRequest, ExamListResponse, ExamDetailResponse
from app.exam.events import push_event_sync

router = APIRouter(prefix="/admin/exams", tags=["Admin Exams"])


# =====================================================
# BACKGROUND EMAIL HELPERS
# All background tasks create their own DB session and
# accept only serialized (non-ORM) data to avoid
# DetachedInstanceError after the request session closes.
# =====================================================

def _send_exam_invites(
    admin_email: str,
    exam_title: str,
    hard_deadline_str: str,
    invite_data: List[dict],
):
    """
    Send invite emails with retry (3 attempts, exponential backoff).
    On persistent failures, notifies the admin.
    invite_data: list of {email: str, token: str}
    """
    from app.db.session import SessionLocal

    failed_emails: List[str] = []

    # Batch-lookup registered students in one query
    all_emails_lower = [d["email"].lower() for d in invite_data]
    db = SessionLocal()
    try:
        registered_users = (
            db.query(models.User)
            .filter(
                func.lower(models.User.email).in_(all_emails_lower),
                models.User.role == UserRole.STUDENT.value,
                models.User.is_active == True,
                models.User.deleted_at.is_(None),
            )
            .all()
        )
        user_map = {u.email.lower(): u.full_name for u in registered_users}
    except Exception as e:
        log.error("Failed to query users for invite emails: %s", e)
        user_map = {}
    finally:
        db.close()

    for inv in invite_data:
        email = inv["email"]
        link = f"{settings.FRONTEND_URL}/exam/{inv['token']}/wait"
        full_name = user_map.get(email.lower())

        if full_name:
            subject = f"You're invited to take an exam: {exam_title}"
            body = (
                f"Hello {full_name},\n\n"
                f"You have been assigned to the exam '{exam_title}'.\n"
                f"Access your exam here: {link}\n\n"
                f"Please ensure you join before the deadline: {hard_deadline_str}.\n"
            )
        else:
            subject = f"Action Required: Exam Invitation for {exam_title}"
            body = (
                f"Hello,\n\n"
                f"You have been assigned to the exam '{exam_title}', but you do not currently "
                f"have an active profile in our system.\n"
                f"Your exam link is: {link}\n\n"
                f"Please register at {settings.FRONTEND_URL}/auth/register using this email "
                f"address ({email}) so you can be verified and take the exam.\n"
            )

        sent = False
        for attempt in range(3):
            try:
                send_email(to=email, subject=subject, body=body)
                sent = True
                break
            except Exception as e:
                log.warning("Invite email attempt %d failed for %s: %s", attempt + 1, email, e)
                if attempt < 2:
                    time.sleep(2**attempt)  # 1s, 2s

        if not sent:
            failed_emails.append(email)
            log.error("All 3 invite email attempts failed for %s", email)

    if failed_emails and admin_email:
        failure_list = "\n".join(f"  - {e}" for e in failed_emails)
        try:
            send_email(
                to=admin_email,
                subject=f"[Proctor AI] Invite delivery failure: {exam_title}",
                body=(
                    f"Hello,\n\n"
                    f"The following student invite emails for '{exam_title}' could not be "
                    f"delivered after 3 attempts:\n\n{failure_list}\n\n"
                    f"Please review and resend manually from the exam dashboard."
                ),
            )
        except Exception as e:
            log.error("Failed to notify admin %s of invite failures: %s", admin_email, e)


def _send_schedule_update_emails(exam_title: str, emails: List[str]):
    subject = f"Exam Update: {exam_title}"
    body = (
        f"Hello,\n\n"
        f"The details (Date, Time, or Duration) for your scheduled exam '{exam_title}' have been updated.\n"
        f"Please check your dashboard to confirm the new schedule.\n\nThank you!"
    )
    for email in emails:
        for attempt in range(3):
            try:
                send_email(to=email, subject=subject, body=body)
                break
            except Exception as e:
                if attempt == 2:
                    log.error("Failed to send schedule update email to %s: %s", email, e)
                else:
                    time.sleep(2**attempt)


def _send_exam_cancelled_emails(exam_title: str, emails: List[str]):
    subject = f"Exam Cancelled: {exam_title}"
    body = (
        f"Hello,\n\n"
        f"The scheduled exam '{exam_title}' has been cancelled by the administrator.\n\n"
        f"If you have any questions, please contact your instructor."
    )
    for email in emails:
        for attempt in range(3):
            try:
                send_email(to=email, subject=subject, body=body)
                break
            except Exception as e:
                if attempt == 2:
                    log.error("Failed to send cancellation email to %s: %s", email, e)
                else:
                    time.sleep(2**attempt)


# =====================================================
# EXAM CRUD
# =====================================================

@router.post("", status_code=status.HTTP_201_CREATED)
def create_exam(
    data: ExamCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    now = datetime.now(UTC)

    # Backend enforcement: start must be >= 10 minutes in the future
    start_utc = data.start_window if data.start_window.tzinfo else data.start_window.replace(tzinfo=UTC)
    if start_utc <= now + timedelta(minutes=10):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Start window must be at least 10 minutes in the future.",
        )

    # at_least_one_invite is enforced by schema, but belt-and-suspenders
    if not data.invites:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one student must be invited.",
        )

    def _utc(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)

    new_exam = models.Exam(
        title=data.title,
        created_by=current_admin.id,
        exam_mode=data.exam_mode.value,
        status=ExamStatus.SCHEDULED.value,
        start_window=_utc(data.start_window),
        end_window=_utc(data.end_window),
        duration_minutes=data.duration_minutes,
        hard_join_deadline=_utc(data.hard_join_deadline),
        flag_threshold=data.flag_threshold,
        late_join_policy=data.late_join_policy.value,
        allow_late_extension=data.allow_late_extension,
        max_late_minutes=data.max_late_minutes,
        config=data.config.model_dump(),
        detection_config=data.detection_config.model_dump(),
    )
    db.add(new_exam)
    db.commit()
    db.refresh(new_exam)

    # Build invites — emails already lowercased by schema
    invite_data: List[dict] = []
    for email in set(data.invites):
        token = secrets.token_urlsafe(32)
        db.add(
            models.ExamInvite(
                exam_id=new_exam.id,
                student_email=email,
                token=token,
                expires_at=new_exam.end_window,
                used=False,
            )
        )
        invite_data.append({"email": email, "token": token})

    db.commit()

    hard_deadline_str = (
        new_exam.hard_join_deadline.strftime("%Y-%m-%d %H:%M UTC")
        if new_exam.hard_join_deadline
        else "N/A"
    )

    if invite_data:
        background_tasks.add_task(
            _send_exam_invites,
            current_admin.email,
            new_exam.title,
            hard_deadline_str,
            invite_data,
        )

    log.info(
        "Exam '%s' created by %s with %d invites.",
        new_exam.title,
        current_admin.email,
        len(invite_data),
    )

    return {
        "message": "Exam created successfully. Invites are being dispatched.",
        "exam_id": str(new_exam.id),
    }


@router.get("", response_model=List[ExamListResponse])
def list_exams(
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    rows = (
        db.query(models.Exam, func.count(models.ExamInvite.id).label("invite_count"))
        .outerjoin(models.ExamInvite, models.Exam.id == models.ExamInvite.exam_id)
        .filter(
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .group_by(models.Exam.id)
        .order_by(models.Exam.created_at.desc())
        .all()
    )

    return [
        {
            "id": str(exam.id),
            "title": exam.title,
            "exam_mode": exam.exam_mode,
            "status": exam.status,
            "start_window": exam.start_window,
            "end_window": exam.end_window,
            "duration_minutes": exam.duration_minutes,
            "created_at": exam.created_at,
            "invite_count": count,
        }
        for exam, count in rows
    ]


@router.get("/{exam_id}", response_model=ExamDetailResponse)
def get_exam_detail(
    exam_id: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")

    invites = db.query(models.ExamInvite).filter(models.ExamInvite.exam_id == exam.id).all()

    return {
        "id": str(exam.id),
        "title": exam.title,
        "exam_mode": exam.exam_mode,
        "status": exam.status,
        "start_window": exam.start_window,
        "end_window": exam.end_window,
        "duration_minutes": exam.duration_minutes,
        "created_at": exam.created_at,
        "invite_count": len(invites),
        "hard_join_deadline": exam.hard_join_deadline,
        "flag_threshold": exam.flag_threshold,
        "late_join_policy": exam.late_join_policy,
        "allow_late_extension": exam.allow_late_extension,
        "max_late_minutes": exam.max_late_minutes,
        "config": exam.config,
        "detection_config": exam.detection_config,
        "invites": [
            {
                "id": str(inv.id),
                "student_email": inv.student_email,
                "token": inv.token,
                "expires_at": inv.expires_at,
                "used": inv.used,
            }
            for inv in invites
        ],
    }


@router.put("/{exam_id}", response_model=dict)
def update_exam(
    exam_id: str,
    data: ExamUpdateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")

    # Block editing completed or cancelled exams
    if exam.status in (ExamStatus.ENDED.value, ExamStatus.CANCELLED.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot edit an exam with status '{exam.status}'.",
        )

    # Block editing within 15 minutes of start
    exam_start_utc = (
        exam.start_window.replace(tzinfo=UTC)
        if exam.start_window.tzinfo is None
        else exam.start_window
    )
    if exam_start_utc <= datetime.now(UTC) + timedelta(minutes=15):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot edit exam within 15 minutes of its scheduled start time.",
        )

    def _utc(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)

    new_start = _utc(data.start_window)
    new_end = _utc(data.end_window)
    new_deadline = _utc(data.hard_join_deadline)

    # Detect schedule changes (UTC-aware comparison)
    schedule_changed = (
        _utc(exam.start_window) != new_start
        or _utc(exam.end_window) != new_end
        or exam.duration_minutes != data.duration_minutes
    )

    exam.title = data.title
    exam.exam_mode = data.exam_mode.value
    exam.start_window = new_start
    exam.end_window = new_end
    exam.duration_minutes = data.duration_minutes
    exam.hard_join_deadline = new_deadline
    exam.flag_threshold = data.flag_threshold
    exam.late_join_policy = data.late_join_policy.value
    exam.allow_late_extension = data.allow_late_extension
    exam.max_late_minutes = data.max_late_minutes
    exam.config = data.config.model_dump()
    exam.detection_config = data.detection_config.model_dump()

    # Sync invites — emails already lowercased by schema
    current_invites = (
        db.query(models.ExamInvite).filter(models.ExamInvite.exam_id == exam.id).all()
    )
    current_email_map = {inv.student_email.lower(): inv for inv in current_invites}
    new_email_set = set(data.invites)

    emails_to_add = new_email_set - set(current_email_map.keys())
    emails_to_remove = set(current_email_map.keys()) - new_email_set

    for email in emails_to_remove:
        db.delete(current_email_map[email])

    new_invite_data: List[dict] = []
    for email in emails_to_add:
        token = secrets.token_urlsafe(32)
        db.add(
            models.ExamInvite(
                exam_id=exam.id,
                student_email=email,
                token=token,
                expires_at=new_end,
                used=False,
            )
        )
        new_invite_data.append({"email": email, "token": token})

    db.commit()

    hard_deadline_str = (
        new_deadline.strftime("%Y-%m-%d %H:%M UTC") if new_deadline else "N/A"
    )

    if new_invite_data:
        background_tasks.add_task(
            _send_exam_invites,
            current_admin.email,
            exam.title,
            hard_deadline_str,
            new_invite_data,
        )

    if schedule_changed:
        existing_emails = list(new_email_set - emails_to_add)
        if existing_emails:
            background_tasks.add_task(
                _send_schedule_update_emails, exam.title, existing_emails
            )

    log.info("Exam '%s' updated by %s.", exam.title, current_admin.email)
    return {"message": "Exam updated successfully."}


@router.delete("/{exam_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_exam(
    exam_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")

    # Completed exams are permanent records — cannot be deleted
    if exam.status == ExamStatus.ENDED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a completed exam. Records must be retained for audit purposes.",
        )

    # Block deletion of ongoing exams with active sessions
    if exam.status == ExamStatus.LIVE.value:
        active_count = (
            db.query(models.ExamSession)
            .filter(
                models.ExamSession.exam_id == exam_id,
                models.ExamSession.status == SessionStatus.ACTIVE.value,
            )
            .count()
        )
        if active_count > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete an ongoing exam — {active_count} student(s) are currently active.",
            )

    invite_emails = [
        inv.student_email
        for inv in db.query(models.ExamInvite)
        .filter(models.ExamInvite.exam_id == exam.id)
        .all()
    ]
    exam_title = exam.title

    # Soft delete
    exam.is_deleted = True
    exam.deleted_at = datetime.now(UTC)
    exam.status = ExamStatus.CANCELLED.value
    db.commit()

    if invite_emails:
        background_tasks.add_task(_send_exam_cancelled_emails, exam_title, invite_emails)

    log.info("Exam '%s' soft-deleted by %s.", exam_title, current_admin.email)
    return None


# =====================================================
# MONITORING — LIVE SESSION CARDS
# =====================================================

@router.get("/{exam_id}/sessions")
def list_exam_sessions(
    exam_id: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """
    Return all sessions for an exam with student info, status, risk, and violation counts.
    Used by the monitoring dashboard.
    """
    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")

    sessions = (
        db.query(models.ExamSession)
        .filter(models.ExamSession.exam_id == exam_id)
        .all()
    )

    result = []
    for sess in sessions:
        user = db.query(models.User).filter(models.User.id == sess.user_id).first()
        violation_count = db.query(models.Violation).filter(
            models.Violation.session_id == sess.id
        ).count()

        pending_appeal = db.query(models.ResumeRequest).filter(
            models.ResumeRequest.session_id == sess.id,
            models.ResumeRequest.status == ResumeStatus.PENDING.value,
        ).first()

        result.append({
            "session_id": str(sess.id),
            "user_id": str(sess.user_id),
            "student_name": user.full_name if user else "Unknown",
            "student_email": user.email if user else "",
            "status": sess.status,
            "start_time": sess.start_time,
            "end_time": sess.end_time,
            "risk_score": sess.risk_score or 0,
            "violation_count": violation_count,
            "last_heartbeat": sess.last_heartbeat,
            "terminated_reason": sess.terminated_reason,
            "terminated_by": sess.terminated_by,
            "time_extension_seconds": sess.time_extension_seconds or 0,
            "has_pending_appeal": pending_appeal is not None,
        })

    return result


# =====================================================
# MONITORING — RESUME REQUEST MANAGEMENT
# =====================================================

@router.get("/{exam_id}/resume-requests")
def list_resume_requests(
    exam_id: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """List all resume requests (appeals) for an exam, newest first."""
    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")

    rrs = (
        db.query(models.ResumeRequest)
        .join(models.ExamSession, models.ExamSession.id == models.ResumeRequest.session_id)
        .filter(models.ExamSession.exam_id == exam_id)
        .order_by(models.ResumeRequest.created_at.desc())
        .all()
    )

    result = []
    for rr in rrs:
        sess = db.query(models.ExamSession).filter(models.ExamSession.id == rr.session_id).first()
        user = db.query(models.User).filter(models.User.id == sess.user_id).first() if sess else None
        result.append({
            "id": str(rr.id),
            "session_id": str(rr.session_id),
            "student_name": user.full_name if user else "Unknown",
            "student_email": user.email if user else "",
            "reason": rr.reason,
            "status": rr.status,
            "review_note": rr.review_note,
            "time_extension_minutes": rr.time_extension_minutes,
            "reviewed_at": rr.reviewed_at,
            "created_at": rr.created_at,
        })

    return result


class ReviewResumeRequest(BaseModel):
    decision: str  # "APPROVED" | "DENIED"
    review_note: Optional[str] = None
    time_extension_minutes: Optional[int] = None  # only when APPROVED


@router.post("/{exam_id}/resume-requests/{rr_id}/review")
def review_resume_request(
    exam_id: str,
    rr_id: str,
    data: ReviewResumeRequest,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """Approve or deny a student appeal, optionally granting extra time."""
    if data.decision not in ("APPROVED", "DENIED"):
        raise HTTPException(status_code=400, detail="decision must be APPROVED or DENIED")

    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")

    rr = db.query(models.ResumeRequest).filter(models.ResumeRequest.id == rr_id).first()
    if not rr:
        raise HTTPException(status_code=404, detail="Resume request not found")

    if rr.status != ResumeStatus.PENDING.value:
        raise HTTPException(status_code=400, detail="This request has already been reviewed")

    # Verify the request belongs to this exam
    sess = db.query(models.ExamSession).filter(
        models.ExamSession.id == rr.session_id,
        models.ExamSession.exam_id == exam_id,
    ).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found for this exam")

    now = datetime.now(UTC)
    rr.status = data.decision
    rr.review_note = data.review_note
    rr.reviewed_by = current_admin.id
    rr.reviewed_at = now
    rr.time_extension_minutes = data.time_extension_minutes if data.decision == "APPROVED" else None

    if data.decision == "APPROVED":
        # Apply time extension to session if provided
        if data.time_extension_minutes and data.time_extension_minutes > 0:
            sess.time_extension_seconds = (sess.time_extension_seconds or 0) + data.time_extension_minutes * 60

        # Resume: reactivate session if it was TERMINATED
        if sess.status == SessionStatus.TERMINATED.value:
            sess.status = SessionStatus.CREATED.value  # student will re-start via /exam/start

        event_type = "RESUME_APPROVED"
        event_data = {
            "review_note": data.review_note,
            "time_extension_minutes": data.time_extension_minutes,
            "time_extension_seconds": sess.time_extension_seconds,
        }
    else:
        event_type = "RESUME_DENIED"
        event_data = {"review_note": data.review_note}

    db.commit()

    # Push SSE event to the student
    push_event_sync(str(sess.id), event_type, event_data)

    log.info(
        "Admin %s %s resume request %s for session %s",
        current_admin.email, data.decision, rr_id, sess.id
    )

    return {"message": f"Appeal {data.decision.lower()} successfully."}


# =====================================================
# TIME EXTENSION — INDIVIDUAL & BULK
# =====================================================

class ExtendTimeRequest(BaseModel):
    minutes: int


@router.post("/{exam_id}/sessions/{session_id}/extend")
def extend_session_time(
    exam_id: str,
    session_id: str,
    data: ExtendTimeRequest,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """Grant extra time to a single student session."""
    if data.minutes <= 0:
        raise HTTPException(status_code=400, detail="minutes must be positive")

    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    sess = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id,
        models.ExamSession.exam_id == exam_id,
    ).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    sess.time_extension_seconds = (sess.time_extension_seconds or 0) + data.minutes * 60
    db.commit()

    push_event_sync(str(sess.id), "TIME_EXTENDED", {
        "added_minutes": data.minutes,
        "total_extension_seconds": sess.time_extension_seconds,
    })

    log.info(
        "Admin %s extended session %s by %d minutes.",
        current_admin.email, session_id, data.minutes
    )

    return {
        "message": f"Extended by {data.minutes} minute(s).",
        "total_extension_seconds": sess.time_extension_seconds,
    }


@router.post("/{exam_id}/extend-time")
def bulk_extend_time(
    exam_id: str,
    data: ExtendTimeRequest,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """Grant extra time to all currently ACTIVE sessions in an exam."""
    if data.minutes <= 0:
        raise HTTPException(status_code=400, detail="minutes must be positive")

    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    active_sessions = db.query(models.ExamSession).filter(
        models.ExamSession.exam_id == exam_id,
        models.ExamSession.status == SessionStatus.ACTIVE.value,
    ).all()

    for sess in active_sessions:
        sess.time_extension_seconds = (sess.time_extension_seconds or 0) + data.minutes * 60
        push_event_sync(str(sess.id), "TIME_EXTENDED", {
            "added_minutes": data.minutes,
            "total_extension_seconds": sess.time_extension_seconds,
        })

    db.commit()

    log.info(
        "Admin %s bulk-extended %d sessions in exam %s by %d minutes.",
        current_admin.email, len(active_sessions), exam_id, data.minutes
    )

    return {
        "message": f"Extended {len(active_sessions)} active session(s) by {data.minutes} minute(s).",
        "sessions_extended": len(active_sessions),
    }


# =====================================================
# PROCTOR ENGINE — ADMIN PROXY ROUTES
# =====================================================

@router.get("/{exam_id}/sessions/{session_id}/live-frame")
async def admin_live_frame(
    exam_id: str,
    session_id: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role("ADMIN")),
):
    """Proxy JPEG snapshot from the engine for admin live monitoring view."""
    from fastapi.responses import Response as _Response
    from app.exam.proctor_proxy import fetch_snapshot

    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id,
        models.ExamSession.exam_id == exam_id,
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.proctor_pc_id or not session.proctor_engine_url:
        raise HTTPException(status_code=404, detail="No proctoring engine session for this student")

    try:
        jpeg_bytes = await fetch_snapshot(session.proctor_engine_url, session.proctor_pc_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Engine snapshot unavailable: {e}")

    return _Response(content=jpeg_bytes, media_type="image/jpeg")


@router.get("/{exam_id}/sessions/{session_id}/live-stream")
async def admin_live_stream(
    exam_id: str,
    session_id: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role("ADMIN")),
):
    """
    SSE proxy from the engine — streams live violation alerts to the admin monitor panel.
    """
    from fastapi.responses import StreamingResponse as _SR
    from app.exam.proctor_proxy import stream_engine_events

    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id,
        models.ExamSession.exam_id == exam_id,
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.proctor_pc_id or not session.proctor_engine_url:
        raise HTTPException(status_code=404, detail="No proctoring engine session for this student")

    return _SR(
        stream_engine_events(session.proctor_engine_url, session.proctor_pc_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class DebugModeBody(BaseModel):
    enabled: bool


@router.post("/{exam_id}/sessions/{session_id}/debug-mode")
async def admin_debug_mode(
    exam_id: str,
    session_id: str,
    body: DebugModeBody,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role("ADMIN")),
):
    """Toggle CV2 debug overlay on the engine's live snapshot for this student."""
    from app.exam.proctor_proxy import proxy_debug_toggle

    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id,
        models.ExamSession.exam_id == exam_id,
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.proctor_pc_id or not session.proctor_engine_url:
        raise HTTPException(status_code=404, detail="No proctoring engine session for this student")

    try:
        result = await proxy_debug_toggle(
            session.proctor_engine_url, session.proctor_pc_id, body.enabled
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Engine debug toggle failed: {e}")

    return result


# =====================================================
# SYSTEM ADMIN — ENGINE SETTINGS
# =====================================================

_system_settings_router = APIRouter(prefix="/admin", tags=["System Admin"])


class EngineSettingsUpdate(BaseModel):
    # Head pose
    look_away_yaw: float | None = None
    look_down_pitch: float | None = None
    look_up_pitch: float | None = None
    gaze_left: float | None = None
    gaze_right: float | None = None
    # Duration gates
    looking_away_threshold: float | None = None
    gaze_threshold: float | None = None
    fake_window: float | None = None
    # Risk scores
    gaze_score: float | None = None
    phone_score_2nd: float | None = None
    phone_score_3rd: float | None = None
    book_score: float | None = None
    headphone_score: float | None = None
    earbud_score: float | None = None
    tab_switch_score: float | None = None
    multi_people_score_2nd: float | None = None
    multi_people_score_3rd: float | None = None
    no_person_score_1: float | None = None
    no_person_score_2: float | None = None
    fake_presence_score_1: float | None = None
    fake_presence_score_2: float | None = None
    # State thresholds
    state_warning: float | None = None
    state_high_risk: float | None = None
    state_admin_review: float | None = None
    # Decay
    decay_amount: float | None = None
    # Termination
    tab_switch_terminate_count: int | None = None
    multi_people_terminate_s: float | None = None
    no_person_terminate_s: float | None = None
    # YOLO confidence
    yolo_phone_conf: float | None = None
    yolo_book_conf: float | None = None
    yolo_audio_conf: float | None = None
    yolo_person_conf: float | None = None


@_system_settings_router.get("/system-settings")
def get_system_settings(
    db: Session = Depends(get_db),
    current_admin=Depends(require_role("SYSADMIN")),
):
    """Read current engine system settings (system admin only)."""
    row = db.query(models.EngineSettings).first()
    if not row:
        raise HTTPException(status_code=404, detail="Engine settings not initialised")
    return {
        "id": str(row.id),
        "look_away_yaw":              row.look_away_yaw,
        "look_down_pitch":            row.look_down_pitch,
        "look_up_pitch":              row.look_up_pitch,
        "gaze_left":                  row.gaze_left,
        "gaze_right":                 row.gaze_right,
        "looking_away_threshold":     row.looking_away_threshold,
        "gaze_threshold":             row.gaze_threshold,
        "fake_window":                row.fake_window,
        "gaze_score":                 row.gaze_score,
        "phone_score_2nd":            row.phone_score_2nd,
        "phone_score_3rd":            row.phone_score_3rd,
        "book_score":                 row.book_score,
        "headphone_score":            row.headphone_score,
        "earbud_score":               row.earbud_score,
        "tab_switch_score":           row.tab_switch_score,
        "multi_people_score_2nd":     row.multi_people_score_2nd,
        "multi_people_score_3rd":     row.multi_people_score_3rd,
        "no_person_score_1":          row.no_person_score_1,
        "no_person_score_2":          row.no_person_score_2,
        "fake_presence_score_1":      row.fake_presence_score_1,
        "fake_presence_score_2":      row.fake_presence_score_2,
        "state_warning":              row.state_warning,
        "state_high_risk":            row.state_high_risk,
        "state_admin_review":         row.state_admin_review,
        "decay_amount":               row.decay_amount,
        "tab_switch_terminate_count": row.tab_switch_terminate_count,
        "multi_people_terminate_s":   row.multi_people_terminate_s,
        "no_person_terminate_s":      row.no_person_terminate_s,
        "yolo_phone_conf":            row.yolo_phone_conf,
        "yolo_book_conf":             row.yolo_book_conf,
        "yolo_audio_conf":            row.yolo_audio_conf,
        "yolo_person_conf":           row.yolo_person_conf,
        "updated_at":                 row.updated_at.isoformat() if row.updated_at else None,
    }


@_system_settings_router.post("/system-settings")
def update_system_settings(
    data: EngineSettingsUpdate,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role("SYSADMIN")),
):
    """Update engine system settings (system admin only). Only provided fields are changed."""
    row = db.query(models.EngineSettings).first()
    if not row:
        raise HTTPException(status_code=404, detail="Engine settings not initialised")

    patch = data.model_dump(exclude_none=True)
    for field, value in patch.items():
        setattr(row, field, value)

    db.commit()
    db.refresh(row)
    log.info("System admin %s updated EngineSettings: %s", current_admin.email, list(patch.keys()))
    return {"message": "Settings updated", "changed": list(patch.keys())}
