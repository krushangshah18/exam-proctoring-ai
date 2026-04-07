import json
import secrets
import time
from typing import List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, BackgroundTasks, status, HTTPException, File, Form, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone, timedelta, UTC
from pydantic import BaseModel

from app.db import models, get_db
from app.db.enums import ExamStatus, UserRole, SessionStatus, ResumeStatus
from app.auth.dependencies import require_role
from app.core import log, system_logger, send_email, settings
from app.exam.schemas import ExamCreateRequest, ExamUpdateRequest, ExamInviteAddRequest, ExamListResponse, ExamDetailResponse
from app.exam.events import push_event_sync

router = APIRouter(prefix="/admin/exams", tags=["Admin Exams"])


# =====================================================
# BACKGROUND EMAIL HELPERS
# All background tasks create their own DB session and
# accept only serialized (non-ORM) data to avoid
# DetachedInstanceError after the request session closes.
# =====================================================

_IST = ZoneInfo("Asia/Kolkata")


def _fmt_email_time(dt: datetime) -> str:
    """
    Format a UTC datetime for email display showing both UTC and IST,
    e.g. "2026-03-25 10:30 UTC  (4:00 PM IST)".
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    utc_str = dt.strftime("%Y-%m-%d %H:%M UTC")
    ist_dt = dt.astimezone(_IST)
    ist_str = ist_dt.strftime("%I:%M %p IST").lstrip("0")
    return f"{utc_str}  ({ist_str})"


def _backfill_missing_proof_sizes(db: Session, session_ids: list) -> None:
    """Populate proof_size_bytes from S3 for older alerts that predate size tracking."""
    if not session_ids:
        return

    from app.core.storage import get_s3_object_size

    missing_alerts = (
        db.query(models.ProctorAlert)
        .filter(
            models.ProctorAlert.session_id.in_(session_ids),
            models.ProctorAlert.proof_s3_key.isnot(None),
            models.ProctorAlert.proof_size_bytes.is_(None),
            (models.ProctorAlert.proof_type.is_(None) | (models.ProctorAlert.proof_type != "audio")),
        )
        .all()
    )

    if not missing_alerts:
        return

    updated = False
    for alert in missing_alerts:
        size = get_s3_object_size(alert.proof_s3_key)
        if size is not None:
            alert.proof_size_bytes = size
            updated = True

    if updated:
        db.commit()


def _send_exam_invites(
    admin_email: str,
    exam_title: str,
    hard_deadline_str: str,
    invite_data: List[dict],
    start_window_str: str = "",
    end_window_str: str = "",
):
    """
    Send invite emails with retry (3 attempts, exponential backoff).
    On persistent failures, notifies the admin.
    invite_data: list of {email: str, token: str}
    start_window_str / end_window_str: pre-formatted UTC+IST strings for the email body.
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
        link = f"{settings.FRONTEND_URL}/student/exam/{inv['token']}/info"
        full_name = user_map.get(email.lower())

        schedule_lines = ""
        if start_window_str:
            schedule_lines += f"  Start : {start_window_str}\n"
        if end_window_str:
            schedule_lines += f"  End   : {end_window_str}\n"
        if hard_deadline_str and hard_deadline_str != "N/A":
            schedule_lines += f"  Join by: {hard_deadline_str}\n"

        if full_name:
            subject = f"You're invited to take an exam: {exam_title}"
            body = (
                f"Hello {full_name},\n\n"
                f"You have been assigned to the exam '{exam_title}'.\n\n"
                f"Exam Schedule (all times shown in UTC and IST):\n"
                f"{schedule_lines}"
                f"\nAccess your exam here: {link}\n\n"
                f"Times above are shown in UTC and IST. Please convert to your local "
                f"timezone if needed.\n\nThank you!"
            )
        else:
            subject = f"Action Required: Exam Invitation for {exam_title}"
            body = (
                f"Hello,\n\n"
                f"You have been assigned to the exam '{exam_title}', but you do not currently "
                f"have an active profile in our system.\n\n"
                f"Exam Schedule (all times shown in UTC and IST):\n"
                f"{schedule_lines}"
                f"\nYour exam link is: {link}\n\n"
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
# DASHBOARD STATS
# =====================================================

@router.get("/stats")
def get_admin_stats(
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """
    Live stats for the exam admin dashboard.
    Scoped to exams created by this admin.
    """
    now = datetime.now(UTC)

    # Exams created by this admin
    my_exam_ids_q = (
        db.query(models.Exam.id)
        .filter(models.Exam.created_by == current_admin.id, models.Exam.is_deleted == False)
        .subquery()
    )

    total_exams = db.query(func.count(models.Exam.id)).filter(
        models.Exam.created_by == current_admin.id, models.Exam.is_deleted == False
    ).scalar() or 0

    live_exams = db.query(func.count(models.Exam.id)).filter(
        models.Exam.created_by == current_admin.id,
        models.Exam.is_deleted == False,
        models.Exam.status == ExamStatus.LIVE.value,
    ).scalar() or 0

    total_sessions = db.query(func.count(models.ExamSession.id)).filter(
        models.ExamSession.exam_id.in_(my_exam_ids_q)
    ).scalar() or 0

    live_sessions = db.query(func.count(models.ExamSession.id)).filter(
        models.ExamSession.exam_id.in_(my_exam_ids_q),
        models.ExamSession.status == SessionStatus.ACTIVE.value,
    ).scalar() or 0

    pending_appeals = db.query(func.count(models.ResumeRequest.id)).join(
        models.ExamSession, models.ExamSession.id == models.ResumeRequest.session_id
    ).filter(
        models.ExamSession.exam_id.in_(my_exam_ids_q),
        models.ResumeRequest.status == ResumeStatus.PENDING.value,
    ).scalar() or 0

    total_students = db.query(func.count(func.distinct(models.ExamInvite.student_email))).filter(
        models.ExamInvite.exam_id.in_(my_exam_ids_q)
    ).scalar() or 0

    return {
        "total_exams": total_exams,
        "live_exams": live_exams,
        "total_sessions": total_sessions,
        "live_sessions": live_sessions,
        "pending_appeals": pending_appeals,
        "total_students": total_students,
    }


@router.get("/pending-appeals")
def get_pending_appeals(
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """
    Return all pending appeals across the current admin's exams.
    Used by the dashboard for a fast-response appeal inbox.
    """
    pending_requests = (
        db.query(models.ResumeRequest, models.ExamSession, models.Exam, models.User)
        .join(models.ExamSession, models.ExamSession.id == models.ResumeRequest.session_id)
        .join(models.Exam, models.Exam.id == models.ExamSession.exam_id)
        .outerjoin(models.User, models.User.id == models.ExamSession.user_id)
        .filter(
            models.ResumeRequest.status == ResumeStatus.PENDING.value,
            models.Exam.created_by == current_admin.id,
            models.Exam.is_deleted == False,
        )
        .order_by(models.ResumeRequest.created_at.desc())
        .all()
    )

    result = []
    for rr, sess, exam, user in pending_requests:
        result.append({
            "resume_request_id": str(rr.id),
            "exam_id": str(exam.id),
            "exam_title": exam.title,
            "session_id": str(sess.id),
            "student_name": user.full_name if user else "Unknown",
            "student_email": user.email if user else "",
            "reason": rr.reason,
            "created_at": rr.created_at,
            "terminated_by": sess.terminated_by,
            "terminated_reason": sess.terminated_reason,
        })

    return result


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

    from app.db.enums import ExamMode as _ExamMode
    end_utc = _utc(data.end_window)
    start_utc_val = _utc(data.start_window)

    if data.exam_mode == _ExamMode.FLEXIBLE:
        # Auto-derive hard_join_deadline = end_window − duration
        computed_hjd = end_utc - timedelta(minutes=data.duration_minutes)
        hard_join_deadline_val = computed_hjd
        allow_late_ext = data.allow_late_extension
        max_late = data.max_late_minutes
    else:  # FIXED
        # end_window must equal start_window + duration
        expected_end = start_utc_val + timedelta(minutes=data.duration_minutes)
        if abs((end_utc - expected_end).total_seconds()) > 60:
            raise HTTPException(status_code=400, detail="FIXED exam: end_window must equal start_window + duration_minutes.")
        if data.hard_join_deadline is None:
            raise HTTPException(status_code=400, detail="FIXED exam: hard_join_deadline is required.")
        hard_join_deadline_val = _utc(data.hard_join_deadline)
        if (hard_join_deadline_val - start_utc_val).total_seconds() < 60:
            raise HTTPException(status_code=400, detail="Hard join deadline must be at least 1 minute after the exam start time.")
        if hard_join_deadline_val >= end_utc:
            raise HTTPException(status_code=400, detail="Hard join deadline must be before the exam end time.")
        allow_late_ext = False
        max_late = 0

    new_exam = models.Exam(
        title=data.title,
        created_by=current_admin.id,
        exam_mode=data.exam_mode.value,
        status=ExamStatus.SCHEDULED.value,
        start_window=start_utc_val,
        end_window=end_utc,
        duration_minutes=data.duration_minutes,
        hard_join_deadline=hard_join_deadline_val,
        flag_threshold=data.flag_threshold,
        late_join_policy=data.late_join_policy.value,
        allow_late_extension=allow_late_ext,
        max_late_minutes=max_late,
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
        _fmt_email_time(new_exam.hard_join_deadline)
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
            _fmt_email_time(new_exam.start_window),
            _fmt_email_time(new_exam.end_window),
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

    # Build email → best session status map
    _STATUS_PRIORITY = {'TERMINATED': 4, 'ENDED': 3, 'ACTIVE': 2, 'CREATED': 1}
    sessions_with_users = (
        db.query(models.ExamSession, models.User)
        .join(models.User, models.User.id == models.ExamSession.user_id)
        .filter(models.ExamSession.exam_id == exam.id)
        .all()
    )
    session_map: dict[str, str] = {}
    for sess, user in sessions_with_users:
        email = user.email.lower()
        existing = session_map.get(email)
        if not existing or _STATUS_PRIORITY.get(sess.status, 0) > _STATUS_PRIORITY.get(existing, 0):
            session_map[email] = sess.status

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
                "session_status": session_map.get(inv.student_email.lower()),
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

    # Block editing within 10 minutes of start
    exam_start_utc = (
        exam.start_window.replace(tzinfo=UTC)
        if exam.start_window.tzinfo is None
        else exam.start_window
    )
    if exam_start_utc <= datetime.now(UTC) + timedelta(minutes=10):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot edit exam within 10 minutes of its scheduled start time.",
        )

    def _utc(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)

    from app.db.enums import ExamMode as _ExamMode
    new_start = _utc(data.start_window)
    new_end = _utc(data.end_window)

    if data.exam_mode == _ExamMode.FLEXIBLE:
        new_deadline = new_end - timedelta(minutes=data.duration_minutes)
        new_allow_late_ext = data.allow_late_extension
        new_max_late = data.max_late_minutes
    else:  # FIXED
        expected_end = new_start + timedelta(minutes=data.duration_minutes)
        if abs((new_end - expected_end).total_seconds()) > 60:
            raise HTTPException(status_code=400, detail="FIXED exam: end_window must equal start_window + duration_minutes.")
        if data.hard_join_deadline is None:
            raise HTTPException(status_code=400, detail="FIXED exam: hard_join_deadline is required.")
        new_deadline = _utc(data.hard_join_deadline)
        if (new_deadline - new_start).total_seconds() < 60:
            raise HTTPException(status_code=400, detail="Hard join deadline must be at least 1 minute after the exam start time.")
        if new_deadline >= new_end:
            raise HTTPException(status_code=400, detail="Hard join deadline must be before the exam end time.")
        new_allow_late_ext = False
        new_max_late = 0

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
    exam.allow_late_extension = new_allow_late_ext
    exam.max_late_minutes = new_max_late
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
        _fmt_email_time(new_deadline) if new_deadline else "N/A"
    )

    if new_invite_data:
        background_tasks.add_task(
            _send_exam_invites,
            current_admin.email,
            exam.title,
            hard_deadline_str,
            new_invite_data,
            _fmt_email_time(new_start),
            _fmt_email_time(new_end),
        )

    if schedule_changed:
        existing_emails = list(new_email_set - emails_to_add)
        if existing_emails:
            background_tasks.add_task(
                _send_schedule_update_emails, exam.title, existing_emails
            )

    log.info("Exam '%s' updated by %s.", exam.title, current_admin.email)
    return {"message": "Exam updated successfully."}


@router.post("/{exam_id}/students")
def add_exam_students(
    exam_id: str,
    data: ExamInviteAddRequest,
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

    if exam.status in (ExamStatus.ENDED.value, ExamStatus.CANCELLED.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot add students to an exam with status '{exam.status}'.",
        )

    current_invites = (
        db.query(models.ExamInvite).filter(models.ExamInvite.exam_id == exam.id).all()
    )
    existing_emails = {inv.student_email.lower() for inv in current_invites}
    requested_emails = set(data.invites)
    emails_to_add = requested_emails - existing_emails

    if not emails_to_add:
        return {
            "message": "All provided students are already assigned to this exam.",
            "added_count": 0,
            "skipped_count": len(requested_emails),
        }

    exam_end = exam.end_window.replace(tzinfo=UTC) if exam.end_window.tzinfo is None else exam.end_window
    invite_data: List[dict] = []
    for email in emails_to_add:
        token = secrets.token_urlsafe(32)
        db.add(
            models.ExamInvite(
                exam_id=exam.id,
                student_email=email,
                token=token,
                expires_at=exam_end,
                used=False,
            )
        )
        invite_data.append({"email": email, "token": token})

    db.commit()

    hard_deadline = exam.hard_join_deadline if exam.hard_join_deadline else exam.end_window
    hard_deadline_str = _fmt_email_time(hard_deadline)

    background_tasks.add_task(
        _send_exam_invites,
        current_admin.email,
        exam.title,
        hard_deadline_str,
        invite_data,
        _fmt_email_time(exam.start_window),
        _fmt_email_time(exam.end_window),
    )

    log.info(
        "Added %d students to exam '%s' by %s.",
        len(invite_data),
        exam.title,
        current_admin.email,
    )
    return {
        "message": f"Added {len(invite_data)} student{'s' if len(invite_data) != 1 else ''}. Invite emails are being sent.",
        "added_count": len(invite_data),
        "skipped_count": len(requested_emails) - len(invite_data),
    }


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
    Return all sessions for an exam with student info, status, and risk.
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
            "last_heartbeat": sess.last_heartbeat,
            "terminated_reason": sess.terminated_reason,
            "terminated_by": sess.terminated_by,
            "time_extension_seconds": sess.time_extension_seconds or 0,
            "has_pending_appeal": pending_appeal is not None,
            "proctor_engine_url": sess.proctor_engine_url,
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

        # Derive termination type from terminated_by field
        terminated_by = sess.terminated_by if sess else None
        if terminated_by == "SYSTEM_DISCONNECT":
            termination_type = "DISCONNECT"
        elif terminated_by == "ADMIN":
            termination_type = "ADMIN"
        elif terminated_by and terminated_by.startswith("SYSTEM"):
            termination_type = "SYSTEM"
        else:
            termination_type = "LATE_JOIN"   # no session or no terminated_by → late join appeal

        # For disconnect type, suggest extension = time from last_heartbeat to now (at review time)
        suggested_extension_minutes = None
        if termination_type == "DISCONNECT" and sess and sess.last_heartbeat:
            lh = sess.last_heartbeat.replace(tzinfo=UTC) if sess.last_heartbeat.tzinfo is None else sess.last_heartbeat
            lost_seconds = max(0, int((datetime.now(UTC) - lh).total_seconds()))
            suggested_extension_minutes = max(1, round(lost_seconds / 60))

        # How long after disconnect the student filed the appeal (or it was auto-created)
        time_since_disconnect_seconds = None
        if sess and sess.last_heartbeat and rr.created_at:
            lh = sess.last_heartbeat.replace(tzinfo=UTC) if sess.last_heartbeat.tzinfo is None else sess.last_heartbeat
            rr_created = rr.created_at.replace(tzinfo=UTC) if rr.created_at.tzinfo is None else rr.created_at
            time_since_disconnect_seconds = max(0, int((rr_created - lh).total_seconds()))

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
            "termination_type": termination_type,
            "suggested_extension_minutes": suggested_extension_minutes,
            "time_since_disconnect_seconds": time_since_disconnect_seconds,
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
        # Fix B: keep the terminated session intact (preserves its alerts/proofs as a
        # clean separate report), and create a NEW ExamSession so the next attempt
        # gets its own session_id. The student's SSE is still subscribed to the OLD
        # session_id at this point, so we push RESUME_APPROVED there first.
        added_extension_seconds = 0
        if data.time_extension_minutes and data.time_extension_minutes > 0:
            added_extension_seconds = data.time_extension_minutes * 60

        new_extension_s = (sess.time_extension_seconds or 0) + added_extension_seconds

        new_sess = models.ExamSession(
            user_id                = sess.user_id,
            exam_id                = sess.exam_id,
            status                 = SessionStatus.CREATED.value,
            start_time             = sess.start_time,   # preserve original start (timer continuity)
            risk_score             = sess.risk_score,   # carry forward existing risk score
            time_extension_seconds = new_extension_s,
            device_fingerprint     = sess.device_fingerprint,
            ip_address             = sess.ip_address,
        )
        db.add(new_sess)

        event_type = "RESUME_APPROVED"
        event_data = {
            "review_note": data.review_note,
            "time_extension_minutes": data.time_extension_minutes,
            "time_extension_seconds": new_extension_s,
        }
    else:
        # DENIED — permanently close the session so no ghost sessions remain.
        sess.status = SessionStatus.ENDED.value
        sess.end_time = datetime.now(UTC)

        event_type = "RESUME_DENIED"
        event_data = {"review_note": data.review_note}

    db.commit()

    # Push SSE event to the ORIGINAL (terminated) session — the student's browser
    # is still subscribed to that session_id while waiting on the terminated page.
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
    from app.db.enums import ExamMode as _ExamMode
    if exam.exam_mode == _ExamMode.FIXED.value:
        raise HTTPException(status_code=400, detail="Time extensions are not allowed for FIXED mode exams.")

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
    from app.db.enums import ExamMode as _ExamMode
    if exam.exam_mode == _ExamMode.FIXED.value:
        raise HTTPException(status_code=400, detail="Time extensions are not allowed for FIXED mode exams.")

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


@router.post("/{exam_id}/sessions/{session_id}/terminate")
async def terminate_session(
    exam_id: str,
    session_id: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """
    Admin manually terminates a student session.
    Pushes a TERMINATED SSE event to the student's active page.
    """
    exam = (
        db.query(models.Exam)
        .filter(
            models.Exam.id == exam_id,
            models.Exam.is_deleted == False,
        )
        .first()
    )
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    sess = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id,
        models.ExamSession.exam_id == exam_id,
        models.ExamSession.status.in_([
            SessionStatus.ACTIVE.value,
            SessionStatus.DISCONNECTED.value,
        ]),
    ).first()
    if not sess:
        raise HTTPException(status_code=404, detail="No active or disconnected session found")

    sess.status = SessionStatus.TERMINATED.value
    sess.terminated_by = "ADMIN"
    sess.terminated_reason = "Session terminated by exam proctor due to high risk score"
    sess.terminated_at = datetime.now(UTC)
    sess.end_time = sess.end_time or sess.terminated_at
    db.commit()

    push_event_sync(str(sess.id), "TERMINATED", {
        "terminated_by": "ADMIN",
        "terminated_reason": sess.terminated_reason,
    })

    # Best-effort: pull final risk score and report ID from engine
    if sess.proctor_pc_id and sess.proctor_engine_url:
        from app.exam.proctor_proxy import fetch_session_log as _fetch_log
        try:
            log_data = await _fetch_log(sess.proctor_engine_url, sess.proctor_pc_id)
            risk = log_data.get("risk", {})
            final_score = risk.get("final_score") or risk.get("score") or log_data.get("final_score")
            if final_score is not None:
                sess.risk_score = int(final_score)
            report_id = log_data.get("report_id") or log_data.get("session_id") or log_data.get("id")
            if report_id:
                sess.proctor_report_id = str(report_id)
            db.commit()
            log.info(
                "Admin terminate: pulled engine report session=%s score=%s report_id=%s",
                session_id, sess.risk_score, sess.proctor_report_id,
            )
        except Exception as _e:
            log.warning("Admin terminate: could not pull engine report (session=%s): %s", session_id, _e)

    log.info(
        "Admin %s manually terminated session %s (exam %s, risk_score=%s)",
        current_admin.email, session_id, exam_id, sess.risk_score,
    )
    return {"message": "Session terminated successfully"}


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
        # Student hasn't established WebRTC connection yet — not an error, just no frame
        return _Response(content=b"", status_code=204, media_type="image/jpeg")

    try:
        jpeg_bytes = await fetch_snapshot(session.proctor_engine_url, session.proctor_pc_id)
    except Exception as e:
        log.warning(
            "admin_live_frame: engine snapshot fetch failed exam_id=%s session_id=%s pc_id=%s: %s",
            exam_id,
            session_id,
            session.proctor_pc_id,
            e,
        )
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
    SSE proxy from the engine — streams live risk alerts to the admin monitor panel.
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
        # Student hasn't connected to engine yet — send keepalive stream so the
        # admin SSE client stays connected and can reconnect when ready
        import asyncio as _asyncio
        async def _waiting_stream():
            while True:
                yield ': waiting\n\n'
                await _asyncio.sleep(5)
        return _SR(
            _waiting_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # Wrap the engine SSE stream so we can intercept session_end and persist
    # the report_id to the DB — this ensures alert-history works after the session ends.
    engine_url_snap = session.proctor_engine_url
    pc_id_snap = session.proctor_pc_id
    session_id_snap = str(session.id)

    async def _intercepting_stream():
        import json as _json
        from sqlalchemy.orm import Session as _DBSession
        from app.db.session import SessionLocal as _SessionLocal

        async for chunk in stream_engine_events(engine_url_snap, pc_id_snap):
            yield chunk
            # Check if this chunk contains a session_end event
            if "session_end" in chunk:
                try:
                    # Extract the data line from the SSE chunk
                    for line in chunk.split("\n"):
                        if line.startswith("data:"):
                            payload = _json.loads(line[5:].strip())
                            if payload.get("type") == "session_end":
                                report_id = payload.get("report_id")
                                if report_id:
                                    _db: _DBSession = _SessionLocal()
                                    try:
                                        _sess = _db.query(models.ExamSession).filter(
                                            models.ExamSession.id == session_id_snap
                                        ).first()
                                        if _sess and not _sess.proctor_report_id:
                                            _sess.proctor_report_id = str(report_id)
                                            _db.commit()
                                            log.info(
                                                "live-stream: saved proctor_report_id=%s for session=%s",
                                                report_id, session_id_snap,
                                            )
                                    finally:
                                        _db.close()
                            break
                except Exception as _exc:
                    log.warning("live-stream: session_end intercept error: %s", _exc)

    return _SR(
        _intercepting_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/{exam_id}/sessions/{session_id}/alert-history")
async def get_session_alert_history(
    exam_id: str,
    session_id: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role("ADMIN")),
):
    """
    Return the full alert + warning history for a session.

    Primary source: proctor_alerts / proctor_warnings tables (written by engine directly to RDS).
    Fallback: engine HTTP polling (for sessions that ran before the RDS integration was deployed).
    """
    from app.core import log as _log

    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id,
        models.ExamSession.exam_id == exam_id,
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # ── Primary path: query RDS directly ─────────────────────────────────────
    db_alerts = (
        db.query(models.ProctorAlert)
        .filter(models.ProctorAlert.session_id == session_id)
        .order_by(models.ProctorAlert.occurred_at.desc())
        .all()
    )
    db_warnings = (
        db.query(models.ProctorWarning)
        .filter(models.ProctorWarning.session_id == session_id)
        .order_by(models.ProctorWarning.occurred_at.desc())
        .all()
    )

    if db_alerts or db_warnings:
        alerts = [
            {
                "message"    : a.message,
                "proof_url"  : None,            # presigned URL generated on demand via /proof endpoint
                "proof_s3_key": a.proof_s3_key,
                "proof_type" : a.proof_type or "image",
                "score_added": a.score_added,
                "elapsed_s"  : a.elapsed_s,
                "time"       : a.time_str or "",
            }
            for a in db_alerts
        ]
        warnings = [
            {
                "message"  : w.message,
                "elapsed_s": w.elapsed_s,
                "time"     : w.time_str or "",
            }
            for w in db_warnings
        ]
        return {"alerts": alerts, "warnings": warnings}

    # ── Fallback: engine HTTP polling (pre-RDS sessions) ─────────────────────
    # This block can be removed once all sessions use the RDS path.
    if not session.proctor_pc_id or not session.proctor_engine_url:
        return {"alerts": [], "warnings": []}

    from app.exam.proctor_proxy import fetch_session_log
    import httpx as _httpx

    def _parse_engine_log(log_data: dict):
        alerts = [
            {
                "message"    : e.get("message", "Alert"),
                "proof_url"  : e.get("proof_url"),
                "proof_s3_key": None,
                "proof_type" : e.get("proof_type", "image"),
                "score_added": e.get("score_added") or e.get("risk_delta") or 0,
                "elapsed_s"  : e.get("elapsed_s", 0),
                "time"       : e.get("time", ""),
            }
            for e in log_data.get("alert_log", [])
        ]
        warnings = [
            {
                "message"  : e.get("message", "Warning"),
                "elapsed_s": e.get("elapsed_s", 0),
                "time"     : e.get("time", ""),
            }
            for e in log_data.get("warning_log", [])
        ]
        return list(reversed(alerts)), list(reversed(warnings))

    async def _fetch_engine_report(engine_url: str, rid: str) -> dict | None:
        try:
            async with _httpx.AsyncClient(timeout=_httpx.Timeout(connect=4.0, read=15.0, write=4.0, pool=4.0)) as client:
                r = await client.get(f"{engine_url}/report/{rid}")
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            _log.warning("alert-history[fallback] report fetch failed (rid=%s): %s", rid, exc)
            return None

    # Try live session log first
    try:
        log_data = await fetch_session_log(session.proctor_engine_url, session.proctor_pc_id)
        alerts, warnings = _parse_engine_log(log_data)
        if alerts or warnings:
            return {"alerts": alerts, "warnings": warnings}
    except Exception as e:
        _log.info("alert-history[fallback] session_log unavailable (pc_id=%s): %s", session.proctor_pc_id, e)

    # Try known report_id
    if session.proctor_report_id:
        data = await _fetch_engine_report(session.proctor_engine_url, session.proctor_report_id)
        if data:
            alerts, warnings = _parse_engine_log(data)
            return {"alerts": alerts, "warnings": warnings}

    _log.warning("alert-history: no data for session=%s (no RDS rows, engine unreachable)", session_id)
    return {"alerts": [], "warnings": []}


@router.get("/{exam_id}/sessions/{session_id}/proof-url")
async def get_proof_presigned_url(
    exam_id: str,
    session_id: str,
    s3_key: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role("ADMIN")),
):
    """
    Generate a presigned S3 URL for a proof image or audio file.
    The s3_key comes from proctor_alerts.proof_s3_key.
    URL is valid for 1 hour.
    """
    import os
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    bucket = os.getenv("S3_BUCKET", "")
    if not bucket:
        raise HTTPException(status_code=503, detail="S3 not configured")

    # Verify the alert belongs to this session (security check)
    alert = db.query(models.ProctorAlert).filter(
        models.ProctorAlert.session_id == session_id,
        models.ProctorAlert.proof_s3_key == s3_key,
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Proof not found")

    try:
        s3 = boto3.client(
            "s3",
            region_name=os.getenv("AWS_REGION", "ap-south-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": s3_key},
            ExpiresIn=3600,
        )
        return {"url": url, "expires_in": 3600}
    except (BotoCoreError, ClientError) as e:
        log.warning(
            "get_proof_presigned_url: S3 presigned URL failed exam_id=%s session_id=%s s3_key=%s error=%s",
            exam_id,
            session_id,
            s3_key,
            e,
        )
        raise HTTPException(status_code=502, detail=f"S3 presigned URL failed: {e}")


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
        log.warning(
            "admin_debug_mode: engine debug toggle failed exam_id=%s session_id=%s pc_id=%s enabled=%s: %s",
            exam_id,
            session_id,
            session.proctor_pc_id,
            body.enabled,
            e,
        )
        raise HTTPException(status_code=502, detail=f"Engine debug toggle failed: {e}")

    return result


# =====================================================
# EXAM ADMIN — SESSION REPORTS
# =====================================================

@router.get("/{exam_id}/reports")
def list_exam_reports(
    exam_id: str,
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """
    List session reports for a specific exam (sourced from RDS).
    Returns one row per completed/terminated session with alert/warning counts.
    """
    from sqlalchemy import func as _sqlfunc

    # Sysadmin can view all exams; admin can only view their own
    exam_filter = [
        models.Exam.id == exam_id,
        models.Exam.is_deleted == False,
    ]
    if getattr(current_admin, "role", None) != "SYSADMIN":
        exam_filter.append(models.Exam.created_by == current_admin.id)

    exam = db.query(models.Exam).filter(*exam_filter).first()
    if not exam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")

    sessions = (
        db.query(models.ExamSession)
        .filter(models.ExamSession.exam_id == exam_id)
        .order_by(models.ExamSession.created_at.desc())
        .all()
    )

    if not sessions:
        return []

    _backfill_missing_proof_sizes(db, [s.id for s in sessions])

    user_ids = [s.user_id for s in sessions]
    users = {str(u.id): u for u in db.query(models.User).filter(models.User.id.in_(user_ids)).all()}

    session_ids = [s.id for s in sessions]

    alert_counts: dict = dict(
        db.query(models.ProctorAlert.session_id, _sqlfunc.count())
        .filter(models.ProctorAlert.session_id.in_(session_ids))
        .group_by(models.ProctorAlert.session_id).all()
    )
    warning_counts: dict = dict(
        db.query(models.ProctorWarning.session_id, _sqlfunc.count())
        .filter(models.ProctorWarning.session_id.in_(session_ids))
        .group_by(models.ProctorWarning.session_id).all()
    )
    proof_counts: dict = dict(
        db.query(models.ProctorAlert.session_id, _sqlfunc.count())
        .filter(
            models.ProctorAlert.session_id.in_(session_ids),
            models.ProctorAlert.proof_s3_key.isnot(None),
        )
        .group_by(models.ProctorAlert.session_id).all()
    )
    proof_size_bytes: dict = dict(
        db.query(
            models.ProctorAlert.session_id,
            _sqlfunc.coalesce(_sqlfunc.sum(models.ProctorAlert.proof_size_bytes), 0),
        )
        .filter(
            models.ProctorAlert.session_id.in_(session_ids),
            models.ProctorAlert.proof_s3_key.isnot(None),
            (models.ProctorAlert.proof_type.is_(None) | (models.ProctorAlert.proof_type != "audio")),
        )
        .group_by(models.ProctorAlert.session_id)
        .all()
    )

    report_rows = []
    for s in sessions:
        user = users.get(str(s.user_id))
        effective_end = s.end_time or s.terminated_at
        student_name = None
        if user:
            fn = getattr(user, "first_name", None) or ""
            ln = getattr(user, "last_name",  None) or ""
            student_name = f"{fn} {ln}".strip() or getattr(user, "full_name", None) or user.email

        duration_s = (
            max(0, int(round((effective_end - s.start_time).total_seconds())))
            if s.start_time and effective_end else None
        )

        report_rows.append({
            "row_id":           str(s.id),
            "session_id":       str(s.id),
            "report_id":        str(s.id),      # session UUID is the report ID for RDS reports
            "engine_url":       s.proctor_engine_url or "",
            "student_name":     student_name or "Unknown",
            "student_email":    user.email if user else "",
            "session_status":   s.status,
            "terminated_by":    s.terminated_by,
            "terminated_reason": s.terminated_reason,
            "risk_score":       s.risk_score or 0,
            "start_time":       s.start_time.isoformat() if s.start_time else None,
            "end_time":         effective_end.isoformat() if effective_end else None,
            "risk_state":       s.status,
            "final_score":      s.risk_score,
            "alert_count":      alert_counts.get(s.id, 0),
            "warning_count":    warning_counts.get(s.id, 0),
            "proof_count":      proof_counts.get(s.id, 0),
            "size_kb":          round((proof_size_bytes.get(s.id, 0) or 0) / 1024, 1),
            "duration_s":       duration_s,
            "terminated":       s.status == "TERMINATED",
        })

    return report_rows


@router.get("/{exam_id}/sessions/{session_id}/report/full")
def get_exam_session_full_report(
    exam_id: str,
    session_id: str,
    report_id: str | None = None,   # kept for API compat, ignored (session_id is used)
    engine_url: str | None = None,  # kept for API compat, ignored
    db: Session = Depends(get_db),
    current_admin=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """Return full report for an exam session from RDS (alerts, warnings, S3 proof URLs)."""
    import uuid as _uuid
    from app.core.storage import get_profile_image_url as _presign

    # Sysadmin can view all exams; admin can only view their own
    exam_filter = [
        models.Exam.id == exam_id,
        models.Exam.is_deleted == False,
    ]
    if getattr(current_admin, "role", None) != "SYSADMIN":
        exam_filter.append(models.Exam.created_by == current_admin.id)

    exam = db.query(models.Exam).filter(*exam_filter).first()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    try:
        session_uuid = _uuid.UUID(session_id)
    except ValueError:
        log.warning(
            "get_exam_session_full_report: invalid session_id exam_id=%s session_id=%s",
            exam_id,
            session_id,
        )
        raise HTTPException(status_code=400, detail="Invalid session ID")

    sess = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_uuid,
        models.ExamSession.exam_id == exam_id,
    ).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    _backfill_missing_proof_sizes(db, [sess.id])

    effective_end = sess.end_time or sess.terminated_at
    duration_s = (
        max(0, int(round((effective_end - sess.start_time).total_seconds())))
        if sess.start_time and effective_end else None
    )

    alert_log = []
    for a in sess.proctor_alerts:
        entry: dict = {
            "_type":       "alert",
            "key":         a.alert_key,
            "message":     a.message,
            "score_added": a.score_added,
            "elapsed_s":   a.elapsed_s,
            "time":        a.time_str,
        }
        if a.proof_s3_key:
            url = _presign(a.proof_s3_key, expires_in=3600)
            if url:
                entry["proof_url"]  = url
                entry["proof_type"] = a.proof_type or "image"
        alert_log.append(entry)

    warning_log = [
        {
            "_type":     "warning",
            "message":   w.message,
            "elapsed_s": w.elapsed_s,
            "time":      w.time_str,
        }
        for w in sess.proctor_warnings
    ]

    return {
        "report_id":     session_id,
        "risk_state":    sess.status,
        "final_score":   sess.risk_score,
        "alert_count":   len(alert_log),
        "warning_count": len(warning_log),
        "size_kb":       round(
            sum(
                (a.proof_size_bytes or 0)
                for a in sess.proctor_alerts
                if a.proof_s3_key and (a.proof_type or "image") != "audio"
            ) / 1024,
            1,
        ),
        "proof_count":   sum(1 for a in sess.proctor_alerts if a.proof_s3_key),
        "duration_s":    duration_s,
        "terminated":    sess.status == "TERMINATED",
        "session_start": sess.start_time.isoformat() if sess.start_time else None,
        "session_end":   effective_end.isoformat() if effective_end else None,
        "alert_log":     alert_log,
        "warning_log":   warning_log,
    }


# =====================================================
# SYSTEM ADMIN — ENGINE SETTINGS
# =====================================================

_system_settings_router = APIRouter(prefix="/admin", tags=["System Admin"])
_model_tuning_sessions: dict[str, dict] = {}


class EngineSettingsUpdate(BaseModel):
    # Detection toggles
    detect_looking_away: bool | None = None
    detect_looking_down: bool | None = None
    detect_looking_up: bool | None = None
    detect_looking_side: bool | None = None
    detect_face_hidden: bool | None = None
    detect_partial_face: bool | None = None
    detect_fake_presence: bool | None = None
    detect_speaker_audio: bool | None = None
    detect_phone: bool | None = None
    detect_book: bool | None = None
    detect_headphone: bool | None = None
    detect_earbud: bool | None = None
    detect_multiple_people: bool | None = None
    # Head pose
    look_away_yaw: float | None = None
    look_down_pitch: float | None = None
    look_up_pitch: float | None = None
    gaze_left: float | None = None
    gaze_right: float | None = None
    min_face_width: int | None = None
    min_face_height: int | None = None
    face_hidden_recency_s: float | None = None
    # Duration gates
    looking_away_threshold: float | None = None
    gaze_threshold: float | None = None
    fake_window: float | None = None
    partial_face_duration_gate: float | None = None
    face_hidden_dur_1: float | None = None
    face_hidden_dur_2: float | None = None
    no_person_dur_1: float | None = None
    no_person_dur_2: float | None = None
    fake_presence_dur_1: float | None = None
    fake_presence_dur_2: float | None = None
    # Risk scores
    gaze_score: float | None = None
    partial_face_score: float | None = None
    face_hidden_score_1: float | None = None
    face_hidden_score_2: float | None = None
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
    # Score cooldowns
    score_cd_looking_away: float | None = None
    score_cd_looking_down: float | None = None
    score_cd_looking_up: float | None = None
    score_cd_looking_side: float | None = None
    score_cd_partial_face: float | None = None
    score_cd_face_hidden: float | None = None
    score_cd_fake_presence: float | None = None
    score_cd_phone: float | None = None
    score_cd_multiple_people: float | None = None
    score_cd_no_person: float | None = None
    score_cd_book: float | None = None
    score_cd_headphone: float | None = None
    score_cd_earbud: float | None = None
    score_cd_speaker_audio: float | None = None
    # Warning cooldowns
    warn_cd_looking_away: float | None = None
    warn_cd_looking_down: float | None = None
    warn_cd_looking_up: float | None = None
    warn_cd_looking_side: float | None = None
    warn_cd_partial_face: float | None = None
    warn_cd_face_hidden: float | None = None
    warn_cd_fake_presence: float | None = None
    warn_cd_phone: float | None = None
    warn_cd_multiple_people: float | None = None
    warn_cd_no_person: float | None = None
    warn_cd_book: float | None = None
    warn_cd_headphone: float | None = None
    warn_cd_earbud: float | None = None
    warn_cd_speaker_audio: float | None = None
    # Speaker audio
    speaker_warn_cooldown: float | None = None
    speaker_alert_cooldown: float | None = None
    speaker_occ1_warn_s: float | None = None
    speaker_occ1_score: float | None = None
    speaker_occ1_repeat: float | None = None
    speaker_occ2_warn_s: float | None = None
    speaker_occ2_score: float | None = None
    speaker_occ2_repeat: float | None = None
    speaker_repeat_interval: float | None = None
    # Identity verification
    identity_check_count: int | None = None
    identity_check_retries: int | None = None
    identity_check_retry_delay: float | None = None
    # Object detection temporal voting
    phone_min_votes: int | None = None
    book_min_votes: int | None = None
    headphone_min_votes: int | None = None
    earbud_min_votes: int | None = None
    object_min_votes: int | None = None
    object_window: int | None = None


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
        # Detection toggles
        "detect_looking_away":        row.detect_looking_away,
        "detect_looking_down":        row.detect_looking_down,
        "detect_looking_up":          row.detect_looking_up,
        "detect_looking_side":        row.detect_looking_side,
        "detect_face_hidden":         row.detect_face_hidden,
        "detect_partial_face":        row.detect_partial_face,
        "detect_fake_presence":       row.detect_fake_presence,
        "detect_speaker_audio":       row.detect_speaker_audio,
        "detect_phone":               row.detect_phone,
        "detect_book":                row.detect_book,
        "detect_headphone":           row.detect_headphone,
        "detect_earbud":              row.detect_earbud,
        "detect_multiple_people":     row.detect_multiple_people,
        # Head pose
        "look_away_yaw":              row.look_away_yaw,
        "look_down_pitch":            row.look_down_pitch,
        "look_up_pitch":              row.look_up_pitch,
        "gaze_left":                  row.gaze_left,
        "gaze_right":                 row.gaze_right,
        "min_face_width":             row.min_face_width,
        "min_face_height":            row.min_face_height,
        "face_hidden_recency_s":      row.face_hidden_recency_s,
        # Duration gates
        "looking_away_threshold":     row.looking_away_threshold,
        "gaze_threshold":             row.gaze_threshold,
        "fake_window":                row.fake_window,
        "partial_face_duration_gate": row.partial_face_duration_gate,
        "face_hidden_dur_1":          row.face_hidden_dur_1,
        "face_hidden_dur_2":          row.face_hidden_dur_2,
        "no_person_dur_1":            row.no_person_dur_1,
        "no_person_dur_2":            row.no_person_dur_2,
        "fake_presence_dur_1":        row.fake_presence_dur_1,
        "fake_presence_dur_2":        row.fake_presence_dur_2,
        # Risk scores
        "gaze_score":                 row.gaze_score,
        "partial_face_score":         row.partial_face_score,
        "face_hidden_score_1":        row.face_hidden_score_1,
        "face_hidden_score_2":        row.face_hidden_score_2,
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
        # State thresholds
        "state_warning":              row.state_warning,
        "state_high_risk":            row.state_high_risk,
        "state_admin_review":         row.state_admin_review,
        "decay_amount":               row.decay_amount,
        # Termination
        "tab_switch_terminate_count": row.tab_switch_terminate_count,
        "multi_people_terminate_s":   row.multi_people_terminate_s,
        "no_person_terminate_s":      row.no_person_terminate_s,
        # YOLO confidence
        "yolo_phone_conf":            row.yolo_phone_conf,
        "yolo_book_conf":             row.yolo_book_conf,
        "yolo_audio_conf":            row.yolo_audio_conf,
        "yolo_person_conf":           row.yolo_person_conf,
        # Score cooldowns
        "score_cd_looking_away":      row.score_cd_looking_away,
        "score_cd_looking_down":      row.score_cd_looking_down,
        "score_cd_looking_up":        row.score_cd_looking_up,
        "score_cd_looking_side":      row.score_cd_looking_side,
        "score_cd_partial_face":      row.score_cd_partial_face,
        "score_cd_face_hidden":       row.score_cd_face_hidden,
        "score_cd_fake_presence":     row.score_cd_fake_presence,
        "score_cd_phone":             row.score_cd_phone,
        "score_cd_multiple_people":   row.score_cd_multiple_people,
        "score_cd_no_person":         row.score_cd_no_person,
        "score_cd_book":              row.score_cd_book,
        "score_cd_headphone":         row.score_cd_headphone,
        "score_cd_earbud":            row.score_cd_earbud,
        "score_cd_speaker_audio":     row.score_cd_speaker_audio,
        # Warning cooldowns
        "warn_cd_looking_away":       row.warn_cd_looking_away,
        "warn_cd_looking_down":       row.warn_cd_looking_down,
        "warn_cd_looking_up":         row.warn_cd_looking_up,
        "warn_cd_looking_side":       row.warn_cd_looking_side,
        "warn_cd_partial_face":       row.warn_cd_partial_face,
        "warn_cd_face_hidden":        row.warn_cd_face_hidden,
        "warn_cd_fake_presence":      row.warn_cd_fake_presence,
        "warn_cd_phone":              row.warn_cd_phone,
        "warn_cd_multiple_people":    row.warn_cd_multiple_people,
        "warn_cd_no_person":          row.warn_cd_no_person,
        "warn_cd_book":               row.warn_cd_book,
        "warn_cd_headphone":          row.warn_cd_headphone,
        "warn_cd_earbud":             row.warn_cd_earbud,
        "warn_cd_speaker_audio":      row.warn_cd_speaker_audio,
        # Speaker audio
        "speaker_warn_cooldown":      row.speaker_warn_cooldown,
        "speaker_alert_cooldown":     row.speaker_alert_cooldown,
        "speaker_occ1_warn_s":        row.speaker_occ1_warn_s,
        "speaker_occ1_score":         row.speaker_occ1_score,
        "speaker_occ1_repeat":        row.speaker_occ1_repeat,
        "speaker_occ2_warn_s":        row.speaker_occ2_warn_s,
        "speaker_occ2_score":         row.speaker_occ2_score,
        "speaker_occ2_repeat":        row.speaker_occ2_repeat,
        "speaker_repeat_interval":    row.speaker_repeat_interval,
        # Identity verification
        "identity_check_count":       row.identity_check_count,
        "identity_check_retries":     row.identity_check_retries,
        "identity_check_retry_delay": row.identity_check_retry_delay,
        # Object detection temporal voting
        "phone_min_votes":            row.phone_min_votes,
        "book_min_votes":             row.book_min_votes,
        "headphone_min_votes":        row.headphone_min_votes,
        "earbud_min_votes":           row.earbud_min_votes,
        "object_min_votes":           row.object_min_votes,
        "object_window":              row.object_window,
        "updated_at":                 row.created_at.isoformat() if row.created_at else None,
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


class ModelTuningSessionCreate(BaseModel):
    container_id: str | None = None
    overrides: dict | None = None


@_system_settings_router.post("/model-tuning/sessions")
async def create_model_tuning_session(
    body: ModelTuningSessionCreate,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    from app.exam.proctor_proxy import create_calibration_session as _create_calibration_session

    settings_row = db.query(models.EngineSettings).first()
    if not settings_row:
        raise HTTPException(status_code=404, detail="Engine settings not initialised")

    query = db.query(models.EngineContainer).filter(models.EngineContainer.is_active == True)
    if body.container_id:
        query = query.filter(models.EngineContainer.id == body.container_id)
    container = query.order_by(models.EngineContainer.created_at.asc()).first()
    if not container:
        raise HTTPException(status_code=404, detail="No active engine container available")

    config = _build_model_tuning_config(settings_row, body.overrides)
    try:
        created = await _create_calibration_session(container.url, config=config)
    except Exception as exc:
        import httpx as _httpx
        if isinstance(exc, _httpx.HTTPStatusError) and exc.response.status_code == 409:
            raise HTTPException(
                status_code=409,
                detail="Cannot start model tuning: exam sessions are currently active on this engine. Wait for all exams to finish.",
            )
        log.warning(
            "create_model_tuning_session: engine calibration session failed container_url=%s: %s",
            container.url,
            exc,
        )
        raise HTTPException(status_code=502, detail=f"Engine calibration session failed: {exc}")

    session_id = secrets.token_urlsafe(18)
    _model_tuning_sessions[session_id] = {
        "engine_url": container.url,
        "engine_session_id": created.get("session_id"),
        "container_id": str(container.id),
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    return {
        "session_id": session_id,
        "engine_session_id": created.get("session_id"),
        "engine": {
            "container_id": str(container.id),
            "container_name": container.container_name,
            "url": container.url,
        },
        "tick_rate_hz": created.get("tick_rate_hz"),
        "object_window_frames": created.get("object_window_frames"),
        "object_vote_targets": created.get("object_vote_targets", {}),
    }


@_system_settings_router.post("/model-tuning/sessions/{session_id}/frame")
async def process_model_tuning_frame(
    session_id: str,
    frame: UploadFile = File(...),
    config_json: str = Form("{}"),
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    from app.exam.proctor_proxy import process_calibration_frame as _process_calibration_frame

    state = _model_tuning_sessions.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Model tuning session not found")

    settings_row = db.query(models.EngineSettings).first()
    if not settings_row:
        raise HTTPException(status_code=404, detail="Engine settings not initialised")

    try:
        overrides = json.loads(config_json or "{}")
    except Exception as exc:
        system_logger.warning(
            "process_model_tuning_frame: invalid config_json session_id=%s engine_session_id=%s error=%s",
            session_id,
            state.get("engine_session_id"),
            exc,
        )
        raise HTTPException(status_code=400, detail=f"Invalid config JSON: {exc}")

    config = _build_model_tuning_config(settings_row, overrides)
    image_bytes = await frame.read()
    state["updated_at"] = time.time()
    try:
        result = await _process_calibration_frame(
            state["engine_url"],
            state["engine_session_id"],
            image_bytes=image_bytes,
            config=config,
            filename=frame.filename or "frame.jpg",
        )
    except Exception as exc:
        log.warning(
            "process_model_tuning_frame: engine calibration frame failed session_id=%s engine_url=%s engine_session_id=%s: %s",
            session_id,
            state.get("engine_url"),
            state.get("engine_session_id"),
            exc,
        )
        raise HTTPException(status_code=502, detail=f"Engine calibration frame failed: {exc}")

    return result


@_system_settings_router.delete("/model-tuning/sessions/{session_id}")
async def delete_model_tuning_session(
    session_id: str,
    _=Depends(require_role("SYSADMIN")),
):
    from app.exam.proctor_proxy import close_calibration_session as _close_calibration_session

    state = _model_tuning_sessions.pop(session_id, None)
    if not state:
        return {"ok": True}
    try:
        await _close_calibration_session(state["engine_url"], state["engine_session_id"])
    except Exception:
        log.warning(
            "delete_model_tuning_session: engine close calibration session failed session_id=%s engine_url=%s engine_session_id=%s",
            session_id,
            state.get("engine_url"),
            state.get("engine_session_id"),
        )
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# SYSADMIN — EC2 Engine instance management (start / stop / restart / apply-settings)
# ─────────────────────────────────────────────────────────────────────────────

def _get_ssm_client(region: str = "ap-south-1"):
    import boto3, os
    return boto3.client(
        "ssm",
        region_name=region,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )

def _get_ec2_client(region: str = "ap-south-1"):
    import boto3, os
    return boto3.client(
        "ec2",
        region_name=region,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )

def _build_engine_settings_payload(s: "models.EngineSettings") -> dict:
    """Build the /admin/settings POST body from the current EngineSettings row."""
    return {
        "scoring": {
            "STATE_WARNING":              s.state_warning,
            "STATE_HIGH_RISK":            s.state_high_risk,
            "STATE_ADMIN":                s.state_admin_review,
            "DECAY_AMOUNT":               s.decay_amount,
            "TAB_SWITCH_SCORE":           s.tab_switch_score,
            "TAB_SWITCH_TERMINATE_COUNT": s.tab_switch_terminate_count,
            "GAZE_SCORE":                 s.gaze_score,
            "PHONE_SCORE_2ND":            s.phone_score_2nd,
            "PHONE_SCORE_3RD":            s.phone_score_3rd,
            "BOOK_SCORE":                 s.book_score,
            "HEADPHONE_SCORE":            s.headphone_score,
            "EARBUD_SCORE":               s.earbud_score,
            "MULTI_PEOPLE_SCORE_2ND":     s.multi_people_score_2nd,
            "MULTI_PEOPLE_SCORE_3RD":     s.multi_people_score_3rd,
            "NO_PERSON_SCORE_1":          s.no_person_score_1,
            "NO_PERSON_SCORE_2":          s.no_person_score_2,
            "NO_PERSON_DUR_1":            s.no_person_dur_1,
            "NO_PERSON_DUR_2":            s.no_person_dur_2,
            "MULTI_PEOPLE_TERMINATE_S":   s.multi_people_terminate_s,
            "NO_PERSON_TERMINATE_S":      s.no_person_terminate_s,
            "FAKE_PRESENCE_SCORE_1":      s.fake_presence_score_1,
            "FAKE_PRESENCE_SCORE_2":      s.fake_presence_score_2,
            "FAKE_PRESENCE_DUR_1":        s.fake_presence_dur_1,
            "FAKE_PRESENCE_DUR_2":        s.fake_presence_dur_2,
        },
        "cooldowns": {
            "score": {
                "looking_away":    s.score_cd_looking_away,
                "looking_down":    s.score_cd_looking_down,
                "looking_up":      s.score_cd_looking_up,
                "looking_side":    s.score_cd_looking_side,
                "partial_face":    s.score_cd_partial_face,
                "face_hidden":     s.score_cd_face_hidden,
                "fake_presence":   s.score_cd_fake_presence,
                "phone":           s.score_cd_phone,
                "multiple_people": s.score_cd_multiple_people,
                "no_person":       s.score_cd_no_person,
                "book":            s.score_cd_book,
                "headphone":       s.score_cd_headphone,
                "earbud":          s.score_cd_earbud,
                "speaker_audio":   s.score_cd_speaker_audio,
            },
        },
        "thresholds": {
            "LOOK_AWAY_YAW":          s.look_away_yaw,
            "LOOK_DOWN_PITCH":        s.look_down_pitch,
            "LOOK_UP_PITCH":          s.look_up_pitch,
            "GAZE_LEFT":              s.gaze_left,
            "GAZE_RIGHT":             s.gaze_right,
            "LOOKING_AWAY_THRESHOLD": s.looking_away_threshold,
            "GAZE_THRESHOLD":         s.gaze_threshold,
            "FAKE_WINDOW":            s.fake_window,
        },
        # Detection toggles — updates coordinator.exam_config on the engine
        # immediately (all running sessions see the change).
        "detection": {
            "DETECT_LOOKING_AWAY":    s.detect_looking_away,
            "DETECT_LOOKING_DOWN":    s.detect_looking_down,
            "DETECT_LOOKING_UP":      s.detect_looking_up,
            "DETECT_LOOKING_SIDE":    s.detect_looking_side,
            "DETECT_FACE_HIDDEN":     s.detect_face_hidden,
            "DETECT_PARTIAL_FACE":    s.detect_partial_face,
            "DETECT_FAKE_PRESENCE":   s.detect_fake_presence,
            "DETECT_SPEAKER_AUDIO":   s.detect_speaker_audio,
            "DETECT_PHONE":           s.detect_phone,
            "DETECT_BOOK":            s.detect_book,
            "DETECT_HEADPHONE":       s.detect_headphone,
            "DETECT_EARBUD":          s.detect_earbud,
            "DETECT_MULTIPLE_PEOPLE": s.detect_multiple_people,
        },
        # YOLO confidence thresholds — updates the live ObjectDetector instance
        # immediately (all running sessions see the change).
        "objects": {
            "YOLO_PHONE_CONF":  s.yolo_phone_conf,
            "YOLO_BOOK_CONF":   s.yolo_book_conf,
            "YOLO_AUDIO_CONF":  s.yolo_audio_conf,
            "YOLO_PERSON_CONF": s.yolo_person_conf,
        },
    }


def _build_model_tuning_config(
    settings_row: "models.EngineSettings",
    overrides: dict | None = None,
) -> dict:
    payload = _build_engine_settings_payload(settings_row)
    flat = {
        **payload.get("detection", {}),
        **payload.get("thresholds", {}),
        **payload.get("objects", {}),
        **payload.get("scoring", {}),
        "SCORE_COOLDOWNS": payload.get("cooldowns", {}).get("score", {}),
        "WARN_COOLDOWNS": {
            "looking_away": settings_row.warn_cd_looking_away,
            "looking_down": settings_row.warn_cd_looking_down,
            "looking_up": settings_row.warn_cd_looking_up,
            "looking_side": settings_row.warn_cd_looking_side,
            "partial_face": settings_row.warn_cd_partial_face,
            "face_hidden": settings_row.warn_cd_face_hidden,
            "fake_presence": settings_row.warn_cd_fake_presence,
            "phone": settings_row.warn_cd_phone,
            "multiple_people": settings_row.warn_cd_multiple_people,
            "no_person": settings_row.warn_cd_no_person,
            "book": settings_row.warn_cd_book,
            "headphone": settings_row.warn_cd_headphone,
            "earbud": settings_row.warn_cd_earbud,
            "speaker_audio": settings_row.warn_cd_speaker_audio,
        },
        "PARTIAL_FACE_SCORE": settings_row.partial_face_score,
        "PARTIAL_FACE_DURATION_GATE": settings_row.partial_face_duration_gate,
        "FACE_HIDDEN_SCORE_1": settings_row.face_hidden_score_1,
        "FACE_HIDDEN_SCORE_2": settings_row.face_hidden_score_2,
        "FACE_HIDDEN_DUR_1": settings_row.face_hidden_dur_1,
        "FACE_HIDDEN_DUR_2": settings_row.face_hidden_dur_2,
        "FAKE_PRESENCE_DUR_1": settings_row.fake_presence_dur_1,
        "FAKE_PRESENCE_DUR_2": settings_row.fake_presence_dur_2,
        "SPEAKER_WARN_COOLDOWN": settings_row.speaker_warn_cooldown,
        "SPEAKER_ALERT_COOLDOWN": settings_row.speaker_alert_cooldown,
        "SPEAKER_OCC1_WARN_S": settings_row.speaker_occ1_warn_s,
        "SPEAKER_OCC1_SCORE": settings_row.speaker_occ1_score,
        "SPEAKER_OCC1_REPEAT": settings_row.speaker_occ1_repeat,
        "SPEAKER_OCC2_WARN_S": settings_row.speaker_occ2_warn_s,
        "SPEAKER_OCC2_SCORE": settings_row.speaker_occ2_score,
        "SPEAKER_OCC2_REPEAT": settings_row.speaker_occ2_repeat,
        "SPEAKER_REPEAT_INTERVAL": settings_row.speaker_repeat_interval,
        "MIN_FACE_WIDTH": settings_row.min_face_width,
        "MIN_FACE_HEIGHT": settings_row.min_face_height,
        "FACE_HIDDEN_RECENCY_S": settings_row.face_hidden_recency_s,
    }

    field_to_engine_key = {
        "detect_looking_away": "DETECT_LOOKING_AWAY",
        "detect_looking_down": "DETECT_LOOKING_DOWN",
        "detect_looking_up": "DETECT_LOOKING_UP",
        "detect_looking_side": "DETECT_LOOKING_SIDE",
        "detect_face_hidden": "DETECT_FACE_HIDDEN",
        "detect_partial_face": "DETECT_PARTIAL_FACE",
        "detect_fake_presence": "DETECT_FAKE_PRESENCE",
        "detect_speaker_audio": "DETECT_SPEAKER_AUDIO",
        "detect_phone": "DETECT_PHONE",
        "detect_book": "DETECT_BOOK",
        "detect_headphone": "DETECT_HEADPHONE",
        "detect_earbud": "DETECT_EARBUD",
        "detect_multiple_people": "DETECT_MULTIPLE_PEOPLE",
        "looking_away_threshold": "LOOKING_AWAY_THRESHOLD",
        "gaze_threshold": "GAZE_THRESHOLD",
        "fake_window": "FAKE_WINDOW",
        "partial_face_duration_gate": "PARTIAL_FACE_DURATION_GATE",
        "face_hidden_dur_1": "FACE_HIDDEN_DUR_1",
        "face_hidden_dur_2": "FACE_HIDDEN_DUR_2",
        "no_person_dur_1": "NO_PERSON_DUR_1",
        "no_person_dur_2": "NO_PERSON_DUR_2",
        "fake_presence_dur_1": "FAKE_PRESENCE_DUR_1",
        "fake_presence_dur_2": "FAKE_PRESENCE_DUR_2",
        "face_hidden_score_1": "FACE_HIDDEN_SCORE_1",
        "face_hidden_score_2": "FACE_HIDDEN_SCORE_2",
        "partial_face_score": "PARTIAL_FACE_SCORE",
        "multi_people_terminate_s": "MULTI_PEOPLE_TERMINATE_S",
        "no_person_terminate_s": "NO_PERSON_TERMINATE_S",
        "speaker_occ1_warn_s": "SPEAKER_OCC1_WARN_S",
        "speaker_occ2_warn_s": "SPEAKER_OCC2_WARN_S",
        "speaker_repeat_interval": "SPEAKER_REPEAT_INTERVAL",
        "speaker_occ1_score": "SPEAKER_OCC1_SCORE",
        "speaker_occ2_score": "SPEAKER_OCC2_SCORE",
        "speaker_occ1_repeat": "SPEAKER_OCC1_REPEAT",
        "speaker_occ2_repeat": "SPEAKER_OCC2_REPEAT",
        "speaker_warn_cooldown": "SPEAKER_WARN_COOLDOWN",
        "speaker_alert_cooldown": "SPEAKER_ALERT_COOLDOWN",
        "min_face_width": "MIN_FACE_WIDTH",
        "min_face_height": "MIN_FACE_HEIGHT",
        "face_hidden_recency_s": "FACE_HIDDEN_RECENCY_S",
        "look_away_yaw": "LOOK_AWAY_YAW",
        "look_down_pitch": "LOOK_DOWN_PITCH",
        "look_up_pitch": "LOOK_UP_PITCH",
        "gaze_left": "GAZE_LEFT",
        "gaze_right": "GAZE_RIGHT",
        "yolo_phone_conf": "YOLO_PHONE_CONF",
        "yolo_book_conf": "YOLO_BOOK_CONF",
        "yolo_audio_conf": "YOLO_AUDIO_CONF",
        "yolo_person_conf": "YOLO_PERSON_CONF",
        "state_warning": "STATE_WARNING",
        "state_high_risk": "STATE_HIGH_RISK",
        "state_admin_review": "STATE_ADMIN",
        "decay_amount": "DECAY_AMOUNT",
        "gaze_score": "GAZE_SCORE",
        "phone_score_2nd": "PHONE_SCORE_2ND",
        "phone_score_3rd": "PHONE_SCORE_3RD",
        "book_score": "BOOK_SCORE",
        "headphone_score": "HEADPHONE_SCORE",
        "earbud_score": "EARBUD_SCORE",
        "multi_people_score_2nd": "MULTI_PEOPLE_SCORE_2ND",
        "multi_people_score_3rd": "MULTI_PEOPLE_SCORE_3RD",
        "no_person_score_1": "NO_PERSON_SCORE_1",
        "no_person_score_2": "NO_PERSON_SCORE_2",
        "fake_presence_score_1": "FAKE_PRESENCE_SCORE_1",
        "fake_presence_score_2": "FAKE_PRESENCE_SCORE_2",
        "tab_switch_terminate_count": "TAB_SWITCH_TERMINATE_COUNT",
        "tab_switch_score": "TAB_SWITCH_SCORE",
    }

    if overrides:
        for key, value in overrides.items():
            if value is not None:
                flat[field_to_engine_key.get(key, key)] = value
    return flat


def _build_env_file_content(s: models.EngineSettings, db_url: str, s3_bucket: str,
                             aws_key: str, aws_secret: str, aws_region: str) -> str:
    """Build the full engine .env content from current DB settings."""
    def _b(v) -> str:
        return "true" if v else "false"

    return f"""DATABASE_URL={db_url}
S3_BUCKET={s3_bucket}
AWS_REGION={aws_region}
AWS_ACCESS_KEY_ID={aws_key}
AWS_SECRET_ACCESS_KEY={aws_secret}
SAVE_REPORT=false
SAVE_PROOF=true

# State thresholds
STATE_WARNING={s.state_warning}
STATE_HIGH_RISK={s.state_high_risk}
STATE_ADMIN={s.state_admin_review}
DECAY_AMOUNT={s.decay_amount}

# Risk scores
GAZE_SCORE={s.gaze_score}
TAB_SWITCH_SCORE={s.tab_switch_score}
TAB_SWITCH_TERMINATE_COUNT={s.tab_switch_terminate_count}
PHONE_SCORE_2ND={s.phone_score_2nd}
PHONE_SCORE_3RD={s.phone_score_3rd}
BOOK_SCORE={s.book_score}
HEADPHONE_SCORE={s.headphone_score}
EARBUD_SCORE={s.earbud_score}
MULTI_PEOPLE_SCORE_2ND={s.multi_people_score_2nd}
MULTI_PEOPLE_SCORE_3RD={s.multi_people_score_3rd}
MULTI_PEOPLE_TERMINATE_S={s.multi_people_terminate_s}
NO_PERSON_SCORE_1={s.no_person_score_1}
NO_PERSON_SCORE_2={s.no_person_score_2}
NO_PERSON_TERMINATE_S={s.no_person_terminate_s}
FAKE_PRESENCE_SCORE_1={s.fake_presence_score_1}
FAKE_PRESENCE_SCORE_2={s.fake_presence_score_2}
PARTIAL_FACE_SCORE={s.partial_face_score}
FACE_HIDDEN_SCORE_1={s.face_hidden_score_1}
FACE_HIDDEN_SCORE_2={s.face_hidden_score_2}

# Duration gates
LOOKING_AWAY_THRESHOLD={s.looking_away_threshold}
GAZE_THRESHOLD={s.gaze_threshold}
FAKE_WINDOW={s.fake_window}
PARTIAL_FACE_DURATION_GATE={s.partial_face_duration_gate}
FACE_HIDDEN_DUR_1={s.face_hidden_dur_1}
FACE_HIDDEN_DUR_2={s.face_hidden_dur_2}
NO_PERSON_DUR_1={s.no_person_dur_1}
NO_PERSON_DUR_2={s.no_person_dur_2}
FAKE_PRESENCE_DUR_1={s.fake_presence_dur_1}
FAKE_PRESENCE_DUR_2={s.fake_presence_dur_2}

# Head pose thresholds
LOOK_AWAY_YAW={s.look_away_yaw}
LOOK_DOWN_PITCH={s.look_down_pitch}
LOOK_UP_PITCH={s.look_up_pitch}
GAZE_LEFT={s.gaze_left}
GAZE_RIGHT={s.gaze_right}
MIN_FACE_WIDTH={s.min_face_width}
MIN_FACE_HEIGHT={s.min_face_height}
FACE_HIDDEN_RECENCY_S={s.face_hidden_recency_s}

# YOLO confidence thresholds
YOLO_PHONE_CONF={s.yolo_phone_conf}
YOLO_BOOK_CONF={s.yolo_book_conf}
YOLO_AUDIO_CONF={s.yolo_audio_conf}
YOLO_PERSON_CONF={s.yolo_person_conf}

# Detection toggles
DETECT_LOOKING_AWAY={_b(s.detect_looking_away)}
DETECT_LOOKING_DOWN={_b(s.detect_looking_down)}
DETECT_LOOKING_UP={_b(s.detect_looking_up)}
DETECT_LOOKING_SIDE={_b(s.detect_looking_side)}
DETECT_FACE_HIDDEN={_b(s.detect_face_hidden)}
DETECT_PARTIAL_FACE={_b(s.detect_partial_face)}
DETECT_FAKE_PRESENCE={_b(s.detect_fake_presence)}
DETECT_SPEAKER_AUDIO={_b(s.detect_speaker_audio)}
DETECT_PHONE={_b(s.detect_phone)}
DETECT_BOOK={_b(s.detect_book)}
DETECT_HEADPHONE={_b(s.detect_headphone)}
DETECT_EARBUD={_b(s.detect_earbud)}
DETECT_MULTIPLE_PEOPLE={_b(s.detect_multiple_people)}

# Speaker audio
SPEAKER_WARN_COOLDOWN={s.speaker_warn_cooldown}
SPEAKER_ALERT_COOLDOWN={s.speaker_alert_cooldown}
SPEAKER_OCC1_WARN_S={s.speaker_occ1_warn_s}
SPEAKER_OCC1_SCORE={s.speaker_occ1_score}
SPEAKER_OCC1_REPEAT={s.speaker_occ1_repeat}
SPEAKER_OCC2_WARN_S={s.speaker_occ2_warn_s}
SPEAKER_OCC2_SCORE={s.speaker_occ2_score}
SPEAKER_OCC2_REPEAT={s.speaker_occ2_repeat}
SPEAKER_REPEAT_INTERVAL={s.speaker_repeat_interval}

# Score cooldowns (also used as API alert cooldowns)
SCORE_CD_LOOKING_AWAY={s.score_cd_looking_away}
SCORE_CD_LOOKING_DOWN={s.score_cd_looking_down}
SCORE_CD_LOOKING_UP={s.score_cd_looking_up}
SCORE_CD_LOOKING_SIDE={s.score_cd_looking_side}
SCORE_CD_PARTIAL_FACE={s.score_cd_partial_face}
SCORE_CD_FACE_HIDDEN={s.score_cd_face_hidden}
SCORE_CD_FAKE_PRESENCE={s.score_cd_fake_presence}
SCORE_CD_PHONE={s.score_cd_phone}
SCORE_CD_MULTIPLE_PEOPLE={s.score_cd_multiple_people}
SCORE_CD_NO_PERSON={s.score_cd_no_person}
SCORE_CD_BOOK={s.score_cd_book}
SCORE_CD_HEADPHONE={s.score_cd_headphone}
SCORE_CD_EARBUD={s.score_cd_earbud}
SCORE_CD_SPEAKER_AUDIO={s.score_cd_speaker_audio}

# Warning cooldowns
WARN_CD_LOOKING_AWAY={s.warn_cd_looking_away}
WARN_CD_LOOKING_DOWN={s.warn_cd_looking_down}
WARN_CD_LOOKING_UP={s.warn_cd_looking_up}
WARN_CD_LOOKING_SIDE={s.warn_cd_looking_side}
WARN_CD_PARTIAL_FACE={s.warn_cd_partial_face}
WARN_CD_FACE_HIDDEN={s.warn_cd_face_hidden}
WARN_CD_FAKE_PRESENCE={s.warn_cd_fake_presence}
WARN_CD_PHONE={s.warn_cd_phone}
WARN_CD_MULTIPLE_PEOPLE={s.warn_cd_multiple_people}
WARN_CD_NO_PERSON={s.warn_cd_no_person}
WARN_CD_BOOK={s.warn_cd_book}
WARN_CD_HEADPHONE={s.warn_cd_headphone}
WARN_CD_EARBUD={s.warn_cd_earbud}
WARN_CD_SPEAKER_AUDIO={s.warn_cd_speaker_audio}
"""


class EC2InstanceAction(BaseModel):
    instance_id: str
    region: str = "ap-south-1"


class ContainerMetaUpdate(BaseModel):
    ec2_instance_id: str
    ec2_region: str = "ap-south-1"
    container_name: str    # "proctor1" or "proctor2"
    container_port: int    # 8000 or 8001


@_system_settings_router.patch("/engine/containers/{container_id}/meta")
def update_container_meta(
    container_id: str,
    body: ContainerMetaUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Store EC2 instance ID and container name on an EngineContainer row."""
    container = db.query(models.EngineContainer).filter(
        models.EngineContainer.id == container_id
    ).first()
    if not container:
        raise HTTPException(status_code=404, detail="Container not found")
    container.ec2_instance_id = body.ec2_instance_id
    container.ec2_region      = body.ec2_region
    container.container_name  = body.container_name
    container.container_port  = body.container_port
    db.commit()
    return {"message": "Container metadata updated"}


@_system_settings_router.post("/engine/ec2/start")
def start_ec2_instance(
    body: EC2InstanceAction,
    _=Depends(require_role("SYSADMIN")),
):
    """Start a stopped EC2 engine instance."""
    try:
        ec2 = _get_ec2_client(body.region)
        ec2.start_instances(InstanceIds=[body.instance_id])
        log.info("SYSADMIN: started EC2 instance %s", body.instance_id)
        return {"message": f"Starting {body.instance_id}"}
    except Exception as e:
        system_logger.error(
            "start_ec2_instance failed region=%s instance_id=%s error=%s",
            body.region,
            body.instance_id,
            e,
        )
        raise HTTPException(status_code=502, detail=str(e))


@_system_settings_router.post("/engine/ec2/stop")
def stop_ec2_instance(
    body: EC2InstanceAction,
    _=Depends(require_role("SYSADMIN")),
):
    """Stop a running EC2 engine instance."""
    try:
        ec2 = _get_ec2_client(body.region)
        ec2.stop_instances(InstanceIds=[body.instance_id])
        log.info("SYSADMIN: stopped EC2 instance %s", body.instance_id)
        return {"message": f"Stopping {body.instance_id}"}
    except Exception as e:
        system_logger.error(
            "stop_ec2_instance failed region=%s instance_id=%s error=%s",
            body.region,
            body.instance_id,
            e,
        )
        raise HTTPException(status_code=502, detail=str(e))


@_system_settings_router.post("/engine/ec2/status")
def get_ec2_status(
    body: EC2InstanceAction,
    _=Depends(require_role("SYSADMIN")),
):
    """Get current state of an EC2 engine instance."""
    try:
        ec2 = _get_ec2_client(body.region)
        resp = ec2.describe_instances(InstanceIds=[body.instance_id])
        instance = resp["Reservations"][0]["Instances"][0]
        return {
            "instance_id": body.instance_id,
            "state": instance["State"]["Name"],
            "public_ip": instance.get("PublicIpAddress"),
        }
    except Exception as e:
        system_logger.error(
            "get_ec2_status failed region=%s instance_id=%s error=%s",
            body.region,
            body.instance_id,
            e,
        )
        raise HTTPException(status_code=502, detail=str(e))


class ContainerAction(BaseModel):
    container_id: str


@_system_settings_router.post("/engine/containers/{container_id}/start")
def start_container(
    container_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Start a Docker container on its EC2 instance via SSM."""
    container = db.query(models.EngineContainer).filter(
        models.EngineContainer.id == container_id
    ).first()
    if not container:
        raise HTTPException(status_code=404, detail="Container not found")
    if not container.ec2_instance_id or not container.container_name:
        raise HTTPException(status_code=400, detail="EC2 instance ID or container name not configured")
    try:
        ssm = _get_ssm_client(container.ec2_region or "ap-south-1")
        resp = ssm.send_command(
            InstanceIds=[container.ec2_instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [f"docker start {container.container_name}"]},
            Comment=f"Start container {container.container_name}",
        )
        return {"message": f"Starting {container.container_name}", "command_id": resp["Command"]["CommandId"]}
    except Exception as e:
        system_logger.error(
            "start_container failed container_id=%s container_name=%s ec2_instance_id=%s error=%s",
            container_id,
            container.container_name,
            container.ec2_instance_id,
            e,
        )
        raise HTTPException(status_code=502, detail=str(e))


@_system_settings_router.post("/engine/containers/{container_id}/stop")
def stop_container(
    container_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Stop a Docker container on its EC2 instance via SSM."""
    container = db.query(models.EngineContainer).filter(
        models.EngineContainer.id == container_id
    ).first()
    if not container:
        raise HTTPException(status_code=404, detail="Container not found")
    if not container.ec2_instance_id or not container.container_name:
        raise HTTPException(status_code=400, detail="EC2 instance ID or container name not configured")
    try:
        ssm = _get_ssm_client(container.ec2_region or "ap-south-1")
        resp = ssm.send_command(
            InstanceIds=[container.ec2_instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [f"docker stop {container.container_name}"]},
            Comment=f"Stop container {container.container_name}",
        )
        return {"message": f"Stopping {container.container_name}", "command_id": resp["Command"]["CommandId"]}
    except Exception as e:
        system_logger.error(
            "stop_container failed container_id=%s container_name=%s ec2_instance_id=%s error=%s",
            container_id,
            container.container_name,
            container.ec2_instance_id,
            e,
        )
        raise HTTPException(status_code=502, detail=str(e))


@_system_settings_router.post("/engine/apply-settings")
async def apply_engine_settings(
    db: Session = Depends(get_db),
    current_admin=Depends(require_role("SYSADMIN")),
):
    """
    Push current EngineSettings from DB to all engine EC2 instances via SSM,
    then restart their Docker containers so new scoring values take effect.

    Steps:
      1. Build .env content from current EngineSettings row
      2. For each container with an ec2_instance_id:
         a. Write new .env to the EC2 via SSM run_command
         b. Restart the specific Docker container
      3. Update container URLs if IP changed (via describe_instances)
    """
    import os
    import asyncio
    import httpx

    s = db.query(models.EngineSettings).first()
    if not s:
        raise HTTPException(status_code=404, detail="EngineSettings not found")

    # ── Step 1: Live push to all active engines via /admin/settings ─────────────
    # This works without EC2 instance IDs and applies settings IMMEDIATELY to
    # all running containers (updates S.* module vars in real-time).
    all_active = db.query(models.EngineContainer).filter(
        models.EngineContainer.is_active == True
    ).all()

    live_push_results = []
    async def _push_live(client: httpx.AsyncClient, url: str) -> dict:
        try:
            payload = _build_engine_settings_payload(s)
            r = await client.post(f"{url}/admin/settings", json=payload, timeout=8.0)
            r.raise_for_status()
            return {"url": url, "status": "live_applied"}
        except Exception as exc:
            log.warning("Live push settings to %s failed: %s", url, exc)
            return {"url": url, "status": "live_push_failed", "error": str(exc)}

    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=3.0, read=8.0, write=4.0, pool=4.0)) as _client:
        live_push_results = list(await asyncio.gather(
            *[_push_live(_client, c.url) for c in all_active],
            return_exceptions=False,
        ))

    log.info("apply-settings live push: %s", live_push_results)

    # ── Step 2: SSM restart (persistent across container restarts) ─────────────
    # Only runs if containers have EC2 instance IDs configured.
    containers = db.query(models.EngineContainer).filter(
        models.EngineContainer.ec2_instance_id.isnot(None)
    ).all()

    if not containers:
        # No EC2 configured — live push was enough, return results
        db.commit()
        return {
            "message": "Settings applied live to all running containers. "
                       "To make settings persist across Docker restarts, configure EC2 instance IDs on container cards.",
            "results": live_push_results,
        }

    db_url    = os.getenv("DATABASE_URL", "").replace("+psycopg2", "")
    s3_bucket = os.getenv("S3_BUCKET", "")
    aws_key   = os.getenv("AWS_ACCESS_KEY_ID", "")
    aws_secret= os.getenv("AWS_SECRET_ACCESS_KEY", "")
    aws_region= os.getenv("AWS_REGION", "ap-south-1")

    env_content = _build_env_file_content(s, db_url, s3_bucket, aws_key, aws_secret, aws_region)
    # Escape for shell single-quote heredoc
    env_escaped = env_content.replace("'", "'\\''")

    results = []
    processed_instances: set[str] = set()

    for container in containers:
        instance_id    = container.ec2_instance_id
        region         = container.ec2_region or "ap-south-1"
        container_name = container.container_name or "proctor1"

        try:
            ssm = _get_ssm_client(region)

            # Write .env + restart container in one SSM command
            # Only write .env once per EC2 instance (multiple containers share it)
            write_env_cmd = ""
            if instance_id not in processed_instances:
                write_env_cmd = f"printf '%s' '{env_escaped}' > /home/ubuntu/.env && "
                processed_instances.add(instance_id)

            restart_cmd = f"{write_env_cmd}docker restart {container_name}"

            resp = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [restart_cmd]},
                Comment=f"Apply engine settings and restart {container_name}",
            )
            command_id = resp["Command"]["CommandId"]
            results.append({
                "instance_id": instance_id,
                "container": container_name,
                "command_id": command_id,
                "status": "sent",
            })
            log.info("SYSADMIN apply-settings: sent SSM command %s to %s/%s",
                     command_id, instance_id, container_name)

            # Update container URL if IP changed
            ec2 = _get_ec2_client(region)
            ec2_resp = ec2.describe_instances(InstanceIds=[instance_id])
            new_ip = ec2_resp["Reservations"][0]["Instances"][0].get("PublicIpAddress")
            if new_ip:
                port = container.container_port or 8000
                new_url = f"http://{new_ip}:{port}"
                if container.url != new_url:
                    # Check if another row already owns this URL; if so skip
                    conflict = db.query(models.EngineContainer).filter(
                        models.EngineContainer.url == new_url,
                        models.EngineContainer.id != container.id,
                    ).first()
                    if conflict:
                        log.warning("apply-settings: URL %s already owned by container %s, skipping update",
                                    new_url, conflict.id)
                    else:
                        log.info("apply-settings: updating container URL %s → %s",
                                 container.url, new_url)
                        container.url = new_url

        except Exception as exc:
            log.error("apply-settings failed for %s/%s: %s", instance_id, container_name, exc)
            results.append({
                "instance_id": instance_id,
                "container": container_name,
                "status": "error",
                "error": str(exc),
            })

    db.commit()
    return {
        "message": "Settings applied live and containers are restarting via SSM.",
        "results": live_push_results + results,
    }


# ─────────────────────────────────────────────────────────────────────────────
# SYSADMIN — Engine monitoring + cross-exam session oversight
# ─────────────────────────────────────────────────────────────────────────────

@_system_settings_router.get("/engine/containers")
def get_engine_containers(
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """List all configured engine containers with their current session load."""
    containers = db.query(models.EngineContainer).filter(
        models.EngineContainer.is_active == True
    ).order_by(models.EngineContainer.url).all()
    result = []
    for c in containers:
        active_sessions = (
            db.query(models.ExamSession)
            .filter(
                models.ExamSession.proctor_engine_url == c.url,
                models.ExamSession.status.in_(["CREATED", "ACTIVE", "DISCONNECTED"]),
            )
            .count()
        )
        result.append({
            "id": str(c.id),
            "url": c.url,
            "max_sessions": c.max_sessions,
            "is_active": c.is_active,
            "active_sessions": active_sessions,
            "ec2_instance_id": c.ec2_instance_id,
            "ec2_region": c.ec2_region,
            "container_name": c.container_name,
            "container_port": c.container_port,
        })
    return result


@_system_settings_router.get("/engine/metrics")
async def get_engine_metrics(
    _=Depends(require_role("SYSADMIN")),
    db: Session = Depends(get_db),
):
    """
    Proxy GET /metrics from every active engine container.
    Returns a list of {url, metrics | error} — one entry per container.
    """
    import httpx
    containers = (
        db.query(models.EngineContainer)
        .filter(models.EngineContainer.is_active == True)
        .all()
    )
    results = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=4.0, read=8.0, write=4.0, pool=4.0)) as client:
        for c in containers:
            try:
                r = await client.get(f"{c.url}/metrics")
                r.raise_for_status()
                results.append({"url": c.url, "ok": True, "metrics": r.json()})
                log.debug("Engine metrics OK: %s", c.url)
            except Exception as exc:
                error_detail = f"{type(exc).__name__}: {exc}"
                log.warning("Engine metrics FAILED for %s — %s", c.url, error_detail)
                results.append({"url": c.url, "ok": False, "error": error_detail})
    return results


@_system_settings_router.get("/engine/report")
async def get_engine_report(
    _=Depends(require_role("SYSADMIN")),
    db: Session = Depends(get_db),
):
    """
    Proxy GET /system/report from every active engine container.
    Returns a list of {url, report | error}.
    """
    import httpx
    containers = (
        db.query(models.EngineContainer)
        .filter(models.EngineContainer.is_active == True)
        .all()
    )
    results = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=4.0, read=15.0, write=4.0, pool=4.0)) as client:
        for c in containers:
            try:
                r = await client.get(f"{c.url}/system/report")
                r.raise_for_status()
                results.append({"url": c.url, "ok": True, "report": r.json()})
            except Exception as exc:
                system_logger.warning(
                    "get_engine_report failed engine_url=%s error=%s",
                    c.url,
                    exc,
                )
                results.append({"url": c.url, "ok": False, "error": str(exc)})
    return results


@_system_settings_router.get("/engine/sessions")
async def get_engine_sessions(
    _=Depends(require_role("SYSADMIN")),
    db: Session = Depends(get_db),
):
    """
    Proxy GET /sessions from every active container and cross-reference with
    our DB to add student name, exam title, and ProctorAI session_id.
    """
    import httpx
    containers = (
        db.query(models.EngineContainer)
        .filter(models.EngineContainer.is_active == True)
        .all()
    )
    combined = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=4.0, read=8.0, write=4.0, pool=4.0)) as client:
        for c in containers:
            try:
                r = await client.get(f"{c.url}/sessions")
                r.raise_for_status()
                engine_sessions = r.json()
            except Exception as exc:
                log.warning("Engine /sessions failed (%s): %s", c.url, exc)
                continue

            for es in engine_sessions:
                pc_id = es.get("pc_id")
                # Look up the ProctorAI session by pc_id + engine_url
                db_session = (
                    db.query(models.ExamSession)
                    .filter(
                        models.ExamSession.proctor_pc_id == pc_id,
                        models.ExamSession.proctor_engine_url == c.url,
                    )
                    .first()
                )
                entry = {**es, "engine_url": c.url}
                if db_session:
                    user = db.query(models.User).filter(models.User.id == db_session.user_id).first()
                    exam = db.query(models.Exam).filter(models.Exam.id == db_session.exam_id).first()
                    entry.update({
                        "session_id": str(db_session.id),
                        "exam_id": str(db_session.exam_id),
                        "exam_title": exam.title if exam else "Unknown",
                        "student_name": user.full_name if user else "Unknown",
                        "student_email": user.email if user else "",
                        "session_status": db_session.status,
                    })
                combined.append(entry)
    return combined


@_system_settings_router.get("/sessions")
def get_all_active_sessions(
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """
    All active/disconnected ProctorAI sessions across all exams — with full
    student info, exam title, risk score, and proctor status.
    """
    sessions = (
        db.query(models.ExamSession)
        .filter(
            models.ExamSession.status.in_(["ACTIVE", "DISCONNECTED"]),
        )
        .order_by(models.ExamSession.start_time.desc())
        .all()
    )
    result = []
    for s in sessions:
        user = db.query(models.User).filter(models.User.id == s.user_id).first()
        exam = db.query(models.Exam).filter(models.Exam.id == s.exam_id).first()
        result.append({
            "session_id": str(s.id),
            "exam_id": str(s.exam_id),
            "exam_title": exam.title if exam else "Unknown",
            "student_name": user.full_name if user else "Unknown",
            "student_email": user.email if user else "",
            "status": s.status,
            "start_time": s.start_time,
            "risk_score": s.risk_score or 0,
            "last_heartbeat": s.last_heartbeat,
            "proctor_connected": bool(s.proctor_pc_id),
            "proctor_engine_url": s.proctor_engine_url,
            "terminated_reason": s.terminated_reason,
        })
    return result


@_system_settings_router.get("/sessions/{session_id}/live-frame")
async def sysadmin_live_frame(
    session_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Snapshot JPEG for any session — no exam_id required."""
    from fastapi.responses import Response as _Response
    from app.exam.proctor_proxy import fetch_snapshot

    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.proctor_pc_id or not session.proctor_engine_url:
        return _Response(content=b"", status_code=204, media_type="image/jpeg")
    try:
        jpeg = await fetch_snapshot(session.proctor_engine_url, session.proctor_pc_id)
        return _Response(content=jpeg, media_type="image/jpeg")
    except Exception as e:
        log.warning(
            "sysadmin_live_frame: engine snapshot fetch failed session_id=%s pc_id=%s: %s",
            session_id,
            session.proctor_pc_id,
            e,
        )
        return _Response(content=b"", status_code=204, media_type="image/jpeg")


@_system_settings_router.get("/sessions/{session_id}/live-stream")
async def sysadmin_live_stream(
    session_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """SSE alert stream for any session — no exam_id required."""
    from fastapi.responses import StreamingResponse as _SR
    from app.exam.proctor_proxy import stream_engine_events
    import asyncio as _asyncio

    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.proctor_pc_id or not session.proctor_engine_url:
        async def _waiting():
            while True:
                yield ': waiting\n\n'
                await _asyncio.sleep(5)
        return _SR(_waiting(), media_type="text/event-stream",
                   headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return _SR(
        stream_engine_events(session.proctor_engine_url, session.proctor_pc_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@_system_settings_router.get("/sessions/{session_id}/alert-history")
async def sysadmin_session_alert_history(
    session_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """
    Return the full alert + warning history for any session.
    Used by the system-admin live sessions page to restore engine history
    after page refreshes or when connecting after warnings already occurred.
    """
    from app.exam.proctor_proxy import fetch_session_log

    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if not session.proctor_pc_id or not session.proctor_engine_url:
        return {"alerts": [], "warnings": []}

    try:
        log_data = await fetch_session_log(session.proctor_engine_url, session.proctor_pc_id)
        alerts = [
            {
                "message": e.get("message", "Alert"),
                "proof_url": e.get("proof_url"),
                "proof_type": e.get("proof_type", "image"),
                "score_added": 0,
                "elapsed_s": e.get("elapsed_s", 0),
                "time": e.get("time", ""),
            }
            for e in log_data.get("alert_log", [])
        ]
        warnings = [
            {
                "message": e.get("message", "Warning"),
                "elapsed_s": e.get("elapsed_s", 0),
                "time": e.get("time", ""),
            }
            for e in log_data.get("warning_log", [])
        ]
        return {"alerts": list(reversed(alerts)), "warnings": list(reversed(warnings))}
    except Exception:
        log.warning(
            "sysadmin_session_alert_history: fetch_session_log failed session_id=%s pc_id=%s",
            session_id,
            session.proctor_pc_id,
        )
        return {"alerts": [], "warnings": []}


@_system_settings_router.post("/sessions/{session_id}/debug-mode")
async def sysadmin_debug_mode(
    session_id: str,
    body: DebugModeBody,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Toggle CV2 debug overlay on the engine's live snapshot for any session."""
    from app.exam.proctor_proxy import proxy_debug_toggle

    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not session.proctor_pc_id or not session.proctor_engine_url:
        raise HTTPException(status_code=404, detail="No proctoring engine session for this student")

    try:
        return await proxy_debug_toggle(
            session.proctor_engine_url, session.proctor_pc_id, body.enabled
        )
    except Exception as e:
        system_logger.warning(
            "sysadmin_debug_mode failed session_id=%s pc_id=%s engine_url=%s enabled=%s error=%s",
            session_id,
            session.proctor_pc_id,
            session.proctor_engine_url,
            body.enabled,
            e,
        )
        raise HTTPException(status_code=502, detail=f"Engine debug toggle failed: {e}")

# =====================================================
# SYSTEM ADMIN — SESSION REPORTS (cross-engine)
# =====================================================

@_system_settings_router.get("/reports")
def list_all_reports(
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """
    List all completed/terminated exam sessions as reports (sourced from RDS).
    """
    from sqlalchemy import func as _sqlfunc

    sessions = (
        db.query(models.ExamSession)
        .filter(models.ExamSession.status.in_(["ENDED", "TERMINATED"]))
        .order_by(models.ExamSession.created_at.desc())
        .all()
    )

    users  = {str(u.id): u for u in db.query(models.User).all()}
    exams  = {str(e.id): e for e in db.query(models.Exam).all()}
    _backfill_missing_proof_sizes(db, [s.id for s in sessions])

    # Aggregate alert/warning/proof counts in a single pass per table
    alert_counts: dict = dict(
        db.query(models.ProctorAlert.session_id, _sqlfunc.count())
        .group_by(models.ProctorAlert.session_id).all()
    )
    warning_counts: dict = dict(
        db.query(models.ProctorWarning.session_id, _sqlfunc.count())
        .group_by(models.ProctorWarning.session_id).all()
    )
    proof_counts: dict = dict(
        db.query(models.ProctorAlert.session_id, _sqlfunc.count())
        .filter(models.ProctorAlert.proof_s3_key.isnot(None))
        .group_by(models.ProctorAlert.session_id).all()
    )
    proof_size_bytes: dict = dict(
        db.query(
            models.ProctorAlert.session_id,
            _sqlfunc.coalesce(_sqlfunc.sum(models.ProctorAlert.proof_size_bytes), 0),
        )
        .filter(
            models.ProctorAlert.proof_s3_key.isnot(None),
            (models.ProctorAlert.proof_type.is_(None) | (models.ProctorAlert.proof_type != "audio")),
        )
        .group_by(models.ProctorAlert.session_id)
        .all()
    )

    result = []
    for s in sessions:
        user  = users.get(str(s.user_id))
        exam  = exams.get(str(s.exam_id))
        effective_end = s.end_time or s.terminated_at
        duration_s = (
            max(0, int(round((effective_end - s.start_time).total_seconds())))
            if s.start_time and effective_end else None
        )
        student_name = None
        if user:
            fn = getattr(user, "first_name", None) or ""
            ln = getattr(user, "last_name",  None) or ""
            student_name = f"{fn} {ln}".strip() or getattr(user, "full_name", None) or user.email

        result.append({
            "report_id":      str(s.id),
            "engine_url":     s.proctor_engine_url or "",
            "risk_state":     s.status,           # ENDED | TERMINATED
            "final_score":    s.risk_score,
            "alert_count":    alert_counts.get(s.id, 0),
            "warning_count":  warning_counts.get(s.id, 0),
            "size_kb":        round((proof_size_bytes.get(s.id, 0) or 0) / 1024, 1),
            "proof_count":    proof_counts.get(s.id, 0),
            "duration_s":     duration_s,
            "terminated":     s.status == "TERMINATED",
            "session_start":  s.start_time.isoformat()  if s.start_time  else None,
            "session_end":    effective_end.isoformat() if effective_end else None,
            "session_id":     str(s.id),
            "exam_id":        str(s.exam_id)   if s.exam_id   else None,
            "exam_title":     exam.title        if exam        else "Unknown Exam",
            "student_name":   student_name,
            "student_email":  user.email        if user        else None,
            "session_status": s.status,
        })

    return result


@_system_settings_router.delete("/reports/{report_id}")
async def delete_report(
    report_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Delete only proof images for a report while preserving the report data."""
    import uuid as _uuid
    from app.core.storage import delete_s3_objects

    try:
        session_uuid = _uuid.UUID(report_id)
    except ValueError:
        system_logger.warning("delete_report invalid report_id=%s", report_id)
        raise HTTPException(status_code=400, detail="Invalid report ID")

    sess = db.query(models.ExamSession).filter(models.ExamSession.id == session_uuid).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    proof_alerts = [
        alert for alert in sess.proctor_alerts
        if alert.proof_s3_key and (alert.proof_type or "image") != "audio"
    ]
    keys = [alert.proof_s3_key for alert in proof_alerts if alert.proof_s3_key]

    deleted_count, errors = delete_s3_objects(keys)

    for alert in proof_alerts:
        alert.proof_s3_key = None
        alert.proof_size_bytes = None

    db.commit()

    log.info("SYSADMIN deleted %d proof image(s) for report %s", deleted_count, report_id)
    return {
        "ok": True,
        "report_id": report_id,
        "deleted_proofs": deleted_count,
        "errors": errors,
    }


# =====================================================
# SYSTEM ADMIN — DASHBOARD STATS
# =====================================================

@_system_settings_router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Live dashboard summary numbers."""
    from datetime import datetime, timezone as _tz
    from sqlalchemy import or_ as _or

    now = datetime.now(_tz.utc)

    total_users = (
        db.query(models.User)
        .filter(models.User.is_deleted == False)
        .count()
    )
    active_exams = (
        db.query(models.Exam)
        .filter(models.Exam.status == "ACTIVE", models.Exam.is_deleted == False)
        .count()
    )
    live_sessions = (
        db.query(models.ExamSession)
        .filter(models.ExamSession.status.in_(["ACTIVE", "DISCONNECTED"]))
        .count()
    )
    pending_applications = (
        db.query(models.AdminApplication)
        .filter(models.AdminApplication.status == "PENDING")
        .count()
    )
    locked_users = (
        db.query(models.User)
        .filter(
            models.User.is_deleted == False,
            models.User.locked_until > now,
        )
        .count()
    )
    active_containers = (
        db.query(models.EngineContainer)
        .filter(models.EngineContainer.is_active == True)
        .count()
    )
    total_exams = (
        db.query(models.Exam)
        .filter(models.Exam.is_deleted == False)
        .count()
    )

    return {
        "total_users": total_users,
        "active_exams": active_exams,
        "live_sessions": live_sessions,
        "pending_applications": pending_applications,
        "locked_users": locked_users,
        "active_containers": active_containers,
        "total_exams": total_exams,
    }


# =====================================================
# SYSTEM ADMIN — USER MANAGEMENT
# =====================================================

@_system_settings_router.get("/users")
def list_users(
    q: str | None = None,
    role: str | None = None,
    locked: bool | None = None,
    page: int = 1,
    limit: int = 50,
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """List all users with optional search, role, and lock-status filters."""
    from datetime import datetime, timezone as _tz
    from sqlalchemy import or_ as _or

    now = datetime.now(_tz.utc)

    query = db.query(models.User).filter(models.User.is_deleted == False)

    if q:
        query = query.filter(
            _or(
                models.User.full_name.ilike(f"%{q}%"),
                models.User.email.ilike(f"%{q}%"),
            )
        )
    if role:
        query = query.filter(models.User.role == role)
    if locked is True:
        query = query.filter(models.User.locked_until > now)
    elif locked is False:
        from sqlalchemy import or_ as _or2
        query = query.filter(
            _or2(
                models.User.locked_until == None,
                models.User.locked_until <= now,
            )
        )

    total = query.count()
    users = (
        query
        .order_by(models.User.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    result = []
    for u in users:
        lu = u.locked_until
        if lu and lu.tzinfo is None:
            from datetime import timezone as _tz2
            lu = lu.replace(tzinfo=_tz2.utc)
        is_locked = bool(lu and lu > now)
        result.append({
            "id": str(u.id),
            "full_name": u.full_name,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "is_locked": is_locked,
            "locked_until": u.locked_until.isoformat() if u.locked_until else None,
            "failed_login_attempts": u.failed_login_attempts,
            "unlock_requests": u.unlock_requests,
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        })

    return {"total": total, "users": result}


# =====================================================
# SYSTEM ADMIN — FULL REPORT VIEW
# =====================================================

@_system_settings_router.get("/report/{report_id}/full")
def get_full_report(
    report_id: str,
    engine_url: str = "",   # kept for API compat, ignored
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Return full report for an exam session from RDS (alerts, warnings, S3 proof URLs)."""
    import uuid as _uuid
    from app.core.storage import get_profile_image_url as _presign

    try:
        session_uuid = _uuid.UUID(report_id)
    except ValueError:
        system_logger.warning("get_full_report invalid report_id=%s", report_id)
        raise HTTPException(status_code=400, detail="Invalid report ID")

    session = db.query(models.ExamSession).filter(models.ExamSession.id == session_uuid).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    _backfill_missing_proof_sizes(db, [session.id])

    effective_end = session.end_time or session.terminated_at
    duration_s = (
        max(0, int(round((effective_end - session.start_time).total_seconds())))
        if session.start_time and effective_end else None
    )

    alert_log = []
    for a in session.proctor_alerts:
        entry: dict = {
            "_type":       "alert",
            "key":         a.alert_key,
            "message":     a.message,
            "score_added": a.score_added,
            "elapsed_s":   a.elapsed_s,
            "time":        a.time_str,
        }
        if a.proof_s3_key:
            url = _presign(a.proof_s3_key, expires_in=3600)
            if url:
                entry["proof_url"]  = url
                entry["proof_type"] = a.proof_type or "image"
        alert_log.append(entry)

    warning_log = [
        {
            "_type":     "warning",
            "message":   w.message,
            "elapsed_s": w.elapsed_s,
            "time":      w.time_str,
        }
        for w in session.proctor_warnings
    ]

    return {
        "report_id":     report_id,
        "risk_state":    session.status,
        "final_score":   session.risk_score,
        "alert_count":   len(alert_log),
        "warning_count": len(warning_log),
        "size_kb":       round(
            sum(
                (a.proof_size_bytes or 0)
                for a in session.proctor_alerts
                if a.proof_s3_key and (a.proof_type or "image") != "audio"
            ) / 1024,
            1,
        ),
        "proof_count":   sum(1 for a in session.proctor_alerts if a.proof_s3_key),
        "duration_s":    duration_s,
        "terminated":    session.status == "TERMINATED",
        "session_start": session.start_time.isoformat() if session.start_time else None,
        "session_end":   effective_end.isoformat() if effective_end else None,
        "alert_log":     alert_log,
        "warning_log":   warning_log,
    }


# =====================================================
# SYSTEM ADMIN — DELETE ALL REPORTS
# =====================================================

@_system_settings_router.delete("/reports")
async def delete_all_reports(
    db: Session = Depends(get_db),
    _=Depends(require_role("SYSADMIN")),
):
    """Delete all stored proof images while preserving report rows and alert history."""
    from app.core.storage import delete_s3_objects

    proof_alerts = (
        db.query(models.ProctorAlert)
        .filter(
            models.ProctorAlert.proof_s3_key.isnot(None),
            (models.ProctorAlert.proof_type.is_(None) | (models.ProctorAlert.proof_type != "audio")),
        )
        .all()
    )

    keys = [alert.proof_s3_key for alert in proof_alerts if alert.proof_s3_key]
    deleted_total, errors = delete_s3_objects(keys)

    for alert in proof_alerts:
        alert.proof_s3_key = None
        alert.proof_size_bytes = None

    db.commit()
    log.info("SYSADMIN deleted %d proof image(s) across all reports", deleted_total)
    return {
        "deleted_proofs": deleted_total,
        "affected_reports": len({str(alert.session_id) for alert in proof_alerts}),
        "errors": errors,
    }


# =====================================================
# PROOF PROXY — accessible to both ADMIN and SYSADMIN
# =====================================================

@_system_settings_router.get("/proxy-proof")
async def proxy_proof(
    engine_url: str,
    path: str,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.SYSADMIN)),
):
    """
    Proxy a proof file (image/audio) from an engine container.
    path should be like /proofs/20260325_abc123.jpg
    """
    import httpx as _httpx
    from fastapi.responses import Response as FastAPIResponse

    container = db.query(models.EngineContainer).filter(
        models.EngineContainer.url == engine_url
    ).first()
    if not container:
        raise HTTPException(status_code=400, detail="Unknown engine URL")

    if not path.startswith("/"):
        path = "/" + path

    full_url = f"{engine_url.rstrip('/')}{path}"
    async with _httpx.AsyncClient(timeout=_httpx.Timeout(connect=4.0, read=30.0, write=4.0, pool=4.0)) as client:
        try:
            r = await client.get(full_url)
            r.raise_for_status()
            content_type = r.headers.get("content-type", "application/octet-stream")
            return FastAPIResponse(content=r.content, media_type=content_type)
        except _httpx.HTTPStatusError as exc:
            system_logger.warning(
                "proxy_proof not found on engine engine_url=%s path=%s status=%s",
                engine_url,
                path,
                exc.response.status_code if exc.response else None,
            )
            raise HTTPException(status_code=exc.response.status_code, detail="Proof not found on engine")
        except Exception as exc:
            system_logger.error(
                "proxy_proof engine unreachable engine_url=%s path=%s error=%s",
                engine_url,
                path,
                exc,
            )
            raise HTTPException(status_code=502, detail=f"Engine unreachable: {exc}")
