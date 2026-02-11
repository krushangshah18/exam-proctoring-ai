from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime

from app.db import models
from app.db import get_db
from app.auth.schemas import (
    AdminApplyRequest,
    AdminReviewRequest,
)
from app.auth.dependencies import get_current_user, require_role
from app.db.enums import ApplicationStatus, UserRole, SessionStatus
from app.core import log, rate_limit, send_email 
from app.auth.security import hash_password

router = APIRouter(
    prefix="/admin-applications",
    tags=["Admin Applications"]
)

@router.post("/apply", status_code=201)
@rate_limit("admin_apply", 2, 3600)
def apply_admin(
    data: AdminApplyRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Public: Submit admin application
    """

    ip = request.client.host

    existing = (
        db.query(models.AdminApplication)
        .filter(
            models.AdminApplication.email == data.email,
            models.AdminApplication.status.in_([
                ApplicationStatus.PENDING.value,
                ApplicationStatus.APPROVED.value
            ])
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Application already processed"
        )

    app = models.AdminApplication(
        full_name=data.full_name,
        email=data.email,
        organization=data.organization,
        contact_number=data.contact_number,
        reason=data.reason
    )

    db.add(app)
    db.commit()
    db.refresh(app)

    log.info(
        "Admin application submitted email=%s ip=%s",
        data.email,
        ip
    )

    return {
        "message": "Application submitted successfully"
    }


@router.get("",dependencies=[Depends(require_role(UserRole.SYSADMIN))])
def list_applications(db: Session = Depends(get_db)):
    """
    SYSADMIN: View all admin applications
    """

    return (
        db.query(models.AdminApplication)
        .order_by(models.AdminApplication.created_at.desc())
        .all()
    )


def _generate_temp_password() -> str:
    import secrets
    return secrets.token_urlsafe(10)

@router.post("/{app_id}/review",dependencies=[Depends(require_role(UserRole.SYSADMIN))])
def review_application(
    app_id: str,
    data: AdminReviewRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
    ):
    """
    SYSADMIN: Approve or reject admin application
    """

    ip = request.client.host

    app = (
        db.query(models.AdminApplication)
        .filter(models.AdminApplication.id == app_id)
        .first()
    )

    if not app:
        raise HTTPException(404, "Application not found")

    if app.status != ApplicationStatus.PENDING.value:
        raise HTTPException(400, "Already reviewed")

    # ---------------- APPROVE ----------------
    if data.approve:

        user = (
        db.query(models.User)
        .filter(models.User.email == app.email)
        .first()
    )

        # ---------------- CASE 1: Active Admin ----------------
        if user and user.is_active and user.role == UserRole.ADMIN.value:
            raise HTTPException(400, "User is already admin")

        # ---------------- CASE 2: Active Student → Promote ----------------
        if user and user.is_active and user.role == UserRole.STUDENT.value:

            user.role = UserRole.ADMIN.value
            admin = user

            audit_action = "PROMOTE_TO_ADMIN"

            send_email(
                to=app.email,
                subject="Admin Role Granted",
                body="""
    Your account has been upgraded to ADMIN.

    You can now manage exams.

    - Exam Proctoring Team
    """
            )

        # ---------------- CASE 3: Deleted User → Reactivate ----------------
        elif user and not user.is_active:

            temp_password = _generate_temp_password()
            hashed = hash_password(temp_password)

            user.is_active = True
            user.deleted_at = None
            user.role = UserRole.ADMIN.value
            user.password_hash = hashed

            admin = user
            audit_action = "REACTIVATE_ADMIN"

            send_email(
                to=app.email,
                subject="Admin Account Reactivated",
                body=f"""
    Hello {app.full_name},

    Your admin account has been reactivated.

    Login email: {app.email}
    Temporary password: {temp_password}

    Please change your password after login.

    - Exam Proctoring Team
    """
            )

        # ---------------- CASE 4: New User ----------------
        else:

            temp_password = _generate_temp_password()
            hashed = hash_password(temp_password)

            admin = models.User(
                email=app.email,
                full_name=app.full_name,
                password_hash=hashed,
                role=UserRole.ADMIN.value,
                is_active=True
            )

            db.add(admin)

            audit_action = "APPROVE_ADMIN_APPLICATION"

            send_email(
                to=app.email,
                subject="Admin Account Approved",
                body=f"""
    Hello {app.full_name},

    Your admin account has been approved.

    Login email: {app.email}
    Temporary password: {temp_password}

    Please change your password after login.

    - Exam Proctoring Team
    """
            )

        # ---------------- UPDATE APPLICATION ----------------

        app.status = ApplicationStatus.APPROVED.value
        app.reviewed_by = current_user.id
        app.approved_at = datetime.now()
        app.review_note = data.review_note

        audit = models.AuditLog(
            actor_id=current_user.id,
            action=audit_action,
            target=f"user:{app.email}",
            ip_address=ip
        )

        db.add(audit)

        log.info(
            "Admin approved email=%s by=%s action=%s",
            app.email,
            current_user.id,
            audit_action
        )


    # ---------------- REJECT ----------------
    else:

        app.status = ApplicationStatus.REJECTED.value
        app.reviewed_by = current_user.id
        app.rejected_at = datetime.now()
        app.review_note = data.review_note

        audit = models.AuditLog(
            actor_id=current_user.id,
            action="REJECTED_ADMIN_APPLICATION",
            target=f"user:{app.email}",
            ip_address=ip
        )
        db.add(audit)


        log.info(
            "Admin rejected email=%s by=%s",
            app.email,
            current_user.id
        )    

    db.commit()

    return {"message": "Review completed"}



@router.get("/exams/active")
def get_active_exams(
    db: Session = Depends(get_db),
    admin=Depends(require_role(UserRole.SYSADMIN))
):
    """
    View all active exam sessions
    """

    sessions = (
        db.query(models.ExamSession)
        .filter(
            models.ExamSession.status == SessionStatus.ACTIVE.value
        )
        .all()
    )

    return [
        {
            "session_id": str(s.id),
            "user_id": str(s.user_id),
            "exam_id": s.exam_id,
            "device": s.device_fingerprint,
            "started_at": s.started_at,
            "ip": s.ip_address
        }
        for s in sessions
    ]


@router.post("/devices/revoke/{device_id}")
def revoke_device(
    device_id: str,
    db: Session = Depends(get_db),
    admin=Depends(require_role(UserRole.SYSADMIN))
):
    device = (
        db.query(models.UserDevice)
        .filter(models.UserDevice.id == device_id)
        .first()
    )

    if not device:
        raise HTTPException(404, "Device not found")

    device.revoked = True
    device.trusted = False
    device.pending = False

    db.commit()

    return {"message": "Device revoked"}


@router.post("/users/unlock/{user_id}")
def admin_unlock_user(
    user_id: str,
    db: Session = Depends(get_db),
    admin=Depends(require_role(UserRole.SYSADMIN))
):

    user = (
        db.query(models.User)
        .filter(models.User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(404, "User not found")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.unlock_requests = 0

    db.commit()

    return {"message": "User unlocked"}


@router.post("/exams/kill/{session_id}")
def kill_exam_session(
    session_id: str,
    db: Session = Depends(get_db),
    admin=Depends(require_role(UserRole.SYSADMIN))
):
    """
    Force terminate exam session
    """

    session = (
        db.query(models.ExamSession)
        .filter(models.ExamSession.id == session_id)
        .first()
    )

    if not session:
        raise HTTPException(404, "Session not found")

    # End session
    session.status = SessionStatus.TERMINATED.value
    session.ended_at = datetime.now()

    # Revoke device
    device = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == session.user_id,
            models.UserDevice.fingerprint == session.device_fingerprint
        )
        .first()
    )

    if device:
        device.revoked = True
        device.trusted = False

    # Revoke refresh tokens
    db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id == session.user_id,
        models.RefreshToken.device_fingerprint == session.device_fingerprint
    ).update({"revoked": True})

    db.commit()

    return {
        "message": "Session terminated",
        "session_id": session_id
    }
