# API endpoints
import hashlib
from pydantic import EmailStr
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request, UploadFile, File
from sqlalchemy.orm import Session

from app.core.device_otp import store_device_otp, verify_device_otp
from app.core.otp import(generate_otp, store_otp, verify_otp)
from app.db import get_db
from app.db import models
from app.db.enums import UserRole, SessionStatus

from app.auth.schemas import (
    UserAdminCreate,
    UnlockVerifyRequest,
    DeviceOut,
    UpdateProfile,
    UserLogin,
    TokenResponse,
    LoginResponse,
    LoginOTPResponse,
    ChangePassword,
    RefreshRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    UserStudentCreate,
    DeviceVerifyRequest, 
    DeviceVerifyResponse
)

from app.auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token
)

from app.auth.service import(
    create_reset_token,
    send_reset_email
)
from app.core import log, settings, generate_fingerprint, rate_limit, send_email, validate_single_face, generate_embedding, save_profile_image, can_update_profile_image, verify_same_person
from app.auth.dependencies import (get_current_user,require_role)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# REGISTER
# @router.post("/register/admin",status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_role(UserRole.SYSADMIN))])
# def register_admin(user: UserAdminCreate, request: Request, db:Session = Depends(get_db)):
#     """
#     Register new ADMIN (SYSADMIN only)
#     """
#     ip = request.client.host

#     existing = (
#         db.query(models.User)
#         .filter(models.User.email == user.email,
#                 models.User.is_active == True
#         )
#         .first()
#     )

#     if existing:
#         log.warning(
#             "Admin register failed: email exists (%s) ip=%s",
#             user.email,
#             ip
#         )

#         raise HTTPException(
#             status_code=400,
#             detail="Email already registered"
#         )

#     hashed = hash_password(user.password)

#     new_user = models.User(
#         email=user.email,
#         full_name=user.full_name,
#         password_hash=hashed,
#         role=UserRole.ADMIN.value,
#         is_active=True
#     )

#     db.add(new_user)
#     db.commit()
#     db.refresh(new_user)

#     log.info(
#         "Admin created: id=%s email=%s by=%s ip=%s",
#         new_user.id,
#         new_user.email,
#         request.state.user_id,
#         ip
#     )

#     return {
#         "message": "Admin registered successfully",
#         "id": str(new_user.id),
#         "email": new_user.email,
#     }

@router.post("/register/student",status_code=status.HTTP_201_CREATED)
@rate_limit("register_student", limit=3, window=600)
async def register_student(
    request: Request,
    user: UserStudentCreate = Depends(UserStudentCreate.as_form),
    selfie: UploadFile = File(...),
    db: Session = Depends(get_db),
    ):
    """
    Register student with selfie verification
    """

    ip = request.client.host

    # Check file type
    if selfie.content_type not in ["image/jpeg", "image/png", "image/jpg"]:
        raise HTTPException(400, "Invalid image format")

    # Check duplicate
    existing = (
        db.query(models.User)
        .filter(models.User.email == user.email)
        .first()
    )

    if existing:
        if existing.is_active:
            log.warning("Student register failed: exists %s ip=%s", user.email, ip)
            raise HTTPException(status_code=400, detail="Email already registered")
        # Reactivate
        existing.is_active = True
        existing.deleted_at = None
        existing.password_hash = hash_password(user.password)
        existing.full_name = user.full_name

        db.commit()

        return {"message": "Account reactivated"}
    
    #Consent in Registration
    if not user.consent:
        raise HTTPException(
            status_code=400,
            detail="You must accept privacy policy"
        )

    # Read image
    data = await selfie.read()

    # Face validation
    # image = load_image(data)
    try: 
        face_box = validate_single_face(data)
    except ValueError as e:
        error_msg = str(e)
        log.warning("Face validation failed: %s ip=%s", str(e), request.client.host)
        
        if "multiple" in error_msg.lower():
            detail = "Multiple faces detected. Please ensure only your face is visible."

        elif "no face" in error_msg.lower():
            detail = "No face detected. Please retake your selfie."

        else:
            detail = "Invalid image. Please upload a clear selfie."

        raise HTTPException(status_code=400,detail=detail)

    try:
        embedding = generate_embedding(data, face_box)

    except ValueError as e:
        log.warning("Embedding failed: %s ip=%s", str(e), request.client.host)
        raise HTTPException(status_code=400,detail=str(e))

    # Create user
    hashed = hash_password(user.password)

    new_user = models.User(
        email=user.email,
        full_name=user.full_name,
        password_hash=hashed,
        role=UserRole.STUDENT.value,
        is_active=True,
        face_embedding=embedding,
        consent_given=True,
        consent_at=datetime.now(),
        privacy_version="v1.0-2026"

    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Save image
    path = save_profile_image(new_user.id, data)
    new_user.profile_image_path = path
    db.commit()

    log.info(
        "Student registered: id=%s email=%s ip=%s",
        new_user.id,
        new_user.email,
        ip
    )

    return {"message": "Student registration successful"}



# LOGIN
@router.post("/login", response_model=LoginResponse)
@rate_limit("login", limit=3, window=60)
def login_user(data: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate user and return tokens.
    """
    ip = request.client.host

    user = (
        db.query(models.User)
        .filter(models.User.email == data.email,
                models.User.is_active == True,
                models.User.deleted_at.is_(None),
        )
        .first()
    )

    if not user:
        log.warning(
            "Login failed: no user (%s) ip=%s",
            data.email,
            ip
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    now = datetime.now()
    if user.locked_until and user.locked_until > now:
        raise HTTPException(
            status_code=403,
            detail="Account locked. Try again later."
        )


    if not verify_password(
        data.password,
        user.password_hash
        ):

        log.warning(
            "Login failed: bad password (%s) ip=%s",
            data.email,
            ip
        )

        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=settings.ACCOUNT_LOCK_FAILED_LOGIN_MINUTES)
            user.unlock_requests = 0

            audit = models.AuditLog(
                actor_id=user.id,
                action="ACCOUNT_LOCKED",
                target=f"user:{user.email}",
                ip_address=request.client.host
            )
            db.add(audit)
            db.commit()
            send_email(
            to=user.email,
            subject="Security Alert: Account Locked",
            body=f"""
                Multiple failed login attempts detected.

                Your account is locked for {settings.ACCOUNT_LOCK_FAILED_LOGIN_MINUTES} minutes.

                If this wasn't you, reset your password.
                """
                    )
        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    fingerprint = generate_fingerprint(request)
    # Always compute active devices first
    active_devices = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == user.id,
            models.UserDevice.revoked == False
        )
        .count()
    )
    log.info(
        "Login device check user=%s devices=%s fingerprint=%s",
        user.id,
        active_devices,
        fingerprint[:8]
    )
    device = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == user.id,
            models.UserDevice.fingerprint == fingerprint,
            models.UserDevice.revoked == False
        )
        .first()
    )


# ---------------- FIRST DEVICE → AUTO TRUST ----------------
    if active_devices == 0:

        device = models.UserDevice(
            user_id=user.id,
            fingerprint=fingerprint,
            trusted=True,
            pending=False,
            revoked=False,
            user_agent=request.headers.get("user-agent"),
            ip_address=request.client.host,
            last_seen=datetime.now()
        )

        db.add(device)
        db.commit()

    # ---------------- EXISTING DEVICE ----------------
    elif device and not device.pending:

        device.last_seen = datetime.now()
        db.commit()

    # ---------------- NEW DEVICE → OTP ----------------
    else:
        trusted_count = (
            db.query(models.UserDevice)
            .filter(
                models.UserDevice.user_id == user.id,
                models.UserDevice.trusted == True,
                models.UserDevice.revoked == False
            )
            .count()
        )

        if trusted_count >= settings.MAX_TRUSTED_DEVICES:

            # revoke oldest
            old = (
                db.query(models.UserDevice)
                .filter(
                    models.UserDevice.user_id == user.id,
                    models.UserDevice.trusted == True,
                    models.UserDevice.revoked == False
                )
                .order_by(models.UserDevice.created_at.asc())
                .first()
            )

            if old:
                old.revoked = True

        device = models.UserDevice(
            user_id=user.id,
            fingerprint=fingerprint,
            trusted=False,
            pending=True,
            revoked=False,
            user_agent=request.headers.get("user-agent"),
            ip_address=request.client.host,
            last_seen=datetime.now()
        )
        db.add(device)
        db.commit()


        otp = generate_otp()

        store_device_otp(
            user.id,
            fingerprint,
            otp
        )

        send_email(
            to=user.email,
            subject="New Device Verification",
            body=f"""
        Your login attempt requires verification.

        OTP: {otp}

        Valid for {settings.OTP_EXPIRE_MINUTES} minutes.
        """
        )

        return LoginOTPResponse(
            message="OTP sent to your email"
        )

    access = create_access_token(
        data={  "sub": str(user.id),
                "device": fingerprint
             }
    )

    refresh = create_refresh_token(user_id= user.id, device_fingerprint=fingerprint, db=db)

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = now

    db.commit()

    log.info(
        "Login success: id=%s ip=%s",
        user.id,
        ip
    )

    return TokenResponse(
        access_token=access,
        refresh_token=refresh
    )


# CHANGE PASSWORD
@router.post("/change-password")
def change_password(
    data: ChangePassword,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change password for logged-in user.
    """

    if not verify_password(
        data.old_password,
        current_user.password_hash
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid current password"
        )

    current_user.password_hash = hash_password(
        data.new_password
    )

    db.commit()
    log.info(f"Password changed: {current_user.id}")

    return {"message": "Password changed successfully"}


@router.get("/me")
def get_me(current_user=Depends(get_current_user)):
    """
    Return logged-in user profile.
    """

    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(data: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    """
    Issue new access token using refresh token.
    """
    now = datetime.now()
    fingerprint = generate_fingerprint(request)

    token_obj = (
        db.query(models.RefreshToken)
        .filter(
            models.RefreshToken.token == data.refresh_token,
            models.RefreshToken.revoked == False
        )
        .first()
    )

    if not token_obj:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if token_obj.expires_at < now:
        raise HTTPException(status_code=401,detail="Refresh token expired")
    if token_obj.device_fingerprint != fingerprint:
        raise HTTPException(403, "Device mismatch")

    user = (
        db.query(models.User)
        .filter(
            models.User.id == token_obj.user_id,
            models.User.is_active == True,
            models.User.deleted_at.is_(None)
        )
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User inactive"
        )

    if user.locked_until and user.locked_until > now:
        raise HTTPException(403, "Account locked")
    
    token_obj.revoked = True

    access = create_access_token(
        data={"sub": str(user.id),
              "device": token_obj.device_fingerprint
              }
    )

    refresh = create_refresh_token(
        user_id=str(user.id),
        device_fingerprint=fingerprint,
        db=db
    )

    db.commit()

    return TokenResponse(
        access_token=access,
        refresh_token=refresh
    )


#Forgot Password
@router.post("/forgot-password")
@rate_limit("forgot", limit=3, window=300)
def forgot_password(
    data: ForgotPasswordRequest,
    db: Session = Depends(get_db)
    ):

    user = db.query(models.User).filter(
        models.User.email == data.email,
        models.User.is_active == True
    ).first()

    # Prevent user enumeration
    if not user:
        return {"message": "If email exists, reset link sent"}

    log.info(f"Password reset requested: {user.email}")

    token = create_reset_token(db, user)

    send_reset_email(user, token)

    return {"message": "If email exists, reset link sent"}


@router.post("/reset-password")
def reset_password(
    data: ResetPasswordRequest,
    db: Session = Depends(get_db)
):

    token_hash = hashlib.sha256(
        data.token.encode()
    ).hexdigest()

    record = db.query(models.PasswordResetToken).filter(
        models.PasswordResetToken.token_hash == token_hash,
        models.PasswordResetToken.used == False,
        models.PasswordResetToken.expires_at > datetime.now()
    ).first()

    if not record:
        log.warning(f"Invalid reset attempt: {data.token[:6]}")

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired token"
        )

    user = db.query(models.User).get(record.user_id)

    user.password_hash = hash_password(data.new_password)

    record.used = True

    db.commit()

    return {"message": "Password reset successful"}


@router.post("/logout")
def logout(
    request: Request,
    data: RefreshRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    """
    Logout user by revoking refresh token
    """

    token = (
        db.query(models.RefreshToken)
        .filter(
            models.RefreshToken.token == data.refresh_token,
            models.RefreshToken.user_id == user.id,
            models.RefreshToken.is_active == True
        )
        .first()
    )

    if token:
        token.is_active = False

    device = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == user.id,
            models.UserDevice.fingerprint == request.state.device_id
        )
        .first()
    )

    if device:
        device.revoked = True


    db.commit()

    return {"message": "Logged out successfully"}


def has_active_exam(db, user_id):
    return (
        db.query(models.ExamSession)
        .filter(
            models.ExamSession.user_id == user_id,
            models.ExamSession.status.in_([
                SessionStatus.CREATED.value,
                SessionStatus.ACTIVE.value,
                SessionStatus.DISCONNECTED.value,
            ])
        )
        .first()
        is not None
    )

@router.delete("/me")
def delete_account(
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    """
    Soft delete user account
    """

    if has_active_exam(db, user.id):
        raise HTTPException(
            400,
            "Cannot delete account during active exam"
        )

    user.is_active = False
    user.deleted_at = datetime.now()

    # Revoke all refresh tokens
    (
        db.query(models.RefreshToken)
        .filter(
            models.RefreshToken.user_id == user.id,
            models.RefreshToken.is_active == True
        )
        .update({"is_active": False})
    )

    db.commit()

    return {"message": "Account deactivated"}


@router.put("/me/profile")
def update_profile(data: UpdateProfile, 
                   request: Request,
                   db: Session = Depends(get_db),
                   current_user=Depends(get_current_user)
                   ):
    """
    Update basic profile
    """
    current_user.full_name = data.full_name

    audit = models.AuditLog(
        actor_id=current_user.id,
        action="UPDATE_PROFILE",
        target=f"user:{current_user.id}",
        ip_address=request.client.host
    )

    db.add(audit)
    db.commit()

    return {"message": "Profile updated"}


@router.put("/me/profile-image")
async def update_profile_image(
    selfie: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Update profile image (Students only)
    """

    # ---------------- Role Check ----------------
    if current_user.role != UserRole.STUDENT.value:
        raise HTTPException(403, "Only students can update selfie")

    # ---------------- Exam Lock ----------------
    active_exam = (
        db.query(models.ExamSession)
        .filter(
            models.ExamSession.user_id == current_user.id,
            models.ExamSession.status == SessionStatus.ACTIVE.value
        )
        .first()
    )

    if active_exam:
        raise HTTPException(
            403,
            "Cannot update profile during active exam"
        )

    # ---------------- Cooldown ----------------
    if not can_update_profile_image(current_user):
        raise HTTPException(
            403,
            "Profile image can be updated only once every 30 days"
        )

    # ---------------- Validate Image ----------------
        # Check file type
    if selfie.content_type not in ["image/jpeg", "image/png", "image/jpg"]:
        raise HTTPException(400, "Invalid image format")
    try:
        data = await selfie.read()

        if not data:
            raise ValueError("Empty image file")

        # Face detection
        face_box = validate_single_face(data)
        
        # Generate embedding
        new_embedding = generate_embedding(data, face_box)

    except ValueError as e:
        log.exception("Profile image processing error while updating user=%s", current_user.id)

        raise HTTPException(
            500,
            f"Image processing failed. Please try again. : {e}"
        )


    # ---------------- Verify Same Person ----------------
    if current_user.face_embedding:
        try:
            is_same = verify_same_person(
                current_user.face_embedding,
                new_embedding
            )
        except ValueError as e:
            log.error("Face verification error user=%s error=%s",current_user.id,e)
            raise HTTPException(400,"Face verification failed")


        if not is_same:
            log.warning(
                "Profile image mismatch user=%s",
                current_user.id
            )

            raise HTTPException(
                403,
                "Face verification failed"
            )

    # ---------------- Save Image ----------------
    try:
        path = save_profile_image(
            user_id=str(current_user.id),
            data=data
        )
    except Exception as e:
        log.exception("Profile image save failed user=%s", current_user.id)
        raise HTTPException(500,"Failed to save image")

    # ---------------- Update DB ----------------
    try:
        current_user.profile_image_path = path
        current_user.face_embedding = new_embedding

        current_user.last_profile_image_update = datetime.now()
        
        db.add(current_user)
        db.commit()

    except Exception:
        db.rollback()
        log.exception("Profile image DB update failed user=%s", current_user.id)
        raise HTTPException(500,"Failed to update profile")


    # ---------------- Audit ----------------
    try: 
        audit = models.AuditLog(
            actor_id=current_user.id,
            action="UPDATE_PROFILE_IMAGE",
            target=f"user:{current_user.id}",
            ip_address=None
        )

        db.add(audit)
        db.commit()
    except Exception:
        db.rollback()
        log.exception("Audit log failed user=%s", current_user.id)

    log.info(
        "Profile image updated user=%s",
        current_user.id
    )

    return {"message": "Profile image updated successfully"}


@router.post("/unlock/request")
def request_unlock(
    data: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    user = (
        db.query(models.User)
        .filter(
            models.User.email == data.email,
            models.User.is_active == True
        )
        .first()
    )

    if not user:
        return {"message": "If account exists, OTP sent"}

    if not user.locked_until:
        raise HTTPException(400, "Account not locked")

    if user.unlock_requests >= settings.MAX_UNLOCK_REQUESTS:
        raise HTTPException(
            403,
            "Max unlock attempts exceeded. Contact admin."
        )

    otp = generate_otp()
    # otp_hash = hash_otp(otp)

    # token = models.AccountUnlockToken(
    #     user_id=user.id,
    #     otp_hash=otp_hash,
    #     expires_at=get_expiry()
    # )
    store_otp("unlock", str(user.id), otp)

    # db.add(token)
    user.unlock_requests += 1


    # Audit
    audit = models.AuditLog(
        actor_id=user.id,
        action="UNLOCK_OTP_SENT",
        target=f"user:{user.id}",
        ip_address=request.client.host
    )

    db.add(audit)

    db.commit()

    send_email(
        to=user.email,
        subject="Unlock OTP",
        body=f"""
            Your OTP: {otp}

            Valid for 10 minutes.
            """
        )

    return {"message": "OTP sent"}


@router.post("/unlock/verify")
def verify_unlock(
    data: UnlockVerifyRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    email, otp = data.email, data.otp
    user = (
        db.query(models.User)
        .filter(
            models.User.email == email,
            models.User.is_active == True
        )
        .first()
    )

    if not user:
        raise HTTPException(400, "Invalid OTP")

    is_valid = verify_otp("unlock", str(user.id), otp)

    if not is_valid:
        raise HTTPException(400, "Invalid or expired OTP")

    # token = (
    #     db.query(models.AccountUnlockToken)
    #     .filter(
    #         models.AccountUnlockToken.user_id == user.id,
    #         models.AccountUnlockToken.used == False,
    #         models.AccountUnlockToken.expires_at > datetime.utcnow()
    #     )
    #     .order_by(models.AccountUnlockToken.created_at.desc())
    #     .first()
    # )

    # if not token:
    #     raise HTTPException(400, "OTP expired")

    # if token.attempts >= settings.MAX_OTP_ATTEMPTS:
    #     raise HTTPException(403, "OTP locked")

    # if not verify_otp(otp, token.otp_hash):

    #     token.attempts += 1

    #     db.commit()

    #     raise HTTPException(400, "Invalid OTP")

    # ---------------- SUCCESS ----------------

    # token.used = True

    user.failed_login_attempts = 0
    user.locked_until = None
    user.unlock_requests = 0

    audit = models.AuditLog(
        actor_id=user.id,
        action="ACCOUNT_UNLOCKED",
        target=f"user:{user.id}",
        ip_address=request.client.host
    )

    db.add(audit)

    db.commit()

    return {"message": "Account unlocked"}


@router.post(
    "/device/verify",
    response_model=DeviceVerifyResponse
)
def verify_device(
    data: DeviceVerifyRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Verify new device via OTP
    """

    user = (
        db.query(models.User)
        .filter(
            models.User.email == data.email,
            models.User.is_active == True
        )
        .first()
    )

    if not user:
        raise HTTPException(400, "Invalid request")

    fingerprint = generate_fingerprint(request)

    if not verify_device_otp(
        str(user.id),
        fingerprint,
        data.otp
    ):
        raise HTTPException(400, "Invalid OTP")

    device = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == user.id,
            models.UserDevice.fingerprint == fingerprint,
            models.UserDevice.pending == True,
            models.UserDevice.revoked == False
        )
        .first()
    )

    if not device:
        raise HTTPException(400, "Device not found")

    # Approve device
    device.trusted = True
    device.pending = False
    device.last_seen = datetime.utcnow()

    # Tokens
    access = create_access_token(
        {
            "sub": str(user.id),
            "type": "access",
            "device": fingerprint
        }
    )

    refresh = create_refresh_token(user_id= user.id, device_fingerprint=fingerprint, db=db)

    # Audit
    audit = models.AuditLog(
        actor_id=user.id,
        action="DEVICE_VERIFIED",
        target=f"device:{fingerprint}",
        ip_address=request.client.host
    )

    db.add(audit)
    db.commit()

    return DeviceVerifyResponse(
        access_token=access,
        refresh_token=refresh
    )


@router.get("/devices/me", response_model=list[DeviceOut])
def my_devices(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Get all active devices for current user
    """

    devices = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == current_user.id,
            models.UserDevice.revoked == False
        )
        .order_by(models.UserDevice.created_at.desc())
        .all()
    )

    return devices


@router.get("/devices/user/{user_id}", response_model=list[DeviceOut])
def get_user_devices(
    user_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.SYSADMIN))
):
    """
    Admin: Get devices of any user
    """

    devices = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.user_id == user_id
        )
        .order_by(models.UserDevice.created_at.desc())
        .all()
    )

    return devices
