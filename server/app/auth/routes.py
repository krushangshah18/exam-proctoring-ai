# API endpoints
import hashlib
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request, UploadFile, File
from sqlalchemy.orm import Session

from app.db import get_db
from app.db import models
from app.db.enums import UserRole, SessionStatus

from app.auth.schemas import (
    UserAdminCreate,
    UpdateProfile,
    UserLogin,
    TokenResponse,
    ChangePassword,
    RefreshRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    UserStudentCreate
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
from app.core import log, load_image, validate_single_face, generate_embedding, save_profile_image, can_update_profile_image, verify_same_person
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
@router.post("/login", response_model=TokenResponse)
def login_user(data: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate user and return tokens.
    """
    ip = request.client.host

    user = (
        db.query(models.User)
        .filter(models.User.email == data.email,
                models.User.is_active == True
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

    if not verify_password(
        data.password,
        user.password_hash
    ):

        log.warning(
            "Login failed: bad password (%s) ip=%s",
            data.email,
            ip
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    access = create_access_token(
        data={"sub": str(user.id)}
    )

    refresh = create_refresh_token(
        user_id=str(user.id),
        db=db
    )

    user.last_login = datetime.now()
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
def refresh_token(data: RefreshRequest, db: Session = Depends(get_db)):
    """
    Issue new access token using refresh token.
    """
    token_value = data.refresh_token

    token_obj = (
        db.query(models.RefreshToken)
        .filter(
            models.RefreshToken.token == token_value,
            models.RefreshToken.revoked == False
        )
        .first()
    )

    if not token_obj:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    if token_obj.expires_at < datetime.now():
        raise HTTPException(
            status_code=401,
            detail="Refresh token expired"
        )

    user = (
        db.query(models.User)
        .filter(
            models.User.id == token_obj.user_id,
            models.User.is_active == True
        )
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User inactive"
        )

    access = create_access_token(
        data={"sub": str(user.id)}
    )

    refresh = create_refresh_token(
        user_id=str(user.id),
        db=db
    )

    # Revoke old
    token_obj.revoked = True
    db.commit()

    return TokenResponse(
        access_token=access,
        refresh_token=refresh
    )


#Forgot Password
@router.post("/forgot-password")
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


