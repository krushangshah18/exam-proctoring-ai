from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError
from urllib3 import request

from app.db import get_db
from app.db import models
from app.auth.security import decode_token
from app.core import log
from datetime import datetime

# Token comes from:
# Authorization: Bearer <token>
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(request: Request,token = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Validate JWT and return user.
    """
    now = datetime.now()

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        request.state.role = payload.get("role")
        # Token type check
        if payload.get("type") != "access":
            raise credentials_exception
        
        user_id = payload.get("sub")
        device_id = payload.get("device")

        if not user_id or not device_id:
            raise credentials_exception
        
        # Device validation
        if not verify_device(payload, db):
            raise HTTPException(401, "Untrusted device")

    except JWTError as e:
        log.warning("JWT decode failed: %s", str(e))
        raise credentials_exception

    user = (
        db.query(models.User)
        .filter(
            models.User.id == user_id,
            models.User.is_active == True,
            models.User.deleted_at.is_(None)
        )
        .first()
    )

    if not user:
        log.warning("JWT user not found: %s", user_id)
        raise credentials_exception
    
    if user.locked_until and user.locked_until > now:
        raise HTTPException(
            403,
            "Account locked"
        )

    request.state.user = user
    request.state.device_id = payload["device"]
    return user


def require_role(*allowed_roles: str):
    """
    Dependency to restrict endpoint access by role.

    Usage:
    Depends(require_role(UserRole.EXAM_ADMIN.value, UserRole.SYSTEM_ADMIN.value))
    """
    def role_checker(current_user=Depends(get_current_user)):
        if not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive account"
            )

        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user

    return role_checker


def verify_device(payload, db):

    device_id = payload.get("device")

    if not device_id:
        raise HTTPException(401, "Invalid token")

    device = (
        db.query(models.UserDevice)
        .filter(
            models.UserDevice.fingerprint == device_id,
            models.UserDevice.revoked == False
        )
        .first()
    )

    if not device:
        raise HTTPException(401, "Device revoked")

    return device
