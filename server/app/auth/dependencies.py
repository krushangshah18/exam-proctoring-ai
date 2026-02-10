from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError

from app.db import get_db
from app.db import models
from app.auth.security import decode_token
from app.core import log


# Token comes from:
# Authorization: Bearer <token>
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Validate JWT and return user.
    """

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub")

        if user_id is None:
            raise credentials_exception

    except JWTError as e:
        log.warning("JWT decode failed: %s", str(e))
        raise credentials_exception

    user = (
        db.query(models.User)
        .filter(
            models.User.id == user_id,
            models.User.is_active == True
        )
        .first()
    )

    if not user:
        log.warning("JWT user not found: %s", user_id)
        raise credentials_exception

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
