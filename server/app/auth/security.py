# Hashing + JWT
"""
This file will handle:
✔ Password hashing
✔ Password verification
✔ JWT creation
✔ JWT validation
"""

from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core import settings
from app.core import log

from uuid import uuid4
from app.db import models

# Password Hashing (ARGON2)
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated = "auto"
)

def hash_password(password):
    """
    Hash plain password using Argon2.
    """
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    """
    Verify plain password against hash.
    """
    return pwd_context.verify(plain, hashed)


# TOKEN CREATION
def create_access_token(data, expires_delta = None):
    """
    Create short-lived access token.
    """
    to_encode = data.copy()
    expire = datetime.now() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode.update({"exp": expire, "type": "access"})

    token = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    log.debug("Access token created")
    return token

def create_refresh_token(user_id, device_fingerprint, db):
    """
    Create and persist refresh token.
    """

    expire = datetime.now() + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    token = str(uuid4())

    refresh = models.RefreshToken(
        user_id=user_id,
        token=token,
        device_fingerprint=device_fingerprint,
        expires_at=expire,
        revoked=False
    )

    db.add(refresh)
    db.flush()

    log.debug("Refresh token created")
    return token


# TOKEN VERIFICATION
def decode_token(token):
    """
    Decode and validate JWT token.
    Raises exception if invalid.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )

        return payload

    except JWTError as e:
        log.warning("Invalid JWT token: %s", str(e))
        raise ValueError("Invalid or expired token")
