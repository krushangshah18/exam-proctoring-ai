# Business logic
import secrets
import hashlib
from datetime import datetime, timedelta, UTC

from sqlalchemy.orm import Session

from app.db import models
from app.core import settings
from app.core import send_email



def create_reset_token(db: Session, user: models.User):

    raw_token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        raw_token.encode()
    ).hexdigest()

    expires = datetime.now(UTC) + timedelta(
        minutes=settings.RESET_TOKEN_EXPIRE_MINUTES
    )

    record = models.PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires
    )

    db.add(record)
    db.commit()

    return raw_token


def send_reset_email(user: models.User, token: str):

    link = (
        f"{settings.FRONTEND_URL}"
        f"/reset-password?token={token}"
    )

    body = f"""
Hello {user.full_name},

Click below to reset password:

{link}

This link expires in 15 minutes.

If not requested, ignore.
"""

    send_email(
        user.email,
        "Reset Your Password",
        body
    )
