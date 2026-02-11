import random
import json
import hashlib
from datetime import timedelta

from app.core import settings
from app.core.redis import redis_client


OTP_TTL = settings.OTP_EXPIRE_MINUTES * 60
MAX_ATTEMPTS = 3


# -------------------------
# Core Helpers
# -------------------------

def generate_otp() -> str:
    """Generate 6 digit OTP"""
    return str(random.randint(100000, 999999))


def _hash_otp(otp: str) -> str:
    raw = otp + settings.OTP_SECRET
    return hashlib.sha256(raw.encode()).hexdigest()


def _key(scope: str, user_id: str, fingerprint: str | None = None):
    """
    scope: device / unlock / reset
    """
    if fingerprint:
        return f"otp:{scope}:{user_id}:{fingerprint}"

    return f"otp:{scope}:{user_id}"


# -------------------------
# Store OTP
# -------------------------

def store_otp(
    scope: str,
    user_id: str,
    otp: str,
    fingerprint: str | None = None
):

    key = _key(scope, user_id, fingerprint)

    data = {
        "otp": _hash_otp(otp),
        "attempts": 0
    }

    redis_client.setex(
        key,
        OTP_TTL,
        json.dumps(data)
    )


# -------------------------
# Verify OTP
# -------------------------

def verify_otp(
    scope: str,
    user_id: str,
    otp: str,
    fingerprint: str | None = None
) -> bool:

    key = _key(scope, user_id, fingerprint)

    raw = redis_client.get(key)

    if not raw:
        return False

    data = json.loads(raw)

    # Too many attempts
    if data["attempts"] >= MAX_ATTEMPTS:
        redis_client.delete(key)
        return False

    # Verify hash
    if _hash_otp(otp) == data["otp"]:
        redis_client.delete(key)
        return True

    # Failed
    data["attempts"] += 1

    redis_client.setex(
        key,
        OTP_TTL,
        json.dumps(data)
    )

    return False


# -------------------------
# Clear OTP
# -------------------------

def clear_otp(
    scope: str,
    user_id: str,
    fingerprint: str | None = None
):

    redis_client.delete(
        _key(scope, user_id, fingerprint)
    )
