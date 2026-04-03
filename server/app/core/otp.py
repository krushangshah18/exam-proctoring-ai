import random
import json
import hashlib
from datetime import timedelta

from app.core import settings, log
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

    try:
        redis_client.setex(
            key,
            OTP_TTL,
            json.dumps(data),
        )
    except Exception as e:
        log.exception(
            "Failed to store OTP scope=%s user_id=%s fingerprint=%s: %s",
            scope,
            user_id,
            fingerprint,
            e,
        )
        raise


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

    try:
        raw = redis_client.get(key)
    except Exception as e:
        log.exception(
            "Failed to verify OTP (redis get) scope=%s user_id=%s fingerprint=%s: %s",
            scope,
            user_id,
            fingerprint,
            e,
        )
        return False

    if not raw:
        return False

    data = json.loads(raw)

    # Too many attempts
    if data["attempts"] >= MAX_ATTEMPTS:
        try:
            redis_client.delete(key)
        except Exception as e:
            log.exception(
                "Failed to delete expired/blocked OTP scope=%s user_id=%s fingerprint=%s: %s",
                scope,
                user_id,
                fingerprint,
                e,
            )
        return False

    # Verify hash
    if _hash_otp(otp) == data["otp"]:
        try:
            redis_client.delete(key)
        except Exception as e:
            log.exception(
                "Failed to delete verified OTP scope=%s user_id=%s fingerprint=%s: %s",
                scope,
                user_id,
                fingerprint,
                e,
            )
        return True

    # Failed
    data["attempts"] += 1

    try:
        redis_client.setex(
            key,
            OTP_TTL,
            json.dumps(data),
        )
    except Exception as e:
        log.exception(
            "Failed to update OTP attempts scope=%s user_id=%s fingerprint=%s: %s",
            scope,
            user_id,
            fingerprint,
            e,
        )
        return False

    return False


# -------------------------
# Clear OTP
# -------------------------

def clear_otp(
    scope: str,
    user_id: str,
    fingerprint: str | None = None
):

    try:
        redis_client.delete(
            _key(scope, user_id, fingerprint)
        )
    except Exception as e:
        log.exception(
            "Failed to clear OTP scope=%s user_id=%s fingerprint=%s: %s",
            scope,
            user_id,
            fingerprint,
            e,
        )
