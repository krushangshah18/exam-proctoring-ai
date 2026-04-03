import hashlib
from app.core.redis import redis_client
from app.core import settings, log


def _hash_otp(otp: str) -> str:
    return hashlib.sha256(
        (otp + settings.OTP_SECRET).encode()
    ).hexdigest()


def store_device_otp(user_id: str, fingerprint: str, otp: str):

    key = f"device_otp:{user_id}:{fingerprint}"

    try:
        redis_client.setex(
            key,
            settings.OTP_EXPIRE_MINUTES * 60,
            _hash_otp(otp),
        )
    except Exception as e:
        # OTP value is never logged; fingerprint is already a fingerprint identifier.
        log.exception(
            "Failed to store device OTP user_id=%s fingerprint=%s: %s",
            user_id,
            fingerprint,
            e,
        )
        raise


def verify_device_otp(user_id: str, fingerprint: str, otp: str):

    key = f"device_otp:{user_id}:{fingerprint}"

    try:
        stored = redis_client.get(key)
    except Exception as e:
        log.exception(
            "Failed to verify device OTP (redis get) user_id=%s fingerprint=%s: %s",
            user_id,
            fingerprint,
            e,
        )
        return False

    if not stored:
        return False

    if stored != _hash_otp(otp):
        return False

    try:
        redis_client.delete(key)
    except Exception as e:
        # Best-effort cleanup; verification itself already succeeded.
        log.exception(
            "Failed to delete device OTP after verification user_id=%s fingerprint=%s: %s",
            user_id,
            fingerprint,
            e,
        )

    return True
