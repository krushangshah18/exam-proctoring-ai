import hashlib
from app.core.redis import redis_client
from app.core import settings


def _hash_otp(otp: str) -> str:
    return hashlib.sha256(
        (otp + settings.OTP_SECRET).encode()
    ).hexdigest()


def store_device_otp(user_id: str, fingerprint: str, otp: str):

    key = f"device_otp:{user_id}:{fingerprint}"

    redis_client.setex(
        key,
        settings.OTP_EXPIRE_MINUTES * 60,
        _hash_otp(otp)
    )


def verify_device_otp(user_id: str, fingerprint: str, otp: str):

    key = f"device_otp:{user_id}:{fingerprint}"

    stored = redis_client.get(key)

    if not stored:
        return False

    if stored != _hash_otp(otp):
        return False

    redis_client.delete(key)

    return True
