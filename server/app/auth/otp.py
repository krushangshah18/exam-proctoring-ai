# import hashlib
# import random
# from datetime import datetime, timedelta

# from app.core import settings


# def generate_otp() -> str:
#     return str(random.randint(100000, 999999))


# def hash_otp(otp: str) -> str:
#     raw = otp + settings.OTP_SECRET
#     return hashlib.sha256(raw.encode()).hexdigest()


# def verify_otp(otp: str, otp_hash: str) -> bool:
#     return hash_otp(otp) == otp_hash


# def get_expiry():
#     return datetime.now() + timedelta(
#         minutes=settings.OTP_EXPIRE_MINUTES
#     )
