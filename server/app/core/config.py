import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://admin:admin123@localhost:5432/exam_proctoring",
    )

    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM","HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES",15))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS",7)) #renew access token without re-login

    RESET_TOKEN_EXPIRE_MINUTES = 15
    SMTP_HOST=os.getenv("SMTP_HOST","smtp.gmail.com")
    SMTP_PORT=os.getenv("SMTP_PORT","587")
    SMTP_USER=os.getenv("SMTP_USER","krushang.shah@drcsystems.com")
    SMTP_PASSWORD=os.getenv("SMTP_PASSWORD")
    SMTP_TLS=os.getenv("SMTP_TLS","true")
    EMAIL_FROM=os.getenv("EMAIL_FROM", "Exam Proctoring System <noreply@examai.com>")
    FRONTEND_URL=os.getenv("FRONTEND_URL","http://localhost:3000")

    PROFILE_IMAGE_UPDATE_DAYS = int(os.getenv("PROFILE_IMAGE_UPDATE_DAYS", 30))
    ACCOUNT_LOCK_FAILED_LOGIN_MINUTES = int(os.getenv("ACCOUNT_LOCK_FAILED_LOGIN_MINUTES",15))

    REDIS_HOST=os.getenv("REDIS_HOST","localhost")
    REDIS_PORT=int(os.getenv("REDIS_PORT",6379))
    REDIS_DB=int(os.getenv("REDIS_DB",0))
    REDIS_PASSWORD=os.getenv("REDIS_PASSWORD")

    MAX_LOGIN_ATTEMPTS=int(os.getenv("MAX_LOGIN_ATTEMPTS",5))
    OTP_EXPIRE_MINUTES=int(os.getenv("OTP_EXPIRE_MINUTES",10))
    MAX_OTP_ATTEMPTS=int(os.getenv("MAX_OTP_ATTEMPTS",3))
    MAX_UNLOCK_REQUESTS=int(os.getenv("MAX_UNLOCK_REQUESTS",2))
    OTP_SECRET=os.getenv("OTP_SECRET")

    MAX_TRUSTED_DEVICES=int(os.getenv("MAX_TRUSTED_DEVICES",3))

settings = Settings()
