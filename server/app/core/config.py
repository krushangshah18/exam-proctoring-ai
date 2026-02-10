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



settings = Settings()
