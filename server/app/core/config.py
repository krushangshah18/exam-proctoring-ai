import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://admin:admin123@localhost:5432/exam_proctoring",
    )


settings = Settings()
