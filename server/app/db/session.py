from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core import settings

"""
SQLAlchemy :
✅ industry standard in Python backend
✅ maps database tables to Python classes
✅ easier querying + relationships + migrations
"""
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
