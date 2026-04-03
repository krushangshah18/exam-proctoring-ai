from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core import settings, log

"""
SQLAlchemy :
✅ industry standard in Python backend
✅ maps database tables to Python classes
✅ easier querying + relationships + migrations
"""
engine = create_engine(
    settings.DATABASE_URL, 
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    pool_recycle=1800 # Recycle connections every 30 minutes to drop old TCP sockets
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        # Route-layer exceptions should trigger a rollback to avoid a broken transaction
        # lingering across requests within the same session instance.
        log.exception("DB transaction failed; rolling back: %s", e)
        try:
            db.rollback()
        except Exception as rb_e:
            log.warning("DB rollback failed after transaction error: %s", rb_e)
        raise
    finally:
        db.close()
