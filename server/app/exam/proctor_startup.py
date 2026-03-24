"""
Proctor engine startup tasks — called once from app lifespan.

1. Seed EngineContainer rows from PROCTOR_ENGINE_URLS env var
   (upsert by URL — safe to call multiple times)
2. Ensure a single EngineSettings row exists with defaults
"""

import uuid
from datetime import datetime, UTC

from app.core import log, settings
from app.db.session import SessionLocal
from app.db import models


def seed_engine_containers() -> None:
    """Upsert EngineContainer rows from settings.proctor_engine_url_list."""
    db = SessionLocal()
    try:
        urls = settings.proctor_engine_url_list
        max_s = settings.PROCTOR_ENGINE_MAX_SESSIONS

        for url in urls:
            existing = (
                db.query(models.EngineContainer)
                .filter(models.EngineContainer.url == url)
                .first()
            )
            if existing:
                existing.max_sessions = max_s
                existing.is_active = True
                log.info("EngineContainer updated: %s (max=%d)", url, max_s)
            else:
                container = models.EngineContainer(
                    id=uuid.uuid4(),
                    url=url,
                    max_sessions=max_s,
                    is_active=True,
                )
                db.add(container)
                log.info("EngineContainer seeded: %s (max=%d)", url, max_s)

        db.commit()
        log.info("Engine containers ready: %d configured", len(urls))
    except Exception as e:
        db.rollback()
        log.error("Failed to seed engine containers: %s", e)
    finally:
        db.close()


def ensure_engine_settings() -> None:
    """Create default EngineSettings row if none exists."""
    db = SessionLocal()
    try:
        count = db.query(models.EngineSettings).count()
        if count == 0:
            row = models.EngineSettings(id=uuid.uuid4())
            db.add(row)
            db.commit()
            log.info("EngineSettings: default row created")
        else:
            log.info("EngineSettings: existing row found")
    except Exception as e:
        db.rollback()
        log.error("Failed to ensure engine settings: %s", e)
    finally:
        db.close()


def run_all() -> None:
    seed_engine_containers()
    ensure_engine_settings()
