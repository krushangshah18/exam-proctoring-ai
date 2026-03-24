"""
Proctor engine startup tasks — called once from app lifespan.

1. Seed EngineContainer rows from PROCTOR_ENGINE_URLS env var
   (upsert by URL — safe to call multiple times).
   Containers removed from the URL list are deactivated.
2. Ensure a single EngineSettings row exists with defaults.
"""

import uuid

from app.core import log, settings
from app.db.session import SessionLocal
from app.db import models


def seed_engine_containers() -> None:
    """
    Upsert EngineContainer rows from settings.proctor_engine_url_list.
    Containers no longer in the list are deactivated.
    """
    db = SessionLocal()
    try:
        urls = settings.proctor_engine_url_list
        max_s = settings.PROCTOR_ENGINE_MAX_SESSIONS

        # Deactivate containers not in current URL list
        stale = (
            db.query(models.EngineContainer)
            .filter(
                models.EngineContainer.is_active == True,
                ~models.EngineContainer.url.in_(urls),
            )
            .all()
        )
        for c in stale:
            c.is_active = False
            log.warning("EngineContainer deactivated (removed from PROCTOR_ENGINE_URLS): %s", c.url)

        # Upsert configured containers
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
                db.add(models.EngineContainer(
                    id=uuid.uuid4(),
                    url=url,
                    max_sessions=max_s,
                    is_active=True,
                ))
                log.info("EngineContainer seeded: %s (max=%d)", url, max_s)

        db.commit()
        log.info("Engine containers ready: %d active, %d deactivated", len(urls), len(stale))

    except Exception as e:
        db.rollback()
        log.error("Failed to seed engine containers: %s", e)
    finally:
        db.close()


def ensure_engine_settings() -> None:
    """Create default EngineSettings row if none exists."""
    db = SessionLocal()
    try:
        if db.query(models.EngineSettings).count() == 0:
            db.add(models.EngineSettings(id=uuid.uuid4()))
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
