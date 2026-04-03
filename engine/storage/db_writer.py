"""
DBWriter — writes proctoring events directly to the shared RDS PostgreSQL.

Uses raw psycopg2 (not SQLAlchemy ORM) so the engine has no dependency on
the backend's model definitions. The schema is fixed and matches the
proctor_alerts / proctor_warnings / exam_sessions tables created by the
backend Alembic migration.

Thread-safety: each write opens its own connection from the pool, executes,
and returns it. psycopg2's ThreadedConnectionPool is used so concurrent
writes from alert handlers don't block each other.

Failure policy: every public method catches all exceptions and logs them.
The engine must never crash because of a DB write failure.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("storage.db")

# Lazy import — psycopg2 may not be installed in local dev without Postgres
try:
    import psycopg2
    from psycopg2 import pool as pg_pool
    _PSYCOPG2_AVAILABLE = True
except ImportError:
    _PSYCOPG2_AVAILABLE = False
    logger.warning("psycopg2 not installed — DB writes disabled")


class DBWriter:
    """
    Writes alert/warning rows and updates exam_sessions on session end.

    Usage:
        writer = DBWriter(database_url)
        writer.write_alert(session_id, ...)
        writer.write_warning(session_id, ...)
        writer.finalize_session(session_id, final_score, risk_state, terminated)
        writer.close()
    """

    def __init__(self, database_url: str | None = None) -> None:
        self._pool: "pg_pool.ThreadedConnectionPool | None" = None
        url = database_url or os.getenv("DATABASE_URL", "")
        if not url or not _PSYCOPG2_AVAILABLE:
            logger.warning("DBWriter: no DATABASE_URL or psycopg2 missing — DB writes disabled")
            return
        try:
            # Convert SQLAlchemy-style URL to psycopg2 DSN
            # "postgresql+psycopg2://user:pass@host/db" → "postgresql://user:pass@host/db"
            dsn = url.replace("postgresql+psycopg2://", "postgresql://")
            self._pool = pg_pool.ThreadedConnectionPool(minconn=1, maxconn=5, dsn=dsn)
            logger.info("DBWriter: connected to RDS (pool size 1-5)")
        except Exception as exc:
            logger.error("DBWriter: failed to create connection pool: %s", exc)
            self._pool = None

    @property
    def enabled(self) -> bool:
        return self._pool is not None

    # ── Public API ────────────────────────────────────────────────────────────

    def write_alert(
        self,
        session_id: str,
        message: str,
        alert_key: str,
        elapsed_s: float,
        time_str: str,
        score_added: float,
        proof_s3_key: str | None = None,
        proof_type: str | None = None,
        proof_size_bytes: int | None = None,
    ) -> None:
        """Insert one row into proctor_alerts. Fire-and-forget, never raises."""
        if not self.enabled:
            return
        try:
            self._execute(
                """
                INSERT INTO proctor_alerts
                    (id, session_id, message, alert_key, elapsed_s, time_str,
                     score_added, proof_s3_key, proof_type, proof_size_bytes, occurred_at)
                VALUES
                    (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    session_id,
                    message,
                    alert_key,
                    elapsed_s,
                    time_str,
                    score_added,
                    proof_s3_key,
                    proof_type,
                    proof_size_bytes,
                    datetime.now(timezone.utc),
                ),
            )
        except Exception as exc:
            logger.error("DBWriter.write_alert failed (session=%s): %s", session_id, exc)

    def write_warning(
        self,
        session_id: str,
        message: str,
        elapsed_s: float,
        time_str: str,
    ) -> None:
        """Insert one row into proctor_warnings. Fire-and-forget, never raises."""
        if not self.enabled:
            return
        try:
            self._execute(
                """
                INSERT INTO proctor_warnings
                    (id, session_id, message, elapsed_s, time_str, occurred_at)
                VALUES
                    (%s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    session_id,
                    message,
                    elapsed_s,
                    time_str,
                    datetime.now(timezone.utc),
                ),
            )
        except Exception as exc:
            logger.error("DBWriter.write_warning failed (session=%s): %s", session_id, exc)

    def finalize_session(
        self,
        session_id: str,
        final_score: float,
        risk_state: str,
        terminated: bool,
    ) -> None:
        """
        Update exam_sessions with final risk score when the session ends.
        Also sets status to TERMINATED if the engine terminated the session
        (i.e. auto-termination by risk threshold, not admin action).
        Only updates status when terminated=True to avoid overwriting
        SUBMITTED status set by the student submitting normally.
        """
        if not self.enabled:
            return
        try:
            if terminated:
                self._execute(
                    """
                    UPDATE exam_sessions
                    SET risk_score = %s,
                        status = CASE
                            WHEN status NOT IN ('SUBMITTED', 'TERMINATED') THEN 'TERMINATED'
                            ELSE status
                        END
                    WHERE id = %s
                    """,
                    (int(final_score), session_id),
                )
            else:
                self._execute(
                    "UPDATE exam_sessions SET risk_score = %s WHERE id = %s",
                    (int(final_score), session_id),
                )
            logger.info(
                "DBWriter.finalize_session: session=%s score=%s state=%s terminated=%s",
                session_id, final_score, risk_state, terminated,
            )
        except Exception as exc:
            logger.error("DBWriter.finalize_session failed (session=%s): %s", session_id, exc)

    def close(self) -> None:
        if self._pool is not None:
            try:
                self._pool.closeall()
            except Exception as exc:
                logger.warning("DBWriter.close: closeall failed: %s", exc)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _execute(self, sql: str, params: tuple) -> None:
        """Get a connection from the pool, execute, return connection."""
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
            conn.commit()
        except Exception as exc:
            logger.debug("DBWriter._execute failed: %s", exc)
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)
