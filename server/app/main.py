import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, UTC, timedelta

from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.core import log, settings
from app.auth.routes import router as auth_router
from app.auth.admin_applications import router as admin_app_router
from app.exam.admin_routes import router as admin_exams_router
from app.exam.admin_routes import _system_settings_router
from app.exam.routes import router as student_exams_router


async def _exam_status_scheduler():
    """
    Background task:
      SCHEDULED → LIVE  when start_window passes
      LIVE      → ENDED when end_window passes
      ACTIVE sessions with last_heartbeat > 90s → DISCONNECTED
      DISCONNECTED sessions with last_heartbeat > 5 min → TERMINATED
    Runs every 60 seconds.
    """
    from app.db.session import SessionLocal
    from app.db import models
    from app.db.enums import ExamStatus, SessionStatus

    while True:
        try:
            now = datetime.now(UTC)
            db = SessionLocal()
            try:
                # Exam status transitions
                scheduled_to_live = (
                    db.query(models.Exam)
                    .filter(
                        models.Exam.status == ExamStatus.SCHEDULED.value,
                        models.Exam.start_window <= now,
                        models.Exam.is_deleted == False,
                    )
                    .all()
                )
                for exam in scheduled_to_live:
                    exam.status = ExamStatus.LIVE.value
                    log.info("Exam %s → LIVE", exam.id)

                live_to_ended = (
                    db.query(models.Exam)
                    .filter(
                        models.Exam.status == ExamStatus.LIVE.value,
                        models.Exam.end_window <= now,
                        models.Exam.is_deleted == False,
                    )
                    .all()
                )
                for exam in live_to_ended:
                    exam.status = ExamStatus.ENDED.value
                    log.info("Exam %s → ENDED", exam.id)
                    # Only end sessions whose personal deadline has passed.
                    # Personal deadline = start_time + duration + admin-granted extension.
                    # Sessions still within their personal window are left running so the
                    # student can finish (their frontend timer will auto-submit when it hits 0).
                    orphaned = (
                        db.query(models.ExamSession)
                        .filter(
                            models.ExamSession.exam_id == exam.id,
                            models.ExamSession.status.in_([
                                SessionStatus.ACTIVE.value,
                                SessionStatus.DISCONNECTED.value,
                            ]),
                        )
                        .all()
                    )
                    for sess in orphaned:
                        if not sess.start_time:
                            sess.status = SessionStatus.ENDED.value
                            sess.end_time = now
                            continue
                        start = sess.start_time.replace(tzinfo=UTC) if sess.start_time.tzinfo is None else sess.start_time
                        personal_deadline = (
                            start
                            + timedelta(minutes=exam.duration_minutes)
                            + timedelta(seconds=sess.time_extension_seconds or 0)
                        )
                        if now >= personal_deadline:
                            sess.status = SessionStatus.ENDED.value
                            sess.end_time = now
                            log.info(
                                "Session %s auto-ended (personal deadline %s passed)", sess.id, personal_deadline
                            )
                        # else: leave running — student has admin-granted extra time

                # Detect disconnected sessions (no heartbeat for > 90 seconds)
                heartbeat_cutoff = now - timedelta(seconds=90)
                stale_sessions = (
                    db.query(models.ExamSession)
                    .filter(
                        models.ExamSession.status == SessionStatus.ACTIVE.value,
                        models.ExamSession.last_heartbeat <= heartbeat_cutoff,
                        models.ExamSession.last_heartbeat.isnot(None),
                    )
                    .all()
                )
                for sess in stale_sessions:
                    sess.status = SessionStatus.DISCONNECTED.value
                    log.info("Session %s marked DISCONNECTED (last heartbeat: %s)", sess.id, sess.last_heartbeat)

                # Auto-terminate sessions disconnected for > 5 min
                from app.exam.events import push_event_sync
                disconnect_terminate_cutoff = now - timedelta(minutes=5)
                long_disconnected = (
                    db.query(models.ExamSession)
                    .filter(
                        models.ExamSession.status == SessionStatus.DISCONNECTED.value,
                        models.ExamSession.last_heartbeat <= disconnect_terminate_cutoff,
                        models.ExamSession.last_heartbeat.isnot(None),
                    )
                    .all()
                )
                for sess in long_disconnected:
                    sess.status = SessionStatus.TERMINATED.value
                    sess.terminated_by = "SYSTEM_DISCONNECT"
                    sess.terminated_reason = "Session auto-terminated: student disconnected for over 5 minutes"
                    sess.terminated_at = now
                    push_event_sync(str(sess.id), "TERMINATED", {
                        "terminated_by": "SYSTEM_DISCONNECT",
                        "terminated_reason": sess.terminated_reason,
                    })
                    log.info(
                        "Session %s auto-terminated (disconnected since %s)", sess.id, sess.last_heartbeat
                    )

                # Also check sessions in already-ENDED exams whose personal deadline has now expired
                # (students who were given time extensions past the exam end_window)
                ended_exam_sessions = (
                    db.query(models.ExamSession, models.Exam)
                    .join(models.Exam, models.Exam.id == models.ExamSession.exam_id)
                    .filter(
                        models.Exam.status == ExamStatus.ENDED.value,
                        models.ExamSession.status.in_([
                            SessionStatus.ACTIVE.value,
                            SessionStatus.DISCONNECTED.value,
                        ]),
                    )
                    .all()
                )
                extended_auto_ended = []
                for sess, exam in ended_exam_sessions:
                    if not sess.start_time:
                        continue
                    start = sess.start_time.replace(tzinfo=UTC) if sess.start_time.tzinfo is None else sess.start_time
                    personal_deadline = (
                        start
                        + timedelta(minutes=exam.duration_minutes)
                        + timedelta(seconds=sess.time_extension_seconds or 0)
                    )
                    if now >= personal_deadline:
                        sess.status = SessionStatus.ENDED.value
                        sess.end_time = now
                        extended_auto_ended.append(sess.id)
                        log.info("Session %s auto-ended (extended past exam window, deadline %s)", sess.id, personal_deadline)

                if scheduled_to_live or live_to_ended or stale_sessions or long_disconnected or extended_auto_ended:
                    db.commit()
                    log.info(
                        "Exam scheduler: %d SCHEDULED→LIVE, %d LIVE→ENDED, %d DISCONNECTED, %d auto-terminated, %d extended-sessions ended",
                        len(scheduled_to_live),
                        len(live_to_ended),
                        len(stale_sessions),
                        len(long_disconnected),
                        len(extended_auto_ended),
                    )
            except Exception as e:
                db.rollback()
                log.error("Exam status update failed: %s", e)
            finally:
                db.close()
        except Exception as e:
            log.error("Exam scheduler outer error: %s", e)

        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Seed engine containers + ensure settings row exist
    from app.exam.proctor_startup import run_all as _proctor_startup
    _proctor_startup()

    scheduler = asyncio.create_task(_exam_status_scheduler())
    log.info("Exam status scheduler started.")
    yield
    scheduler.cancel()
    try:
        await scheduler
    except asyncio.CancelledError:
        pass
    log.info("Exam status scheduler stopped.")


app = FastAPI(title="Exam Proctoring AI Backend", version="0.1.0", lifespan=lifespan)
app.mount("/storage", StaticFiles(directory="storage"), name="storage")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    path = request.url.path
    if path.startswith("/docs") or path.startswith("/redoc") or path.startswith("/openapi"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' https://cdn.jsdelivr.net https://fastapi.tiangolo.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' https://fastapi.tiangolo.com data:; "
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self'; "
            "connect-src 'self' http://localhost:3000; "
            "frame-ancestors 'none';"
        )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


app.include_router(auth_router)
app.include_router(admin_app_router)
app.include_router(admin_exams_router)
app.include_router(_system_settings_router)
app.include_router(student_exams_router)


@app.get("/health")
def health_check():
    log.info("Health check hit")
    return {"status": "ok"}


from app.core.redis import redis_client
