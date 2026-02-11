from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.core import log
from app.auth.routes import router as auth_router
from app.auth.admin_applications import router as admin_app_router
from app.exam.routes import router as exam_router

app = FastAPI(title="Exam Proctoring AI Backend", version="0.1.0")


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
        # Strict for everything else
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"


    return response



app.include_router(auth_router)
app.include_router(admin_app_router)
app.include_router(exam_router)


@app.get("/health")
def health_check():
    log.info("Health check hit")
    return {"status": "ok"}

from app.core.redis import redis_client



