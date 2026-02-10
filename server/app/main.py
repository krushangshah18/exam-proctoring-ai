from fastapi import FastAPI
from app.core import log
from app.auth.routes import router as auth_router
from app.auth.admin_applications import router as admin_app_router


app = FastAPI(title="Exam Proctoring AI Backend", version="0.1.0")

app.include_router(auth_router)
app.include_router(admin_app_router)


@app.get("/health")
def health_check():
    log.info("Health check hit")
    return {"status": "ok"}
