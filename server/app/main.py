from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.core import log, settings
from app.auth.routes import router as auth_router
from app.auth.admin_applications import router as admin_app_router
from app.exam.routes import router as exam_router

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Exam Proctoring AI Backend", version="0.1.0")

# CORS (Frontend Access)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add this line after creating the app
app.mount("/storage", StaticFiles(directory="storage"), name="storage")

@app.get("/health")
def health_check():
    return {"status": "ok"}
