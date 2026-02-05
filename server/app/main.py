from fastapi import FastAPI
from app.core import log

app = FastAPI(title="Exam Proctoring AI Backend", version="0.1.0")

@app.get("/health")
def health_check():
    log.info("Health check hit")
    return {"status": "ok"}
