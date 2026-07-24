"""
PhishGuard AI - backend entrypoint.

Run locally with:  uvicorn app.main:app --reload
Docs available at:  http://localhost:8000/docs
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import init_db
from app.routers import auth, url_scanner, sms_analyzer, email_scanner, alerts, reports, team

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="AI-assisted phishing detection API: URL scanning, SMS/smishing "
                 "analysis, email/Gmail scanning, real-time alerts, and reporting.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(url_scanner.router)
app.include_router(sms_analyzer.router)
app.include_router(email_scanner.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(team.router)


@app.on_event("startup")
async def on_startup():
    await init_db()


@app.get("/")
async def root():
    return {"service": settings.app_name, "status": "online"}


@app.get("/api/health")
async def health():
    return {"status": "ok"}
