"""
PhishGuard AI - backend entrypoint.

Run locally with:  uvicorn app.main:app --reload
Docs available at:  http://localhost:8000/docs
"""
import time
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import get_settings
from app.database import init_db, AsyncSessionLocal
from sqlalchemy import text
from redis.asyncio import Redis
from app.routers import auth, url_scanner, sms_analyzer, email_scanner, alerts, reports, team
from app.services.websocket_manager import manager

settings = get_settings()
logger = logging.getLogger(__name__)
redis_client = Redis.from_url(settings.redis_url, decode_responses=True) if settings.redis_url else None


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception_type"] = record.exc_info[0].__name__
        return json.dumps(entry, ensure_ascii=True)


if settings.environment in {"production", "prod"}:
    root_logger = logging.getLogger()
    root_logger.setLevel(settings.log_level)
    if not root_logger.handlers:
        root_logger.addHandler(logging.StreamHandler())
    for handler in root_logger.handlers:
        handler.setFormatter(JsonLogFormatter())


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.environment in {"production", "prod"}:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.requests: dict[str, list[float]] = defaultdict(list)
        self.redis = redis_client

    async def dispatch(self, request: Request, call_next):
        if request.method in {"POST", "PUT", "DELETE"}:
            client = request.client.host if request.client else "unknown"
            now = time.monotonic()
            try:
                if self.redis:
                    bucket = int(time.time() // 60)
                    key = f"phishguard:rate:{client}:{bucket}"
                    count = await self.redis.incr(key)
                    if count == 1:
                        await self.redis.expire(key, 120)
                    if count > 60:
                        return JSONResponse(
                            status_code=429,
                            content={"detail": "Too many requests; retry later"},
                        )
                else:
                    window = [
                        timestamp for timestamp in self.requests[client]
                        if now - timestamp < 60
                    ]
                    if len(window) >= 60:
                        return JSONResponse(
                            status_code=429,
                            content={"detail": "Too many requests; retry later"},
                        )
                    window.append(now)
                    self.requests[client] = window
            except Exception:
                logger.exception("Rate-limit backend request failed")
                if settings.environment in {"production", "prod"}:
                    return JSONResponse(
                        status_code=503,
                        content={"detail": "Request protection is temporarily unavailable"},
                    )
        return await call_next(request)

app = FastAPI(
    title=settings.app_name,
    debug=settings.debug,
    description="AI-assisted phishing detection API: URL scanning, SMS/smishing "
                 "analysis, email/Gmail scanning, real-time alerts, and reporting.",
    version="1.0.0",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SimpleRateLimitMiddleware)

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
    try:
        from app.ml.ml_model import _load
        _load()
    except Exception:
        logger.exception("URL ML model artifact validation failed")
    if redis_client:
        await redis_client.ping()
        await manager.start(settings.redis_url)


@app.on_event("shutdown")
async def on_shutdown():
    await manager.stop()
    if redis_client:
        await redis_client.aclose()


@app.get("/")
async def root():
    return {"service": settings.app_name, "status": "online"}


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/ready")
async def readiness():
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            if settings.environment in {"production", "prod"}:
                await session.execute(
                    text("SELECT version_num FROM alembic_version LIMIT 1")
                )
        if settings.environment in {"production", "prod"} and redis_client:
            await redis_client.ping()
        return {"status": "ready"}
    except Exception:
        logger.exception("Database readiness check failed")
        return JSONResponse(status_code=503, content={"status": "not_ready"})
