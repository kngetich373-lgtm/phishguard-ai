import json
import secrets

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Scan, Verdict, ApiKey, User
from app.schemas import ReportSummary, ScanResult, ApiKeyOut
from app.auth import get_current_user

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/summary", response_model=ReportSummary)
async def summary(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count(Scan.id)))).scalar_one()

    counts = {}
    for verdict in Verdict:
        c = (await db.execute(select(func.count(Scan.id)).where(Scan.verdict == verdict))).scalar_one()
        counts[verdict.value] = c

    by_type = {}
    result = await db.execute(select(Scan.scan_type, func.count(Scan.id)).group_by(Scan.scan_type))
    for scan_type, c in result.all():
        by_type[scan_type.value] = c

    recent_result = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(10))
    recent_scans = [
        ScanResult(
            id=s.id,
            scan_type=s.scan_type.value,
            input_value=s.input_value,
            verdict=s.verdict.value,
            risk_score=s.risk_score,
            reasons=json.loads(s.reasons_json),
            created_at=s.created_at,
        )
        for s in recent_result.scalars().all()
    ]

    return ReportSummary(
        total_scans=total,
        safe_count=counts.get("safe", 0),
        suspicious_count=counts.get("suspicious", 0),
        malicious_count=counts.get("malicious", 0),
        scans_by_type=by_type,
        recent_scans=recent_scans,
    )


@router.get("/history", response_model=list[ScanResult])
async def history(db: AsyncSession = Depends(get_db), limit: int = 100):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(limit))
    return [
        ScanResult(
            id=s.id,
            scan_type=s.scan_type.value,
            input_value=s.input_value,
            verdict=s.verdict.value,
            risk_score=s.risk_score,
            reasons=json.loads(s.reasons_json),
            created_at=s.created_at,
        )
        for s in result.scalars().all()
    ]


@router.get("/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(ApiKey).where(ApiKey.owner_id == current_user.id))
    return result.scalars().all()


@router.post("/api-keys", response_model=ApiKeyOut)
async def create_api_key(
    label: str = "Default key",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    key = ApiKey(key=f"pg_live_{secrets.token_hex(20)}", label=label, owner_id=current_user.id)
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return key
