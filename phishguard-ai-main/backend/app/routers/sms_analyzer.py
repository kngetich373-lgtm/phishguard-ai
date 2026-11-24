import json

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Scan, Alert, ScanType, Verdict
from app.schemas import SMSScanRequest, ScanResult
from app.services.sms_detection import score_sms
from app.services.scoring import classify
from app.services.websocket_manager import manager
from app.auth import get_scan_user
from app.models import User

router = APIRouter(prefix="/api/scan/sms", tags=["sms-analyzer"])


@router.post("", response_model=ScanResult)
async def scan_sms(
    payload: SMSScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_scan_user),
):
    score, reasons = score_sms(payload.message, payload.sender)
    verdict = classify(score)

    scan = Scan(
        scan_type=ScanType.SMS,
        input_value=payload.message,
        verdict=Verdict(verdict),
        risk_score=score,
        reasons_json=json.dumps(reasons),
        owner_id=current_user.id if current_user else None,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    if verdict != "safe":
        alert = Alert(
            title=f"{verdict.capitalize()} SMS detected",
            message=payload.message[:120],
            severity=Verdict(verdict),
            scan_id=scan.id,
            owner_id=current_user.id if current_user else None,
        )
        db.add(alert)
        await db.commit()
        await manager.broadcast({
            "type": "alert",
            "title": alert.title,
            "message": alert.message,
            "severity": verdict,
            "created_at": alert.created_at.isoformat(),
            "owner_id": alert.owner_id,
        })

    return ScanResult(
        id=scan.id,
        scan_type=scan.scan_type.value,
        input_value=scan.input_value,
        verdict=scan.verdict.value,
        risk_score=scan.risk_score,
        reasons=reasons,
        created_at=scan.created_at,
    )
