import json
import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import User, Scan, Alert, ScanType, Verdict
from app.schemas import URLScanRequest, ScanResult
from app.services.url_detection import generate_report_with_reputation
from app.services.websocket_manager import manager
from app.ml.ml_model import predict_url, ml_to_risk_factor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan/url", tags=["url-scanner"])


async def _maybe_current_user(db: AsyncSession, current_user: User | None):
    return current_user


@router.post("", response_model=ScanResult)
async def scan_url(
    payload: URLScanRequest,
    db: AsyncSession = Depends(get_db),
):
    risk_factor = None
    try:
        ml_result = predict_url(payload.url, check_live_signals=True)
        risk_factor = ml_to_risk_factor(ml_result)
    except Exception:
        # ML is an enhancement, not a dependency - never let it take down
        # a scan the heuristic engine could've handled on its own.
        logger.exception("ML scoring failed for %s, falling back to heuristics only", payload.url)

    report = generate_report_with_reputation(payload.url, risk_factor, check_live_signals=True)

    score = report["risk_percentage"]
    verdict = report["verdict"]
    reasons = [f["reason"] for f in report["factors"]]

    scan = Scan(
        scan_type=ScanType.URL,
        input_value=payload.url,
        verdict=Verdict(verdict),
        risk_score=score,
        reasons_json=json.dumps(reasons),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    if verdict != "safe":
        alert = Alert(
            title=f"{verdict.capitalize()} URL detected",
            message=f"{payload.url[:120]}",
            severity=Verdict(verdict),
            scan_id=scan.id,
        )
        db.add(alert)
        await db.commit()
        await manager.broadcast({
            "type": "alert",
            "title": alert.title,
            "message": alert.message,
            "severity": verdict,
            "created_at": alert.created_at.isoformat(),
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
