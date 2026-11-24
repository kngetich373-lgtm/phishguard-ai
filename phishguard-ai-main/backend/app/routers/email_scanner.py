import json

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import Scan, Alert, ScanType, Verdict
from app.schemas import EmailScanRequest, ScanResult
from app.services.email_detection import score_email
from app.services.scoring import classify
from app.services.websocket_manager import manager
from app.auth import get_scan_user
from app.models import User

router = APIRouter(prefix="/api/scan/email", tags=["email-scanner"])
settings = get_settings()


@router.post("", response_model=ScanResult)
async def scan_email(
    payload: EmailScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_scan_user),
):
    """Score a raw subject/body/sender - paste-in mode, or fed by the Gmail sync below."""
    score, reasons = score_email(payload.subject, payload.body, payload.sender)
    verdict = classify(score)

    scan = Scan(
        scan_type=ScanType.EMAIL,
        input_value=f"{payload.subject} | {payload.body[:500]}",
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
            title=f"{verdict.capitalize()} email detected",
            message=payload.subject[:120] or payload.body[:120],
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


@router.get("/gmail/status")
async def gmail_status():
    """Tells the frontend whether Gmail OAuth is configured on this deployment."""
    configured = bool(settings.google_client_id and settings.google_client_secret)
    return {"configured": configured}


@router.get("/gmail/oauth/start")
async def gmail_oauth_start():
    """
    Kicks off the Gmail OAuth consent flow.

    IMPLEMENTATION NOTE (not wired up in this scaffold - requires real Google
    Cloud credentials): install `google-auth-oauthlib` and `google-api-python-client`,
    then build the flow like:

        from google_auth_oauthlib.flow import Flow
        flow = Flow.from_client_config(
            {"web": {"client_id": settings.google_client_id,
                      "client_secret": settings.google_client_secret,
                      "redirect_uris": [settings.google_redirect_uri],
                      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                      "token_uri": "https://oauth2.googleapis.com/token"}},
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        flow.redirect_uri = settings.google_redirect_uri
        auth_url, _ = flow.authorization_url(prompt="consent")
        return {"auth_url": auth_url}

    Then in /oauth/callback, exchange the returned `code` for tokens, store
    them against the user record, and use the Gmail API's `users.messages.list`
    / `.get` to pull recent messages, calling `score_email()` on each.
    """
    return {
        "detail": "Gmail OAuth is not configured on this deployment. "
                   "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the backend .env "
                   "to enable it, or use the paste-in email scanner instead."
    }
