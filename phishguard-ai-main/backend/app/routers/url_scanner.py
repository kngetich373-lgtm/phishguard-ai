import json
import logging
import time
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_scan_user
from app.database import get_db
from app.models import User, Scan, Alert, ScanType, Verdict
from app.schemas import URLScanRequest, ScanResult
from app.services.url_detection import generate_report_with_reputation
from app.services.websocket_manager import manager
from app.ml.ml_model import predict_url, ml_to_risk_factor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan/url", tags=["url-scanner"])


def normalize_and_validate_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise ValueError("URL is required")
    if len(url) > 2048:
        raise ValueError("URL exceeds the 2048-character limit")
    if "://" not in url:
        url = "http://" + url
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    if not parsed.hostname:
        raise ValueError("URL must contain a valid hostname")
    if parsed.username or parsed.password:
        raise ValueError("URLs must not contain embedded credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    if port not in {None, 80, 443}:
        raise ValueError("Only standard HTTP and HTTPS ports are allowed")
    host = parsed.hostname.lower()
    if host in {"localhost"} or host.endswith(".localhost"):
        raise ValueError("Local and loopback hosts are not allowed")
    try:
        addresses = {item for item in socket.getaddrinfo(host, port or None)}
    except socket.gaierror:
        addresses = set()
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))
    for _family, _type, _proto, _canonname, sockaddr in addresses:
        address = sockaddr[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Private and reserved network addresses are not allowed")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


async def _maybe_current_user(db: AsyncSession, current_user: User | None):
    return current_user


@router.post("", response_model=ScanResult)
async def scan_url(
    payload: URLScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_scan_user),
):
    started = time.monotonic()
    try:
        normalized_url = normalize_and_validate_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    risk_factor = None
    ml_result = None
    try:
        ml_result = predict_url(normalized_url, check_live_signals=True)
        risk_factor = ml_to_risk_factor(ml_result)
    except Exception as exc:
        # ML is an enhancement, not a dependency - never let it take down
        # a scan the heuristic engine could've handled on its own.
        logger.warning("ML scoring failed; falling back to heuristics only", extra={"error_type": type(exc).__name__})

    report = generate_report_with_reputation(normalized_url, risk_factor, check_live_signals=True)

    score = report["risk_percentage"]
    verdict = report["verdict"]
    reasons = [f["reason"] for f in report["factors"]]

    scan = Scan(
        scan_type=ScanType.URL,
        input_value=normalized_url,
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
            title=f"{verdict.capitalize()} URL detected",
            message=f"{normalized_url[:120]}",
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

    unavailable = []
    if ml_result is None:
        unavailable.append("ml_model")
    if ml_result is not None:
        feats = ml_result.get("features_used", {})
        net_names = {
            "time_domain_activation": "whois_domain_age",
            "time_domain_expiration": "whois_domain_expiration",
            "ttl_hostname": "dns_ttl",
            "qty_nameservers": "dns_nameservers",
            "qty_mx_servers": "dns_mx",
            "domain_spf": "dns_spf",
            "qty_ip_resolved": "dns_ip_count",
        }
        unavailable.extend(
            label for key, label in net_names.items()
            if feats.get(key, -1) == -1
        )

    confidence_category = "low"
    confidence_score = 0.2
    confidence_text = "insufficient evidence"
    if ml_result:
        if ml_result["confidence"].startswith("high"):
            confidence_category = "high"
            confidence_score = 0.8
            confidence_text = ml_result["confidence"]
        elif ml_result["confidence"].startswith("medium"):
            confidence_category = "medium"
            confidence_score = 0.55
            confidence_text = ml_result["confidence"]
        else:
            confidence_text = ml_result["confidence"]

    risk_category = "inconclusive" if not report["factors"] and ml_result is None else verdict
    duration_ms = round((time.monotonic() - started) * 1000)

    return ScanResult(
        id=scan.id,
        scan_type=scan.scan_type.value,
        input_value=scan.input_value,
        verdict=scan.verdict.value,
        risk_score=scan.risk_score,
        reasons=reasons,
        created_at=scan.created_at,
        normalized_url=normalized_url,
        risk_category=risk_category,
        confidence=confidence_category,
        confidence_score=confidence_score,
        confidence_interpretation=confidence_text,
        ml_prediction=ml_result["predicted_label"] if ml_result else None,
        ml_probability=ml_result["phishing_probability"] if ml_result else None,
        ml_model=ml_result["model_name"] if ml_result else None,
        ml_model_version=ml_result["model_version"] if ml_result else None,
        operating_mode="offline" if False else "online",
        network_status="degraded" if unavailable and ml_result is not None else ("online" if ml_result else "ml_unavailable"),
        degraded=bool(unavailable),
        scan_duration_ms=duration_ms,
        unavailable_signals=unavailable,
    )
