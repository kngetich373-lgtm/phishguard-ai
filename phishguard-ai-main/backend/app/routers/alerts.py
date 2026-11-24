from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert
from app.schemas import AlertOut
from app.services.websocket_manager import manager
from app.auth import _resolve_access_token, get_current_user
from app.models import User
from app.config import get_settings
from app.models import User

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
settings = get_settings()


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50,
):
    limit = min(max(limit, 1), 100)
    result = await db.execute(
        select(Alert)
        .where(Alert.owner_id == current_user.id)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.post("/{alert_id}/read", response_model=AlertOut)
async def mark_read(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id, Alert.owner_id == current_user.id)
        .values(read=True)
    )
    await db.commit()
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.owner_id == current_user.id)
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.websocket("/ws")
async def alerts_websocket(
    websocket: WebSocket,
    token: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    origin = websocket.headers.get("origin")
    if not origin or origin.rstrip("/") not in settings.cors_origin_list:
        await websocket.close(code=1008, reason="Origin not allowed")
        return
    if not token:
        await websocket.close(code=1008, reason="Authentication required")
        return
    try:
        user = await _resolve_access_token(token, db)
    except HTTPException:
        await websocket.close(code=1008, reason="Invalid authentication token")
        return
    await manager.connect(websocket, owner_id=user.id)
    try:
        while True:
            # We don't expect inbound messages, but keep the loop alive to
            # detect disconnects. Clients may send pings; we just ignore them.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
