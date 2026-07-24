from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert
from app.schemas import AlertOut
from app.services.websocket_manager import manager

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(db: AsyncSession = Depends(get_db), limit: int = 50):
    result = await db.execute(select(Alert).order_by(Alert.created_at.desc()).limit(limit))
    return result.scalars().all()


@router.post("/{alert_id}/read", response_model=AlertOut)
async def mark_read(alert_id: str, db: AsyncSession = Depends(get_db)):
    await db.execute(update(Alert).where(Alert.id == alert_id).values(read=True))
    await db.commit()
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    return result.scalar_one()


@router.websocket("/ws")
async def alerts_websocket(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect inbound messages, but keep the loop alive to
            # detect disconnects. Clients may send pings; we just ignore them.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
