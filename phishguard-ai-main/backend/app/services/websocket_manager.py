"""
In-memory WebSocket connection manager powering the "Real-Time Alerts" feed.

For a multi-instance production deployment, back this with Redis pub/sub
instead of an in-process list so alerts fan out across all API workers.
"""
import json
import asyncio

from fastapi import WebSocket
from redis.asyncio import Redis


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.connection_owners: dict[WebSocket, str] = {}
        self.redis: Redis | None = None
        self._subscriber_task: asyncio.Task | None = None

    async def start(self, redis_url: str):
        if not redis_url:
            return
        self.redis = Redis.from_url(redis_url, decode_responses=True)
        await self.redis.ping()
        self._subscriber_task = asyncio.create_task(self._subscribe())

    async def stop(self):
        if self._subscriber_task:
            self._subscriber_task.cancel()
            try:
                await self._subscriber_task
            except asyncio.CancelledError:
                pass
            self._subscriber_task = None
        if self.redis:
            await self.redis.aclose()
            self.redis = None

    async def _subscribe(self):
        if not self.redis:
            return
        async with self.redis.pubsub() as pubsub:
            await pubsub.subscribe("phishguard:alerts")
            async for message in pubsub.listen():
                if message["type"] == "message":
                    await self._broadcast_local(json.loads(message["data"]))

    async def connect(self, websocket: WebSocket, owner_id: str | None = None):
        await websocket.accept()
        self.active_connections.append(websocket)
        if owner_id:
            self.connection_owners[websocket] = owner_id

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        self.connection_owners.pop(websocket, None)

    async def broadcast(self, payload: dict):
        if not payload.get("owner_id"):
            return
        if self.redis:
            await self.redis.publish("phishguard:alerts", json.dumps(payload))
            return
        await self._broadcast_local(payload)

    async def _broadcast_local(self, payload: dict):
        dead: list[WebSocket] = []
        owner_id = payload.get("owner_id")
        if not owner_id:
            return
        for connection in self.active_connections:
            if self.connection_owners.get(connection) != owner_id:
                continue
            try:
                await connection.send_text(json.dumps(payload))
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)


manager = ConnectionManager()
