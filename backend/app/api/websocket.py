"""WebSocket and Server-Sent Events (SSE) endpoints for real-time SOC alert streaming."""

import asyncio
import json
from typing import List, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse

router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket and SSE subscriber connections for SOC updates."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []
        self.sse_queues: Set[asyncio.Queue] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    def register_sse(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.sse_queues.add(q)
        return q

    def unregister_sse(self, q: asyncio.Queue) -> None:
        self.sse_queues.discard(q)

    async def broadcast(self, message: dict) -> None:
        """Broadcast event to all connected WebSockets and SSE queues."""
        # 1. WebSockets
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

        # 2. SSE queues
        dead_queues = []
        for q in self.sse_queues:
            try:
                if q.full():
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(message)
            except Exception:
                dead_queues.append(q)

        for dq in dead_queues:
            self.unregister_sse(dq)


manager = ConnectionManager()


@router.websocket("/events")
async def websocket_events(websocket: WebSocket):
    """Real-time event and alert broadcast WebSocket channel."""
    await manager.connect(websocket)
    try:
        # Send initial connection handshake
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to SentinelX real-time SOC stream",
        })
        while True:
            data = await websocket.receive_text()
            # Echo ping / heartbeat
            await websocket.send_json({"type": "pong", "received": data})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@router.get("/stream", summary="Server-Sent Events (SSE) real-time security stream")
async def sse_events_stream():
    """Server-Sent Events endpoint streaming new alerts, incidents, and telemetry."""
    q = manager.register_sse()

    async def event_generator():
        try:
            # Yield initial connection event
            yield f"data: {json.dumps({'type': 'connection_established', 'message': 'SentinelX SSE Stream Connected'})}\n\n"
            while True:
                try:
                    # Wait for next broadcast message or send keep-alive comment
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            manager.unregister_sse(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
