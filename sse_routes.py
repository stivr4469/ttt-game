"""
SSE (Server-Sent Events) для real-time пуша событий во фронт.

GET  /api/v1/events/stream  — подключиться к SSE-потоку (клиенты, фронт)
POST /api/v1/events/publish — (внутренний) опубликовать событие в поток
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from auth import require_auth, require_auditor

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/events", tags=["sse"])

_subscribers: list[asyncio.Queue] = []


async def _event_generator(
    request: Request,
    queue: asyncio.Queue,
) -> AsyncGenerator[str, None]:
    try:
        while True:
            if await request.is_disconnected():
                break
            try:
                data = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield f"data: {json.dumps(data)}\n\n"
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
    finally:
        try:
            _subscribers.remove(queue)
        except ValueError:
            pass
        log.debug("SSE client disconnected, %d remaining", len(_subscribers))


@router.get("/stream")
async def event_stream(
    request: Request,
    _: dict = Depends(require_auth),
) -> StreamingResponse:
    """SSE-поток событий для подключённых браузеров."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _subscribers.append(queue)
    log.debug("SSE client connected, total: %d", len(_subscribers))
    return StreamingResponse(
        _event_generator(request, queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.post("/publish")
async def publish_event(
    data: dict,
    _: dict = Depends(require_auditor),
) -> dict:
    """Опубликовать событие в SSE-поток (внутренний/тестовый endpoint)."""
    await broadcast(data.get("type", "event"), {k: v for k, v in data.items() if k != "type"})
    return {"ok": True, "subscribers": len(_subscribers)}


async def broadcast(event_type: str, payload: dict) -> None:
    """Отправить событие всем подключённым SSE-клиентам."""
    data = {"type": event_type, **payload}
    dead: list[asyncio.Queue] = []
    for q in _subscribers:
        try:
            q.put_nowait(data)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass
    if dead:
        log.debug("Dropped %d slow SSE clients", len(dead))
