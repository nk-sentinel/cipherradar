"""WebSocket endpoints for real-time notification and scan progress delivery.

Uses Redis Pub/Sub to receive notifications published by any API instance
and forwards them to connected WebSocket clients.
"""

import asyncio
import json
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.services.cache_service import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/notifications")
async def notifications_ws(
    websocket: WebSocket,
    user_id: str = Query(description="User ID for notification subscription"),
) -> None:
    """WebSocket endpoint for real-time notifications.

    Subscribes to the Redis Pub/Sub channel ``notifications:{user_id}``
    and forwards messages to the connected client. This allows multi-instance
    delivery — any API instance that publishes a notification will have it
    delivered to the user regardless of which instance holds their WebSocket.
    """
    await websocket.accept()

    redis_client = get_redis()
    if redis_client is None:
        # No Redis — still accept connection but warn and close
        await websocket.send_json({"error": "Real-time notifications unavailable"})
        await websocket.close()
        return

    channel_name = f"notifications:{user_id}"
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel_name)

    async def _listen_redis() -> None:
        """Listen for Redis messages and forward to WebSocket."""
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    try:
                        payload = json.loads(data)
                        await websocket.send_json(payload)
                    except Exception:
                        logger.warning("Invalid notification payload on channel %s", channel_name)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.warning("Redis listener error for %s", channel_name, exc_info=True)

    listener_task = asyncio.create_task(_listen_redis())

    try:
        # Keep the WebSocket open by reading (client may send pings/acks)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        listener_task.cancel()
        await pubsub.unsubscribe(channel_name)
        await pubsub.aclose()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for real-time scan progress updates (D20 #36).

    Subscribes to the Redis Pub/Sub channel ``scan:{scan_id}`` and forwards
    progress messages to the connected client. Messages include status stage,
    progress percentage, and optional detail text.
    """
    await websocket.accept()

    redis_client = get_redis()
    if redis_client is None:
        await websocket.send_json({"error": "Real-time scan progress unavailable"})
        await websocket.close()
        return

    channel_name = f"scan:{scan_id}"
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel_name)

    async def _listen_redis() -> None:
        """Listen for Redis messages and forward to WebSocket."""
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    try:
                        payload = json.loads(data)
                        await websocket.send_json(payload)
                        # Auto-close when scan completes or fails
                        if payload.get("status") in ("completed", "failed"):
                            await websocket.close()
                            return
                    except Exception:
                        logger.warning("Invalid scan progress payload on channel %s", channel_name)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.warning("Redis listener error for %s", channel_name, exc_info=True)

    listener_task = asyncio.create_task(_listen_redis())

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        listener_task.cancel()
        await pubsub.unsubscribe(channel_name)
        await pubsub.aclose()
