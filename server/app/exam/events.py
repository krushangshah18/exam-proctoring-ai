"""
In-memory SSE event queue manager.

Each active exam session gets its own asyncio.Queue.  The SSE endpoint
reads from the queue and streams events to the browser.  Admin endpoints
push events into the queue via push_event_sync() (callable from sync
FastAPI route handlers running in a thread pool).

Queue lifecycle:
  - Created lazily on first get_queue() call.
  - Removed when the SSE connection closes (remove_queue).
  - If no SSE connection is open the event is silently dropped — the
    client will pick up the state on its next poll / reconnect.
"""

import asyncio
import json
from typing import Dict

# session_id (str) → asyncio.Queue
_queues: Dict[str, asyncio.Queue] = {}


def get_queue(session_id: str) -> asyncio.Queue:
    """Return (creating if necessary) the queue for a session."""
    if session_id not in _queues:
        _queues[session_id] = asyncio.Queue(maxsize=50)
    return _queues[session_id]


def remove_queue(session_id: str) -> None:
    """Remove the queue when the SSE connection closes."""
    _queues.pop(session_id, None)


async def push_event(session_id: str, event_type: str, data: dict) -> None:
    """Push an event from an async context (e.g. async admin endpoint)."""
    if session_id in _queues:
        try:
            await _queues[session_id].put({"type": event_type, "data": data})
        except asyncio.QueueFull:
            pass


def push_event_sync(session_id: str, event_type: str, data: dict) -> None:
    """
    Push an event from a sync context (sync FastAPI route handler).
    Uses call_soon_threadsafe so the asyncio event loop handles the put.
    """
    if session_id not in _queues:
        return
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.call_soon_threadsafe(
                _queues[session_id].put_nowait,
                {"type": event_type, "data": data},
            )
    except (RuntimeError, asyncio.QueueFull):
        pass
