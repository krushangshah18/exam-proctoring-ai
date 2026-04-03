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
import time
from typing import Dict

from app.core import log, system_logger

# session_id (str) → asyncio.Queue
_queues: Dict[str, asyncio.Queue] = {}
_main_loop: asyncio.AbstractEventLoop | None = None

# Rate-limit queue-full warnings to avoid log spam on bursty streams.
_queue_full_last_log_at: float = 0.0
_queue_full_drop_count: int = 0


def _log_queue_full(session_id: str, event_type: str) -> None:
    global _queue_full_last_log_at, _queue_full_drop_count
    _queue_full_drop_count += 1
    now = time.time()
    if now - _queue_full_last_log_at >= 60:
        # Emit at most once per minute.
        system_logger.warning(
            "SSE event queue full; dropping events session_id=%s event=%s dropped_count=%s",
            session_id,
            event_type,
            _queue_full_drop_count,
        )
        _queue_full_last_log_at = now
        _queue_full_drop_count = 0


def set_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Register the app's main event loop for thread-safe sync event pushes."""
    global _main_loop
    _main_loop = loop


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
            _log_queue_full(session_id, event_type)


def push_event_sync(session_id: str, event_type: str, data: dict) -> None:
    """
    Push an event from a sync context (sync FastAPI route handler).
    Uses the app's registered main event loop so threadpool handlers can
    still enqueue SSE events reliably.
    """
    if session_id not in _queues:
        return
    if _main_loop is None:
        # If this happens, SSE push infrastructure isn't initialised correctly.
        log.error("push_event_sync called before event loop initialised (session_id=%s, event=%s)", session_id, event_type)
        return
    try:
        _main_loop.call_soon_threadsafe(
            _queues[session_id].put_nowait,
            {"type": event_type, "data": data},
        )
    except RuntimeError as e:
        # Thread-safety / lifecycle issue; log for diagnostics.
        log.warning(
            "SSE push_event_sync runtime error (session_id=%s, event=%s): %s",
            session_id,
            event_type,
            e,
        )
        return
    except asyncio.QueueFull:
        _log_queue_full(session_id, event_type)
