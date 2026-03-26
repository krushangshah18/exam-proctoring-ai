"""
Proctor engine proxy helpers.

All communication between ProctorAI and the AI engine goes through here.
The engine runs on a separate EC2 instance and is not directly reachable
by the student browser — ProctorAI backend acts as the signaling proxy.

WebRTC media (UDP) still flows directly between the browser and engine;
only HTTP signaling (offer/ICE/tab-switch) is proxied.
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

import httpx

from app.core import log

# Shared async client — reused across requests (connection pooling)
# Timeout tuned for engine inference latency:
#   connect=5s, read=30s (SSE streams are long-lived — handled separately)
_client = httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0))

SSE_KEEPALIVE_INTERVAL = 25  # seconds between ping comments on proxied SSE


# ── WebRTC signaling ──────────────────────────────────────────────────────────

async def proxy_offer(
    engine_url: str,
    sdp: str,
    sdp_type: str,
    detection_config: dict,
    initial_score: float = 0.0,
    metadata: dict | None = None,
) -> dict:
    """
    POST /offer to the engine.
    Returns the engine's answer JSON: {sdp, type, device_id, device_label, ...}
    Raises httpx.HTTPError on network failure.

    initial_score: existing risk score to seed the engine session (used on reconnect
                   so the score continues from where it left off rather than restarting at 0).
    """
    resp = await _client.post(
        f"{engine_url}/offer",
        json={
            "sdp": sdp,
            "type": sdp_type,
            "detection_config": detection_config,
            "initial_score": initial_score,
            "metadata": metadata or {},
        },
        timeout=15.0,   # offer round-trip includes SDP negotiation
    )
    resp.raise_for_status()
    return resp.json()


async def proxy_ice_candidate(engine_url: str, pc_id: str, candidate: dict) -> None:
    """POST /ice-candidate/{pc_id} to the engine (fire-and-forget, best effort)."""
    try:
        resp = await _client.post(
            f"{engine_url}/ice-candidate/{pc_id}",
            json=candidate,
        )
        resp.raise_for_status()
    except Exception as exc:
        log.warning("ICE candidate proxy failed (pc_id=%s): %s", pc_id, exc)


async def proxy_tab_switch(engine_url: str, pc_id: str) -> dict:
    """
    POST /tab_switch/{pc_id} to the engine.
    Returns {ok, risk} — caller checks risk.terminated.
    """
    resp = await _client.post(
        f"{engine_url}/tab_switch/{pc_id}",
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


# ── Snapshot (admin live frame) ───────────────────────────────────────────────

async def fetch_snapshot(engine_url: str, pc_id: str) -> bytes:
    """
    GET /snapshot/{pc_id} — returns raw JPEG bytes.
    Raises httpx.HTTPStatusError(404) when no frame available yet.
    """
    resp = await _client.get(f"{engine_url}/snapshot/{pc_id}", timeout=5.0)
    resp.raise_for_status()
    return resp.content


# ── Debug overlay toggle (admin) ──────────────────────────────────────────────

async def proxy_debug_toggle(engine_url: str, pc_id: str, enabled: bool) -> dict:
    resp = await _client.post(
        f"{engine_url}/debug/{pc_id}",
        json={"enabled": enabled},
    )
    resp.raise_for_status()
    return resp.json()


# ── Session log (pulled on exam end) ─────────────────────────────────────────

async def fetch_session_log(engine_url: str, pc_id: str) -> dict:
    """
    GET /session/{pc_id}/log — full alert + warning history + final risk.
    Called once when the student's exam session closes.
    """
    resp = await _client.get(f"{engine_url}/session/{pc_id}/log", timeout=10.0)
    resp.raise_for_status()
    return resp.json()


# ── SSE proxy (student + admin) ───────────────────────────────────────────────

async def stream_engine_events(
    engine_url: str,
    pc_id: str,
) -> AsyncIterator[str]:
    """
    Async generator that yields SSE lines from the engine's /stream/{pc_id}.

    Each yielded string is a complete SSE message ready to forward to the client,
    e.g. 'data: {"type": "alert", ...}\n\n'

    Sends a keepalive comment every SSE_KEEPALIVE_INTERVAL seconds so the
    client connection stays alive through proxies and load balancers.

    Stops when the engine closes the stream (session_end) or on network error.
    """
    url = f"{engine_url}/stream/{pc_id}"

    async with httpx.AsyncClient(timeout=None) as sse_client:
        try:
            async with sse_client.stream("GET", url) as response:
                response.raise_for_status()
                buffer = ""
                async for chunk in response.aiter_text():
                    buffer += chunk
                    # SSE messages are separated by double newlines
                    while "\n\n" in buffer:
                        message, buffer = buffer.split("\n\n", 1)
                        message = message.strip()
                        if not message:
                            continue
                        # Forward the raw SSE message to the client
                        yield message + "\n\n"
                        # If this is a session_end event, stop the stream
                        if "session_end" in message:
                            return
        except httpx.RemoteProtocolError:
            # Engine closed the connection cleanly
            pass
        except Exception as exc:
            log.warning("SSE proxy error (pc_id=%s): %s", pc_id, exc)
            # Yield an error event so the client knows
            yield f'data: {json.dumps({"type": "error", "message": "Engine stream disconnected"})}\n\n'


def build_engine_detection_config(
    detection_config: dict | None,
    engine_settings: "models.EngineSettings",  # type: ignore[name-defined]
) -> dict:
    """
    Merge exam-admin detection toggles + system-admin thresholds/scores
    into a single dict sent to the engine's /offer detection_config field.

    All keys match what engine's ProctorSession.__init__ reads from cfg dict.
    """
    # Default all detections ON if exam has no detection_config set
    defaults: dict = {
        "DETECT_LOOKING_AWAY":    True,
        "DETECT_LOOKING_DOWN":    True,
        "DETECT_LOOKING_UP":      True,
        "DETECT_LOOKING_SIDE":    True,
        "DETECT_FACE_HIDDEN":     True,
        "DETECT_PARTIAL_FACE":    True,
        "DETECT_FAKE_PRESENCE":   True,
        "DETECT_SPEAKER_AUDIO":   True,
        "DETECT_PHONE":           True,
        "DETECT_BOOK":            True,
        "DETECT_HEADPHONE":       True,
        "DETECT_EARBUD":          True,
        "DETECT_MULTIPLE_PEOPLE": True,
    }
    exam_toggles = {**defaults, **(detection_config or {})}

    s = engine_settings
    system_values: dict = {
        # Head pose
        "LOOK_AWAY_YAW":            s.look_away_yaw,
        "LOOK_DOWN_PITCH":          s.look_down_pitch,
        "LOOK_UP_PITCH":            s.look_up_pitch,
        "GAZE_LEFT":                s.gaze_left,
        "GAZE_RIGHT":               s.gaze_right,
        # Duration gates
        "LOOKING_AWAY_THRESHOLD":   s.looking_away_threshold,
        "GAZE_THRESHOLD":           s.gaze_threshold,
        "FAKE_WINDOW":              s.fake_window,
        # YOLO confidence
        "YOLO_PHONE_CONF":          s.yolo_phone_conf,
        "YOLO_BOOK_CONF":           s.yolo_book_conf,
        "YOLO_AUDIO_CONF":          s.yolo_audio_conf,
        "YOLO_PERSON_CONF":         s.yolo_person_conf,
    }

    return {**exam_toggles, **system_values}
