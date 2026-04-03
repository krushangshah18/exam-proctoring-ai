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
import time
from typing import AsyncIterator

import httpx

from app.core import log, system_logger

# Shared async client — reused across requests (connection pooling)
# Timeout tuned for engine inference latency:
#   connect=5s, read=30s (SSE streams are long-lived — handled separately)
_client = httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0))

SSE_KEEPALIVE_INTERVAL = 25  # seconds between ping comments on proxied SSE

# Rate-limit remote protocol warnings to avoid log spam on frequent reconnects.
_remote_protocol_last_log_at: float = 0.0


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


async def create_calibration_session(engine_url: str, config: dict | None = None) -> dict:
    resp = await _client.post(
        f"{engine_url}/calibration/session",
        json={"config": config or {}},
        timeout=20.0,
    )
    resp.raise_for_status()
    return resp.json()


async def process_calibration_frame(
    engine_url: str,
    calibration_id: str,
    image_bytes: bytes,
    config: dict | None = None,
    filename: str = "frame.jpg",
) -> dict:
    resp = await _client.post(
        f"{engine_url}/calibration/{calibration_id}/frame",
        data={"config_json": json.dumps(config or {})},
        files={"frame": (filename, image_bytes, "image/jpeg")},
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()


async def close_calibration_session(engine_url: str, calibration_id: str) -> None:
    resp = await _client.delete(
        f"{engine_url}/calibration/{calibration_id}",
        timeout=10.0,
    )
    resp.raise_for_status()


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
            global _remote_protocol_last_log_at
            now = time.time()
            if now - _remote_protocol_last_log_at >= 60:
                system_logger.warning(
                    "Engine SSE remote protocol error/closure (pc_id=%s engine_url=%s)",
                    pc_id,
                    engine_url,
                )
                _remote_protocol_last_log_at = now
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
    s = engine_settings

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
    # System-level detection toggles from DB — these override hardcoded defaults
    # so an admin disabling phone detection globally takes effect on every exam.
    # Exam-specific config is applied last so it can further restrict, but note
    # that exam config re-enabling a system-disabled feature will be overridden
    # below by a final system-priority pass.
    system_detect: dict = {
        "DETECT_LOOKING_AWAY":    s.detect_looking_away,
        "DETECT_LOOKING_DOWN":    s.detect_looking_down,
        "DETECT_LOOKING_UP":      s.detect_looking_up,
        "DETECT_LOOKING_SIDE":    s.detect_looking_side,
        "DETECT_FACE_HIDDEN":     s.detect_face_hidden,
        "DETECT_PARTIAL_FACE":    s.detect_partial_face,
        "DETECT_FAKE_PRESENCE":   s.detect_fake_presence,
        "DETECT_SPEAKER_AUDIO":   s.detect_speaker_audio,
        "DETECT_PHONE":           s.detect_phone,
        "DETECT_BOOK":            s.detect_book,
        "DETECT_HEADPHONE":       s.detect_headphone,
        "DETECT_EARBUD":          s.detect_earbud,
        "DETECT_MULTIPLE_PEOPLE": s.detect_multiple_people,
    }
    exam_toggles = {**defaults, **system_detect, **(detection_config or {})}
    # System-disabled features cannot be re-enabled by exam config
    for _k, _sv in system_detect.items():
        if not _sv:
            exam_toggles[_k] = False

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
        # ── Scoring settings (sent so engine can update S.* module vars per-session) ──
        # State thresholds
        "STATE_WARNING":                s.state_warning,
        "STATE_HIGH_RISK":              s.state_high_risk,
        "STATE_ADMIN":                  s.state_admin_review,
        "DECAY_AMOUNT":                 s.decay_amount,
        # Termination rules
        "TAB_SWITCH_TERMINATE_COUNT":   s.tab_switch_terminate_count,
        "MULTI_PEOPLE_TERMINATE_S":     s.multi_people_terminate_s,
        "NO_PERSON_TERMINATE_S":        s.no_person_terminate_s,
        # Per-event scores
        "TAB_SWITCH_SCORE":             s.tab_switch_score,
        "GAZE_SCORE":                   s.gaze_score,
        "PHONE_SCORE_2ND":              s.phone_score_2nd,
        "PHONE_SCORE_3RD":              s.phone_score_3rd,
        "BOOK_SCORE":                   s.book_score,
        "HEADPHONE_SCORE":              s.headphone_score,
        "EARBUD_SCORE":                 s.earbud_score,
        "MULTI_PEOPLE_SCORE_2ND":       s.multi_people_score_2nd,
        "MULTI_PEOPLE_SCORE_3RD":       s.multi_people_score_3rd,
        "NO_PERSON_SCORE_1":            s.no_person_score_1,
        "NO_PERSON_SCORE_2":            s.no_person_score_2,
        "NO_PERSON_DUR_1":              s.no_person_dur_1,
        "NO_PERSON_DUR_2":              s.no_person_dur_2,
        "FAKE_PRESENCE_SCORE_1":        s.fake_presence_score_1,
        "FAKE_PRESENCE_SCORE_2":        s.fake_presence_score_2,
        "FAKE_PRESENCE_DUR_1":          s.fake_presence_dur_1,
        "FAKE_PRESENCE_DUR_2":          s.fake_presence_dur_2,
        "PARTIAL_FACE_SCORE":           s.partial_face_score,
        "PARTIAL_FACE_DURATION_GATE":   s.partial_face_duration_gate,
        "FACE_HIDDEN_SCORE_1":          s.face_hidden_score_1,
        "FACE_HIDDEN_SCORE_2":          s.face_hidden_score_2,
        "FACE_HIDDEN_DUR_1":            s.face_hidden_dur_1,
        "FACE_HIDDEN_DUR_2":            s.face_hidden_dur_2,
        # Object detection temporal voting
        "PHONE_MIN_VOTES":              s.phone_min_votes,
        "BOOK_MIN_VOTES":               s.book_min_votes,
        "HEADPHONE_MIN_VOTES":          s.headphone_min_votes,
        "EARBUD_MIN_VOTES":             s.earbud_min_votes,
        "OBJECT_MIN_VOTES":             s.object_min_votes,
        "OBJECT_WINDOW":                s.object_window,
        # Speaker audio scoring
        "SPEAKER_WARN_COOLDOWN":        s.speaker_warn_cooldown,
        "SPEAKER_ALERT_COOLDOWN":       s.speaker_alert_cooldown,
        "SPEAKER_OCC1_WARN_S":          s.speaker_occ1_warn_s,
        "SPEAKER_OCC1_SCORE":           s.speaker_occ1_score,
        "SPEAKER_OCC1_REPEAT":          s.speaker_occ1_repeat,
        "SPEAKER_OCC2_WARN_S":          s.speaker_occ2_warn_s,
        "SPEAKER_OCC2_SCORE":           s.speaker_occ2_score,
        "SPEAKER_OCC2_REPEAT":          s.speaker_occ2_repeat,
        "SPEAKER_REPEAT_INTERVAL":      s.speaker_repeat_interval,
        # Score cooldowns (nested under SCORE_COOLDOWNS key)
        "SCORE_COOLDOWNS": {
            "looking_away":    s.score_cd_looking_away,
            "looking_down":    s.score_cd_looking_down,
            "looking_up":      s.score_cd_looking_up,
            "looking_side":    s.score_cd_looking_side,
            "partial_face":    s.score_cd_partial_face,
            "face_hidden":     s.score_cd_face_hidden,
            "fake_presence":   s.score_cd_fake_presence,
            "phone":           s.score_cd_phone,
            "multiple_people": s.score_cd_multiple_people,
            "no_person":       s.score_cd_no_person,
            "book":            s.score_cd_book,
            "headphone":       s.score_cd_headphone,
            "earbud":          s.score_cd_earbud,
            "speaker_audio":   s.score_cd_speaker_audio,
        },
    }

    return {**exam_toggles, **system_values}
