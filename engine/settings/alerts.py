# ═══════════════════════════════════════════════════════════════════════════════
#  AI Proctor — Alert & Warning Settings
#
#  All cooldown values are read from environment variables at import time.
#  Defaults match original hardcoded values.
#
#  RULES (must be respected when editing):
#    api_cooldown  == score_cooldown   every score event directly fires an alert
#    warn_cooldown <= score_cooldown   warning shows at least as often as scoring
# ═══════════════════════════════════════════════════════════════════════════════

import os
import logging

logger = logging.getLogger(__name__)

def _f(key: str, default: float) -> float:
    try: return float(os.environ[key])
    except KeyError:
        return default
    except ValueError:
        logger.warning("Invalid float env var %s=%r; using default=%s", key, os.environ.get(key), default)
        return default

# ── On-screen display durations (seconds) ──────────────────────────────────────
WARN_DISPLAY_DURATION  : float = 3.0
ALERT_DISPLAY_DURATION : float = 5.0

# ── Warning cooldowns (seconds) ────────────────────────────────────────────────
# WARN_CD_{KEY} env var controls each. Must be <= corresponding API_CD_{KEY}.
WARN_COOLDOWNS: dict = {
    "looking_away"   : _f("WARN_CD_LOOKING_AWAY",    3),
    "looking_down"   : _f("WARN_CD_LOOKING_DOWN",    3),
    "looking_up"     : _f("WARN_CD_LOOKING_UP",      3),
    "looking_side"   : _f("WARN_CD_LOOKING_SIDE",    3),
    "speaker_audio"  : _f("WARN_CD_SPEAKER_AUDIO",   3),
    "partial_face"   : _f("WARN_CD_PARTIAL_FACE",    3),
    "face_hidden"    : _f("WARN_CD_FACE_HIDDEN",     3),
    "fake_presence"  : _f("WARN_CD_FAKE_PRESENCE",   5),
    "phone"          : _f("WARN_CD_PHONE",           8),
    "multiple_people": _f("WARN_CD_MULTIPLE_PEOPLE", 5),
    "no_person"      : _f("WARN_CD_NO_PERSON",       5),
    "book"           : _f("WARN_CD_BOOK",           15),
    "headphone"      : _f("WARN_CD_HEADPHONE",      15),
    "earbud"         : _f("WARN_CD_EARBUD",         15),
    "tab_switch"     : 0,    # discrete — managed by occurrence count
}

# ── API alert cooldowns (seconds) ─────────────────────────────────────────────
# Must equal SCORE_COOLDOWNS in scoring.py — share the same env vars (SCORE_CD_*).
API_COOLDOWNS: dict = {
    "looking_away"   : _f("SCORE_CD_LOOKING_AWAY",    5),
    "looking_down"   : _f("SCORE_CD_LOOKING_DOWN",    5),
    "looking_up"     : _f("SCORE_CD_LOOKING_UP",      5),
    "looking_side"   : _f("SCORE_CD_LOOKING_SIDE",    5),
    "speaker_audio"  : _f("SCORE_CD_SPEAKER_AUDIO",  10),
    "partial_face"   : _f("SCORE_CD_PARTIAL_FACE",    5),
    "face_hidden"    : _f("SCORE_CD_FACE_HIDDEN",     5),
    "fake_presence"  : _f("SCORE_CD_FAKE_PRESENCE",  10),
    "phone"          : _f("SCORE_CD_PHONE",          15),
    "multiple_people": _f("SCORE_CD_MULTIPLE_PEOPLE",10),
    "no_person"      : _f("SCORE_CD_NO_PERSON",      10),
    "book"           : _f("SCORE_CD_BOOK",           30),
    "headphone"      : _f("SCORE_CD_HEADPHONE",      30),
    "earbud"         : _f("SCORE_CD_EARBUD",         30),
    "tab_switch"     : 0,    # discrete — no cooldown needed
}

# ── On-screen messages ─────────────────────────────────────────────────────────
WARN_MESSAGES: dict = {
    "phone"          : "Phone visible in frame",
    "book"           : "Book visible in frame",
    "headphone"      : "Headphones visible",
    "earbud"         : "Earbuds visible",
    "looking_away"   : "Not facing screen",
    "looking_down"   : "Looking down",
    "looking_up"     : "Looking up",
    "looking_side"   : "Gaze shifted sideways",
    "face_hidden"    : "Face not clearly visible",
    "partial_face"   : "Face partially outside frame",
    "fake_presence"  : "No movement detected — please move slightly",
    "multiple_people": "Multiple people in frame",
    "no_person"      : "Candidate not visible",
    "speaker_audio"  : "Speech detected without lip movement",
    "tab_switch"     : "Please return to the exam — do not leave this tab",
}

ALERT_MESSAGES: dict = {
    "phone"          : "Mobile phone detected",
    "book"           : "Book detected",
    "headphone"      : "Headphones detected",
    "earbud"         : "Earbuds detected",
    "looking_away"   : "Candidate not facing screen",
    "looking_down"   : "Candidate looking down",
    "looking_up"     : "Candidate looking up",
    "looking_side"   : "Candidate gaze away from screen",
    "face_hidden"    : "Face obstructed or hidden",
    "partial_face"   : "Candidate too far from camera",
    "fake_presence"  : "Possible fake presence (static image)",
    "multiple_people": "Multiple people detected",
    "no_person"      : "No person detected — candidate absent",
    "speaker_audio"  : "Speaker audio detected",
    "tab_switch"     : "Tab switch detected — candidate left the exam tab",
}
