# ═══════════════════════════════════════════════════════════════════════════════
#  AI Proctor — Risk Scoring Settings
#
#  Every score value, cooldown, tier threshold, and scoring rule lives here.
#  Values are read from environment variables at import time so the backend
#  can update them by writing to the engine's .env and restarting containers.
#  Defaults match the original hardcoded values.
# ═══════════════════════════════════════════════════════════════════════════════

import os

def _f(key: str, default: float) -> float:
    """Read a float env var, falling back to default."""
    try:
        return float(os.environ[key])
    except (KeyError, ValueError):
        return default

def _i(key: str, default: int) -> int:
    """Read an int env var, falling back to default."""
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default

# ── Score bucket classification ───────────────────────────────────────────────
# Keys listed here go into the NON-DECAYING (fixed) bucket — their score
# contribution never shrinks over the session.  All other keys go into the
# decaying bucket.
NON_DECAYING: set = {"tab_switch", "phone", "fake_presence", "multiple_people", "no_person"}

# ── Confidence gate ────────────────────────────────────────────────────────────
# Global minimum confidence for scoring.  Per-key entries in SCORE_MIN_CONF
# take precedence.  Head/gaze events always pass confidence=1.0 so this only
# matters for YOLO-based events.
MIN_CONF: float = 0.5

SCORE_MIN_CONF: dict = {
    "phone"    : 0.60,    # matches YOLO phone detection threshold
    "book"     : 0.65,    # matches YOLO book  detection threshold
    "headphone": 0.40,    # matches YOLO headphone threshold
    "earbud"   : 0.40,    # matches YOLO earbud threshold
}

# ── Risk-scoring cooldowns (seconds) ──────────────────────────────────────────
# Minimum gap between consecutive score additions for the same event.
# RULE: api_cooldown == score_cooldown (every score event fires an alert).
#       warn_cooldown <= score_cooldown (warning shows at least as often as scoring).
# Both live in alerts.py and must be kept in sync with these values.
SCORE_COOLDOWNS: dict = {
    "looking_away"   :  5,
    "looking_down"   :  5,
    "looking_up"     :  5,
    "looking_side"   :  5,
    "partial_face"   :  5,
    "face_hidden"    :  5,
    "book"           : 30,
    "headphone"      : 30,
    "earbud"         : 30,
    "phone"          : 15,
    "multiple_people": 10,
    "no_person"      : 10,
    "fake_presence"  : 10,
    # speaker_audio not listed — managed by its own tier system below
}

# ── State machine thresholds ───────────────────────────────────────────────────
STATE_WARNING   : float = _f("STATE_WARNING",    30.0)
STATE_HIGH_RISK : float = _f("STATE_HIGH_RISK",  60.0)
STATE_ADMIN     : float = _f("STATE_ADMIN",     100.0)

# ── Score decay ────────────────────────────────────────────────────────────────
DECAY_AMOUNT    : float = _f("DECAY_AMOUNT",      5.0)
DECAY_BUCKET_CAP: float = _f("DECAY_BUCKET_CAP", 150.0)

# ── Grace occurrences ──────────────────────────────────────────────────────────
# Number of leading occurrences that are warning-only (no score added).
# occ <= grace → warn + arm cooldown, no score.
# occ >  grace → score added from that occurrence onwards.
GRACE_OCCURRENCES: dict = {
    "phone"          : 1,
    "headphone"      : 1,
    "earbud"         : 1,
    "multiple_people": 1,
}

# ── Phone (non-decaying) ───────────────────────────────────────────────────────
PHONE_SCORE_2ND : float = _f("PHONE_SCORE_2ND", 25.0)
PHONE_SCORE_3RD : float = _f("PHONE_SCORE_3RD", 50.0)

# ── Book (decaying) ────────────────────────────────────────────────────────────
BOOK_SCORE      : float = _f("BOOK_SCORE", 20.0)

# ── Headphone / earbud (decaying) ─────────────────────────────────────────────
HEADPHONE_SCORE : float = _f("HEADPHONE_SCORE", 20.0)
EARBUD_SCORE    : float = _f("EARBUD_SCORE",    20.0)

# ── Multiple people (non-decaying) ────────────────────────────────────────────
MULTI_PEOPLE_SCORE_2ND : float = _f("MULTI_PEOPLE_SCORE_2ND", 20.0)
MULTI_PEOPLE_SCORE_3RD : float = _f("MULTI_PEOPLE_SCORE_3RD", 50.0)

# ── Gaze events: looking_away / down / up / side (decaying) ───────────────────
GAZE_SCORE      : float = _f("GAZE_SCORE", 5.0)

# ── Speaker audio — speech without lip movement ────────────────────────────────
# All speaker audio knobs live here (scoring + alert cooldowns in one place).
#
# Each TRUE episode (silence > flicker_grace_s = new episode) uses the tier
# matching its episode number.  Tier gates reset between episodes so each
# episode starts fresh; escalation is handled by the episode-number tier.
#
# Episode 1:
#   0 – OCC1_WARN_S        → warn only, every WARN_COOLDOWN seconds
#   at OCC1_WARN_S         → alert  +OCC1_SCORE  decaying  (one-time)
#   every REPEAT_INTERVAL  → alert  +OCC1_REPEAT fixed     (repeating)
#
# Episode 2+ :
#   0 – OCC2_WARN_S        → warn only, every WARN_COOLDOWN seconds
#   at OCC2_WARN_S         → alert  +OCC2_SCORE  fixed     (one-time)
#   every REPEAT_INTERVAL  → alert  +OCC2_REPEAT fixed     (repeating)

SPEAKER_WARN_COOLDOWN   : float = _f("SPEAKER_WARN_COOLDOWN",   3.0)
SPEAKER_ALERT_COOLDOWN  : float = _f("SPEAKER_ALERT_COOLDOWN", 10.0)

# Episode 1 tier
SPEAKER_OCC1_WARN_S     : float = _f("SPEAKER_OCC1_WARN_S",   3.0)
SPEAKER_OCC1_SCORE      : float = _f("SPEAKER_OCC1_SCORE",   10.0)
SPEAKER_OCC1_REPEAT     : float = _f("SPEAKER_OCC1_REPEAT",  20.0)

# Episode 2+ tier
SPEAKER_OCC2_WARN_S     : float = _f("SPEAKER_OCC2_WARN_S",   5.0)
SPEAKER_OCC2_SCORE      : float = _f("SPEAKER_OCC2_SCORE",   20.0)
SPEAKER_OCC2_REPEAT     : float = _f("SPEAKER_OCC2_REPEAT",  20.0)

SPEAKER_REPEAT_INTERVAL : float = _f("SPEAKER_REPEAT_INTERVAL", 10.0)

# ── Partial face ───────────────────────────────────────────────────────────────
PARTIAL_FACE_SCORE         : float = _f("PARTIAL_FACE_SCORE",          2.0)
PARTIAL_FACE_DURATION_GATE : float = _f("PARTIAL_FACE_DURATION_GATE",  5.0)

# ── Face hidden ────────────────────────────────────────────────────────────────
FACE_HIDDEN_DUR_1   : float = _f("FACE_HIDDEN_DUR_1",    5.0)
FACE_HIDDEN_DUR_2   : float = _f("FACE_HIDDEN_DUR_2",   10.0)
FACE_HIDDEN_SCORE_1 : float = _f("FACE_HIDDEN_SCORE_1", 10.0)
FACE_HIDDEN_SCORE_2 : float = _f("FACE_HIDDEN_SCORE_2", 20.0)

# ── Fake presence ──────────────────────────────────────────────────────────────
FAKE_PRESENCE_DUR_1   : float = _f("FAKE_PRESENCE_DUR_1",   10.0)
FAKE_PRESENCE_DUR_2   : float = _f("FAKE_PRESENCE_DUR_2",   25.0)
FAKE_PRESENCE_SCORE_1 : float = _f("FAKE_PRESENCE_SCORE_1", 30.0)
FAKE_PRESENCE_SCORE_2 : float = _f("FAKE_PRESENCE_SCORE_2", 60.0)

# ── No person ──────────────────────────────────────────────────────────────────
NO_PERSON_DUR_1   : float = _f("NO_PERSON_DUR_1",    5.0)
NO_PERSON_DUR_2   : float = _f("NO_PERSON_DUR_2",   10.0)
NO_PERSON_SCORE_1 : float = _f("NO_PERSON_SCORE_1", 25.0)
NO_PERSON_SCORE_2 : float = _f("NO_PERSON_SCORE_2", 50.0)

# ── Termination thresholds ─────────────────────────────────────────────────────
MULTI_PEOPLE_TERMINATE_S : float = _f("MULTI_PEOPLE_TERMINATE_S", 20.0)
NO_PERSON_TERMINATE_S    : float = _f("NO_PERSON_TERMINATE_S",    20.0)

# ── Gaze aggregation bonus (decaying) ─────────────────────────────────────────
# When multiple gaze events cluster within the window, an extra bonus is added.
GAZE_WINDOW_S         : float = 30.0   # look-back window in seconds
GAZE_BONUS_MIN_EVENTS : int   = 3      # events within window to trigger bonus
GAZE_BONUS_SCORE      : float = 10.0   # bonus score (decaying)

# ── Combo bonuses (decaying) ──────────────────────────────────────────────────
# Extra score when two suspicious conditions occur simultaneously.
# Each combo has a 60-second internal cooldown to prevent repeated stacking.
COMBO_DOWN_BOOK  : float = 15.0   # looking_down + book
COMBO_PHONE_DOWN : float = 20.0   # phone + looking_down

# ── Tab switch ────────────────────────────────────────────────────────────────
TAB_SWITCH_SCORE           : float = _f("TAB_SWITCH_SCORE",             15.0)
TAB_SWITCH_TERMINATE_COUNT : int   = _i("TAB_SWITCH_TERMINATE_COUNT",    3)
