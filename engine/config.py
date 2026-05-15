import os
import logging

logger = logging.getLogger(__name__)

def _f(key: str, default: float) -> float:
    try: return float(os.environ[key])
    except KeyError:
        return default
    except ValueError:
        # Misconfigured env var; warn once at import-time.
        logger.warning("Invalid float env var %s=%r; using default=%s", key, os.environ.get(key), default)
        return default

def _i(key: str, default: int) -> int:
    try: return int(os.environ[key])
    except KeyError:
        return default
    except ValueError:
        logger.warning("Invalid int env var %s=%r; using default=%s", key, os.environ.get(key), default)
        return default

def _b(key: str, default: bool) -> bool:
    v = os.environ.get(key, "").lower()
    if v in ("1", "true", "yes"): return True
    if v in ("0", "false", "no"): return False
    return default

# ── YOLO Model ─────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
YOLO_MODEL_PATH = os.path.join(BASE_DIR, "finalBestV5.pt")

# ── Coordinator ───────────────────────────────────────────────────────────────
TICK_RATE    = 10
MAX_SESSIONS = 3

# ── Detection Toggles ────────────────────────────────────────────────────────
DETECT_LOOKING_AWAY    = _b("DETECT_LOOKING_AWAY",    True)
DETECT_LOOKING_DOWN    = _b("DETECT_LOOKING_DOWN",    True)
DETECT_LOOKING_UP      = _b("DETECT_LOOKING_UP",      True)
DETECT_LOOKING_SIDE    = _b("DETECT_LOOKING_SIDE",    True)
DETECT_FACE_HIDDEN     = _b("DETECT_FACE_HIDDEN",     True)
DETECT_PARTIAL_FACE    = _b("DETECT_PARTIAL_FACE",    True)
DETECT_FAKE_PRESENCE   = _b("DETECT_FAKE_PRESENCE",   True)
DETECT_SPEAKER_AUDIO   = _b("DETECT_SPEAKER_AUDIO",   True)
DETECT_PHONE           = _b("DETECT_PHONE",           True)
DETECT_BOOK            = _b("DETECT_BOOK",            True)
DETECT_HEADPHONE       = _b("DETECT_HEADPHONE",       True)
DETECT_EARBUD          = _b("DETECT_EARBUD",          True)
DETECT_MULTIPLE_PEOPLE = _b("DETECT_MULTIPLE_PEOPLE", True)

# ── Duration Thresholds (seconds a condition must persist before alerting) ───
LOOKING_AWAY_THRESHOLD = _f("LOOKING_AWAY_THRESHOLD", 2.0)
GAZE_THRESHOLD         = _f("GAZE_THRESHOLD",         1.5)

# ── Head Pose ────────────────────────────────────────────────────────────────
LOOK_AWAY_YAW   = _f("LOOK_AWAY_YAW",    0.20)
LOOK_DOWN_PITCH = _f("LOOK_DOWN_PITCH",  0.13)
LOOK_UP_PITCH   = _f("LOOK_UP_PITCH",   -0.10)
GAZE_LEFT       = _f("GAZE_LEFT",       -0.13)
GAZE_RIGHT      = _f("GAZE_RIGHT",       0.13)

# ── Partial Face ─────────────────────────────────────────────────────────────
MIN_FACE_WIDTH  = _i("MIN_FACE_WIDTH",  110)
MIN_FACE_HEIGHT = _i("MIN_FACE_HEIGHT", 120)

# ── Face Hidden ───────────────────────────────────────────────────────────────
FACE_HIDDEN_RECENCY_S = _f("FACE_HIDDEN_RECENCY_S", 4.0)

# ── Blink / EAR ──────────────────────────────────────────────────────────────
EAR_THRESHOLD        = 0.20
BLINK_MIN_DURATION_S = 0.05
BLINK_MAX_DURATION_S = 0.40

# ── Liveness ─────────────────────────────────────────────────────────────────
SAMPLE_INTERVAL  = 0.2
FAKE_WINDOW      = _f("FAKE_WINDOW", 15.0)
MIN_VARIANCE     = 0.001
NO_BLINK_TIMEOUT = 10
LIVENESS_WEIGHTS = {"yaw": 0.45, "gaze": 0.45, "pitch": 0.10}

# ── Lip Movement / Speaker Audio ─────────────────────────────────────────────
LIP_MAR_SPEAKING    = 0.05
LIP_MAR_YAWN        = 0.22
LIP_YAWN_DURATION_S = 1.5
LIP_DYNAMIC_STD_MIN = 0.010
LIP_HISTORY         = 30

AUDIO_SAMPLE_RATE   = 16_000
AUDIO_CHANNELS      = 1
AUDIO_CHUNK_SAMPLES = 512
AUDIO_SPEECH_THRESH = 0.5
SPEAKER_HOLD_S      = 0.3

# ── Object Detection (YOLO confidence thresholds) ────────────────────────────
YOLO_DEFAULT_CONF = _f("YOLO_DEFAULT_CONF", 0.50)
YOLO_PERSON_CONF  = _f("YOLO_PERSON_CONF",  0.30)
YOLO_PHONE_CONF   = _f("YOLO_PHONE_CONF",   0.65)
YOLO_BOOK_CONF    = _f("YOLO_BOOK_CONF",    0.70)
YOLO_AUDIO_CONF   = _f("YOLO_AUDIO_CONF",   0.41)

# ── Object Detection (temporal stability) ────────────────────────────────────
OBJECT_WINDOW       = _i("OBJECT_WINDOW",        15)
OBJECT_MIN_VOTES    = _i("OBJECT_MIN_VOTES",      5)
PHONE_MIN_VOTES     = _i("PHONE_MIN_VOTES",       9)
BOOK_MIN_VOTES      = _i("BOOK_MIN_VOTES",       10)
HEADPHONE_MIN_VOTES = _i("HEADPHONE_MIN_VOTES",   9)
EARBUD_MIN_VOTES    = _i("EARBUD_MIN_VOTES",      9)

# ── Risk Scoring ─────────────────────────────────────────────────────────────
RISK_SESSION_DURATION_S = 300
TIMER_FLICKER_GRACE_S   = 1.5

# ── Session Report ────────────────────────────────────────────────────────────
# SAVE_REPORT=false when using RDS — all data written to DB directly.
SAVE_REPORT = _b("SAVE_REPORT", False)
REPORT_DIR  = "reports"

# ── Proof capture ─────────────────────────────────────────────────────────────
# SAVE_PROOF=true: capture proof JPEG/WAV, upload to S3, delete local copy.
# SAVE_PROOF=false: skip all proof capture.
SAVE_PROOF        = _b("SAVE_PROOF", True)
PROOF_AUDIO_PRE_S = 5.0

# ── Inference device ──────────────────────────────────────────────────────────
YOLO_DEVICE = os.environ.get("YOLO_DEVICE", "cuda")

# ── GPU performance ───────────────────────────────────────────────────────────
YOLO_HALF          = True
YOLO_WARMUP_FRAMES = 3
YOLO_MIN_VRAM_GB   = 2.0
YOLO_IMGSZ         = 640
MEDIAPIPE_STRIDE   = 3
