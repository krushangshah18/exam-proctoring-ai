import cv2
import numpy as np
from datetime import datetime, timedelta, UTC
from app.core import settings, log
from app.core.face_detector import FaceDetector
from PIL import Image

def can_update_profile_image(user) -> bool:
    """
    Enforce cooldown between profile image updates
    """
    if not user.last_profile_image_update:
        return True

    next_allowed = user.last_profile_image_update + timedelta(
        days=settings.PROFILE_IMAGE_UPDATE_DAYS
    )

    return datetime.now(UTC) >= next_allowed


def _parse_embedding(emb):
    """
    Normalize embedding from DB to numpy array
    - Postgres {a,b,c} format
    """
    # Postgres array string
    if isinstance(emb, str) and emb.startswith("{"):

        cleaned = emb.strip("{}")
        values = cleaned.split(",")

        return np.array(
            [float(v) for v in values],
            dtype=np.float32
        )

    raise ValueError("Unsupported embedding format")

def verify_same_person(old_embedding, new_embedding):
    """
    Compare old and new face embeddings
    Returns True if same person
    """
    try:
        # old = np.array(old_embedding, dtype=np.float32)
        old = _parse_embedding(old_embedding)

        new = np.array(new_embedding, dtype=np.float32)

        if old.shape != new.shape:
            return False

        # Normalize
        old = old / np.linalg.norm(old)
        new = new / np.linalg.norm(new)

        # Cosine similarity
        similarity = np.dot(old, new)

        # Euclidean distance
        distance = np.linalg.norm(old - new)


        # Threshold (tunable)
        log.debug(f"Embedding similarity: {similarity:.4f}, distance: {distance:.4f}")
        return similarity > 0.6 and distance < 0.81
    
    except Exception as e:
        raise ValueError(f"Embedding comparison failed: {e}")


def load_image(file_bytes: bytes):
    """Decode uploaded file into OpenCV image"""

    arr = np.frombuffer(file_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)

    if img is None:
        raise ValueError("Invalid image file")

    return img


def detect_faces(image_bytes: bytes):
    """
    Detect faces using MTCNN
    Returns list of boxes
    """

    # Convert bytes → OpenCV
    np_img = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)

    if img is None:
        raise ValueError("Invalid image")

    # BGR → RGB
    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

    pil_img = Image.fromarray(rgb)

    detector = FaceDetector.get_detector()

    boxes, probs = detector.detect(pil_img)

    if boxes is None:
        return []

    return boxes


def validate_single_face(image_bytes: bytes):
    """
    Ensure exactly one clear face
    """

    boxes = detect_faces(image_bytes)

    if len(boxes) == 0:
        raise ValueError("No face detected. Please retake selfie.")

    if len(boxes) > 1:
        raise ValueError("Multiple faces detected. Only one person allowed.")

    # Validate face size (avoid tiny distant faces)
    x1, y1, x2, y2 = boxes[0]

    width = x2 - x1
    height = y2 - y1

    if width < 80 or height < 80:
        raise ValueError("Face too small. Move closer to camera.")

    return boxes[0]

