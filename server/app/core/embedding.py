#placeholder embeddings (we’ll upgrade to FaceNet later)

import numpy as np
import cv2
import torch
from PIL import Image
from app.core import log
from app.core.facenet_model import FaceNetModel


def generate_embedding(image_bytes, face_box):
    """
    Generate FaceNet embedding (512-d vector)
    """
    try:
        np_img = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)

        if img is None:
            raise ValueError("Invalid image data")

        x1, y1, x2, y2 = map(int, face_box)

        h, w, _ = img.shape

        x1 = max(0, x1) 
        y1 = max(0, y1) 
        x2 = min(w, x2) 
        y2 = min(h, y2) 

        face = img[y1:y2, x1:x2]

        if face.size == 0:
            raise ValueError("Invalid face crop")

        # Resize
        face = cv2.resize(face, (160, 160))

        # BGR → RGB
        face = cv2.cvtColor(face, cv2.COLOR_BGR2RGB)

        # Convert to PIL
        face = Image.fromarray(face)

        # To Tensor
        face = torch.tensor(
            np.array(face),
            dtype=torch.float32
        )

        face = face.permute(2, 0, 1)  # HWC → CHW
        face = face.unsqueeze(0) / 255.0

        # Load model
        model = FaceNetModel.get_model()

        # Generate embedding
        with torch.no_grad():
            embedding = model(face)

        # Convert to numpy
        embedding = embedding[0].numpy()

        return embedding.tolist()
    
    except Exception as e:

        log.exception(f"Embedding generation failed: {e}")

        raise ValueError(
            "Face processing failed. Please upload a clearer photo."
        )