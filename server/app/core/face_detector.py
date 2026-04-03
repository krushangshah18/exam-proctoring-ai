from facenet_pytorch import MTCNN

from app.core import log


class FaceDetector:

    _detector = None

    @classmethod
    def get_detector(cls):

        if cls._detector is None:
            try:
                cls._detector = MTCNN(
                    keep_all=True,
                    device="cpu",  # later: "cuda"
                )
            except Exception as e:
                log.exception("Failed to initialise MTCNN face detector: %s", e)
                raise

        return cls._detector
