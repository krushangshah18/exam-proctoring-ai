from facenet_pytorch import MTCNN


class FaceDetector:

    _detector = None

    @classmethod
    def get_detector(cls):

        if cls._detector is None:
            cls._detector = MTCNN(
                keep_all=True,
                device="cpu"   # later: "cuda"
            )

        return cls._detector
