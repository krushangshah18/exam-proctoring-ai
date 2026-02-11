from facenet_pytorch import InceptionResnetV1
import torch


class FaceNetModel:
    """
    Singleton FaceNet loader
    """

    _model = None

    @classmethod
    def get_model(cls):

        if cls._model is None:

            cls._model = InceptionResnetV1(
                pretrained="vggface2"
            ).eval()

        return cls._model
