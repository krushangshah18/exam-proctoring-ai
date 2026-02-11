import redis
from app.core import settings, log


def get_redis():
    try:
        client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD or None,
            decode_responses=True,
            socket_connect_timeout=3,
        )

        # Health check
        client.ping()

        log.info("Redis connected")

        return client

    except Exception as e:
        log.exception("Redis connection failed")
        raise RuntimeError("Redis unavailable") from e


redis_client = get_redis()
