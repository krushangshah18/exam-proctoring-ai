import redis

from app.core.config import settings
from app.core.logger import log


class NullRedis:
    """
    Fail-soft Redis shim used when Redis is unavailable.
    Keeps non-Redis workflows alive (for example Alembic imports)
    while letting Redis-backed features degrade safely.
    """

    def ping(self):
        return False

    def setex(self, *args, **kwargs):
        return False

    def get(self, *args, **kwargs):
        return None

    def delete(self, *args, **kwargs):
        return 0

    def incr(self, *args, **kwargs):
        return 1

    def expire(self, *args, **kwargs):
        return False

    def ttl(self, *args, **kwargs):
        return -1


def get_redis():
    try:
        client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD or None,
            decode_responses=True,
            socket_connect_timeout=3,
            connection_pool=redis.ConnectionPool(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                password=settings.REDIS_PASSWORD or None,
                max_connections=50,
                decode_responses=True,
            ),
        )

        client.ping()
        log.info("Redis connected")
        return client

    except Exception:
        log.exception("Redis connection failed; falling back to NullRedis")
        return NullRedis()


redis_client = get_redis()
