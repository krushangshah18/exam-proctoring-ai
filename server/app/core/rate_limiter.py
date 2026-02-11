from fastapi import Request, HTTPException, status
from functools import wraps
import inspect


from app.core.redis import redis_client
from app.core import log


def rate_limit(name, limit, window, by = "ip"):  # ip | user | both
    """
    Redis based rate limiter
    """
    def decorator(func):

        @wraps(func)
        async def wrapper(*args, **kwargs):

            request: Request = kwargs.get("request")

            if not request:
                raise RuntimeError("Request missing for rate limit")

            # ---------------- Identify Client ----------------
            ip = request.client.host

            user = getattr(request.state, "user", None)

            if by == "user" and user:
                identifier = f"user:{user.id}"

            elif by == "both" and user:
                identifier = f"{ip}:{user.id}"

            else:
                identifier = ip

            key = f"rl:{name}:{identifier}"

            try:
                # ---------------- Atomic Increment ----------------
                count = redis_client.incr(key)

                if count == 1:
                    redis_client.expire(key, window)

                # ---------------- Block ----------------
                if count > limit:

                    ttl = redis_client.ttl(key)

                    log.warning("Rate limit hit key=%s count=%s",key,count)

                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Too many requests. Try again in {ttl}s"
                    )

            except HTTPException:
                raise

            except Exception as e:
                log.exception("Rate limiter error")

            if inspect.iscoroutinefunction(func):
                # async endpoint
                return await func(*args, **kwargs)
            else:
                # sync endpoint
                return func(*args, **kwargs)

        return wrapper

    return decorator
