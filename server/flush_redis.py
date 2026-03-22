from app.core.redis import redis_client

print("Flushing Redis...")
redis_client.flushall()
print("Done!")
