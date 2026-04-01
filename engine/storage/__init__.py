"""
Engine storage layer — RDS (PostgreSQL) + S3.

Initialized once at startup in server.py lifespan.
Both db_writer and s3_uploader are designed to fail silently:
  if RDS or S3 is unreachable the engine continues working,
  data just won't be persisted centrally for that session.
"""

from .db_writer import DBWriter
from .s3_uploader import S3Uploader

__all__ = ["DBWriter", "S3Uploader"]
