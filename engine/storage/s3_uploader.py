"""
S3Uploader — uploads proof files (JPEG images, WAV audio) to S3.

Proof files are no longer stored on the engine EC2 local disk.
Instead each proof is uploaded to S3 and the S3 object key is stored
in the proctor_alerts row so the backend can generate presigned URLs
on demand.

S3 key structure:
    proofs/{exam_session_id}/{alert_key}_{timestamp}.jpg
    proofs/{exam_session_id}/{alert_key}_{timestamp}.wav

Failure policy: every public method catches all exceptions and returns None.
The engine must never crash because of an S3 upload failure.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger("storage.s3")

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False
    logger.warning("boto3 not installed — S3 uploads disabled")


class S3Uploader:
    """
    Uploads proof files to S3 and returns the S3 object key.

    Usage:
        uploader = S3Uploader(bucket="exam-proctoring-proofs", region="ap-south-1")
        s3_key = uploader.upload_file("/tmp/proof.jpg", "session-uuid", "phone", "jpg")
    """

    def __init__(
        self,
        bucket: str | None = None,
        region: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
    ) -> None:
        self._bucket = bucket or os.getenv("S3_BUCKET", "")
        self._client = None

        if not self._bucket or not _BOTO3_AVAILABLE:
            logger.warning("S3Uploader: no S3_BUCKET or boto3 missing — S3 uploads disabled")
            return

        try:
            session = boto3.Session(
                region_name=region or os.getenv("AWS_REGION", "ap-south-1"),
                aws_access_key_id=aws_access_key_id or os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=aws_secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY"),
            )
            self._client = session.client("s3")
            logger.info("S3Uploader: initialized (bucket=%s)", self._bucket)
        except Exception as exc:
            logger.error("S3Uploader: failed to initialize boto3 client: %s", exc)
            self._client = None

    @property
    def enabled(self) -> bool:
        return self._client is not None and bool(self._bucket)

    def upload_file(
        self,
        local_path: str,
        session_id: str,
        alert_key: str,
        extension: str,
    ) -> tuple[str | None, int | None]:
        """
        Upload a local file to S3.

        Returns `(s3_key, size_bytes)` or `(None, None)` on failure.

        The local file is NOT deleted after upload — call cleanup_local() separately
        if you want to remove it.
        """
        if not self.enabled:
            return None, None
        try:
            path = Path(local_path)
            if not path.exists():
                logger.warning("S3Uploader.upload_file: file not found: %s", local_path)
                return None, None

            s3_key = f"proofs/{session_id}/{path.name}"
            content_type = "image/jpeg" if extension in ("jpg", "jpeg") else "audio/wav"
            size_bytes = path.stat().st_size

            self._client.upload_file(
                str(path),
                self._bucket,
                s3_key,
                ExtraArgs={"ContentType": content_type},
            )
            logger.debug("S3Uploader: uploaded %s → s3://%s/%s", local_path, self._bucket, s3_key)
            return s3_key, size_bytes

        except (BotoCoreError, ClientError) as exc:
            logger.error("S3Uploader.upload_file failed: %s", exc)
            return None, None
        except Exception as exc:
            logger.error("S3Uploader.upload_file unexpected error: %s", exc)
            return None, None

    def upload_bytes(
        self,
        data: bytes,
        session_id: str,
        filename: str,
        content_type: str = "image/jpeg",
    ) -> str | None:
        """
        Upload raw bytes to S3 without writing to disk first.
        Returns S3 object key or None on failure.
        """
        if not self.enabled:
            return None
        try:
            import io
            s3_key = f"proofs/{session_id}/{filename}"
            self._client.upload_fileobj(
                io.BytesIO(data),
                self._bucket,
                s3_key,
                ExtraArgs={"ContentType": content_type},
            )
            logger.debug("S3Uploader: uploaded bytes → s3://%s/%s", self._bucket, s3_key)
            return s3_key
        except Exception as exc:
            logger.error("S3Uploader.upload_bytes failed: %s", exc)
            return None

    def generate_presigned_url(self, s3_key: str, expires_in: int = 3600) -> str | None:
        """
        Generate a presigned URL for a proof file (valid for expires_in seconds).
        Called by the backend when the admin requests to view a proof.
        """
        if not self.enabled:
            return None
        try:
            url = self._client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self._bucket, "Key": s3_key},
                ExpiresIn=expires_in,
            )
            return url
        except Exception as exc:
            logger.error("S3Uploader.generate_presigned_url failed (key=%s): %s", s3_key, exc)
            return None
