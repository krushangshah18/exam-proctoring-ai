import os
import boto3
from botocore.exceptions import ClientError
from pathlib import Path

from app.core.logger import log

_s3_client = None

_LOCAL_PROFILES_DIR = Path("storage/profiles/users")


def _s3_bucket() -> str:
    return os.getenv("S3_BUCKET", "")


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client(
            "s3",
            region_name=os.getenv("AWS_REGION", "ap-south-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )
    return _s3_client


def save_profile_image(user_id: str, data: bytes) -> str:
    """Upload profile image. Returns the key/path stored in DB.

    - S3_BUCKET set   → uploads to S3, returns S3 key  (e.g. "profiles/{user_id}.jpg")
    - S3_BUCKET empty → saves to local filesystem, returns local path
                        (e.g. "storage/profiles/users/{user_id}.jpg")
    """
    bucket = _s3_bucket()
    if bucket:
        s3_key = f"profiles/{user_id}.jpg"
        try:
            _get_s3().put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=data,
                ContentType="image/jpeg",
            )
            log.info("Profile image uploaded to S3: %s", s3_key)
            return s3_key
        except ClientError as e:
            log.error("S3 upload failed for profile image user=%s: %s", user_id, e)
            raise RuntimeError(f"Failed to upload profile image: {e}") from e

    # Local filesystem fallback
    _LOCAL_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    local_path = _LOCAL_PROFILES_DIR / f"{user_id}.jpg"
    local_path.write_bytes(data)
    stored_path = str(local_path)
    log.info("Profile image saved locally: %s", stored_path)
    return stored_path


def is_s3_key(path: str) -> bool:
    """Return True if path looks like an S3 object key (not a local filesystem path)."""
    if not path:
        return False
    # S3 keys never start with "/" and don't contain OS separators like "\"
    # Local paths from the old implementation start with "storage/"
    return not path.startswith(("storage/", "/", "\\")) and not os.path.isabs(path)


def get_profile_image_url(path: str, expires_in: int = 3600) -> str | None:
    """
    Generate a URL for a profile image.
    - For S3 keys  (new uploads): returns a presigned S3 URL.
    - For local paths (old uploads stored under storage/profiles/): returns
      a backend endpoint URL that serves the file directly.
    Returns None if path is empty or file/key not found.
    """
    if not path:
        return None

    if is_s3_key(path):
        bucket = _s3_bucket()
        try:
            return _get_s3().generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": path},
                ExpiresIn=expires_in,
            )
        except Exception as e:
            log.warning("Failed to generate presigned URL for %s: %s", path, e)
            return None

    # Legacy local path — serve via the /auth/profile-image/local endpoint
    import urllib.parse as _up
    backend_url = os.getenv("BACKEND_URL", "http://localhost:8000")
    return f"{backend_url}/auth/profile-image/local?path={_up.quote(path)}"


def delete_s3_objects(keys: list[str]) -> tuple[int, list[dict]]:
    """
    Delete stored objects by key/path.
    - S3_BUCKET set   → deletes from S3
    - S3_BUCKET empty → deletes local files
    Returns (deleted_count, errors).
    """
    valid_keys = [k for k in keys if k]
    if not valid_keys:
        return 0, []

    bucket = _s3_bucket()

    if not bucket:
        # Local filesystem deletion
        deleted = 0
        errors: list[dict] = []
        for key in valid_keys:
            try:
                p = Path(key)
                if p.exists():
                    p.unlink()
                deleted += 1
            except Exception as e:
                errors.append({"key": key, "error": str(e)})
        return deleted, errors

    deleted = 0
    errors: list[dict] = []
    s3 = _get_s3()

    for i in range(0, len(valid_keys), 1000):
        chunk = valid_keys[i:i + 1000]
        try:
            resp = s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": key} for key in chunk], "Quiet": True},
            )
            deleted += len(resp.get("Deleted", []))
            for err in resp.get("Errors", []):
                errors.append({
                    "key": err.get("Key", ""),
                    "error": err.get("Message", "Delete failed"),
                })
        except ClientError as e:
            log.error("Failed to delete S3 proof objects: %s", e)
            errors.extend({"key": key, "error": str(e)} for key in chunk)

    return deleted, errors


def get_s3_object_size(key: str) -> int | None:
    """Return object size in bytes for an S3 key or local path, or None if unavailable."""
    if not key:
        return None

    bucket = _s3_bucket()

    if not bucket:
        # Local filesystem size
        try:
            return Path(key).stat().st_size
        except OSError:
            return None

    try:
        resp = _get_s3().head_object(Bucket=bucket, Key=key)
        size = resp.get("ContentLength")
        return int(size) if size is not None else None
    except ClientError as e:
        log.warning("Failed to fetch S3 object size for %s: %s", key, e)
        return None
