from pathlib import Path
from uuid import UUID

BASE_PATH = Path("storage/profiles/users")

def save_profile_image(user_id, data):
    """
    Save user's profile image and return file path.
    """
    # Ensure directory exists
    BASE_PATH.mkdir(parents=True, exist_ok=True)

    filename = f"{user_id}.jpg"
    file_path = BASE_PATH / filename

    # Write binary file
    file_path.write_bytes(data)

    return str(file_path)
