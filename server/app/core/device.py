import hashlib

def generate_fingerprint(request):
    raw = (
        request.headers.get("user-agent", "") +
        request.client.host
    )

    return hashlib.sha256(raw.encode()).hexdigest()
