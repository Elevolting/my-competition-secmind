import hashlib


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
