import hashlib


def digest() -> str:
    return hashlib.sha256(b"fixture-value").hexdigest()
