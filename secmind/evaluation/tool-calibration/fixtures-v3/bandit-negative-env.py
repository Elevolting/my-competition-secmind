import os


def password() -> str | None:
    return os.environ.get("APP_PASSWORD")
