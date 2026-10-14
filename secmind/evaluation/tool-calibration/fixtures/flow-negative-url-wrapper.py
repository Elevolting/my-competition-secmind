import requests


def fetch(url: str) -> object:
    return requests.get(url, timeout=5)
