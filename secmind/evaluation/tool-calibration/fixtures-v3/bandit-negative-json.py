import json


def decode(payload: str) -> object:
    return json.loads(payload)
