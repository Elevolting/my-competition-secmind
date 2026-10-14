import json


def parse(payload: str) -> object:
    return json.loads(payload)
