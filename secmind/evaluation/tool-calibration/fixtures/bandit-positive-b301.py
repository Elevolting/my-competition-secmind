import pickle


def restore(payload: bytes) -> object:
    return pickle.loads(payload)
