import pickle


def restore(blob: bytes) -> object:
    return pickle.loads(blob)
