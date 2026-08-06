import pickle


def load_payload(raw_bytes: bytes):
    return pickle.loads(raw_bytes)
