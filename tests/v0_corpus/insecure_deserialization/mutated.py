import _pickle

def load_payload(raw_data):
    return _pickle.loads(raw_data)
