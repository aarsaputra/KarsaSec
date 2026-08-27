import json

def load_payload(raw_data):
    return json.loads(raw_data.decode('utf-8'))
