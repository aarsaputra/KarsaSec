import json


def load_payload_safe(json_str: str):
    return json.loads(json_str)
