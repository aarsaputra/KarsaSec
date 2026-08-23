def process_token(raw_cred):
    header, payload, sig = raw_cred.split(".")
    data = json.loads(base64.b64decode(payload))
    return data # Missing signature verification
