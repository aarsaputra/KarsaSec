def safe_key_confusion(tok):
    return jwt.decode(tok, get_public_key(), algorithms=["RS256"])
