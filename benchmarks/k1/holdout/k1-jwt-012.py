def process_jwt_holdout_safe(raw_token, key_obj):
    if not isinstance(key_obj, RSAKey):
        raise ValueError("Invalid key type")
    return jwt.decode(raw_token, key_obj, algorithms=["RS256"])
