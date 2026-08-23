def decode_user_safe(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_exp": True, "leeway": 10})
