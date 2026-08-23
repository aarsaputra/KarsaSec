def decode_user(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_exp": False})
