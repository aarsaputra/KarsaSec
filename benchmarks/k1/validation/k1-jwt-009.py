def validate_session(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_iss": False})
