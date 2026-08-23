def validate_jwt(tok):
    return jwt.decode(tok, "secret", options={"verify_iss": False})
