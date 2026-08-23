def parse_token(token):
    return jwt.decode(token, "", algorithms=["none"], options={"verify_signature": False})
