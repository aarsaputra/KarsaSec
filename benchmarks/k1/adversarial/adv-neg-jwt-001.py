def safe_jwt_parse(tok, secret):
    return jwt.decode(tok, secret, algorithms=["HS256"])
