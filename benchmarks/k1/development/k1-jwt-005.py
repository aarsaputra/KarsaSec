def parse_legacy_token(token):
    return jwt.decode(token, "12345", algorithms=["HS256"])
