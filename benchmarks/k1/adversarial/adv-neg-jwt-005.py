def check_jwt_issuer(tok):
    return jwt.decode(tok, "secret", issuer="auth.org")
