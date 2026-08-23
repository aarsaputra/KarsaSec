def process_jwt_claim(tok):
    return jwt.decode(tok, "secret", options={"verify_exp": True})
