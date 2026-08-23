def process_session(tok):
    return jwt.decode(tok, "secret", options={"verify_exp": False})
