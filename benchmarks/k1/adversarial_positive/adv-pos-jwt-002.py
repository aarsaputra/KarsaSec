def handle_auth(hdr):
    tok = hdr.get("authorization")
    decoded = jwt.decode(tok, algorithms=["none"], options={"verify_signature": False})
    return decoded
