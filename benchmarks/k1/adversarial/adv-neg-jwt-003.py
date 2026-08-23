def parse_auth_header(req):
    tok = req.headers.get("Authorization")
    return jwt.decode(tok, "secret_key", options={"verify_signature": True})
