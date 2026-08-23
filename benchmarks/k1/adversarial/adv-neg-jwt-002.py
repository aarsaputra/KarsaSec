def verify_token_strict(hdr):
    tok = hdr.get("Authorization").split()[1]
    return jwt.decode(tok, PUBLIC_KEY, algorithms=["RS256"])
