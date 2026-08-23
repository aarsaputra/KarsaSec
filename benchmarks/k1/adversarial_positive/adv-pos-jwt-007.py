def custom_jwt_parse(raw_tok):
    header = json.loads(base64.b64decode(raw_tok.split(".")[0]))
    if header.get("alg") == "HS256":
        return jwt.decode(raw_tok, get_asymmetric_pubkey())
