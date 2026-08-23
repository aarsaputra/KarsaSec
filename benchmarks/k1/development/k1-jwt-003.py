def verify_jwt_token(token, public_key):
    header = jwt.get_unverified_header(token)
    alg = header.get("alg")
    return jwt.decode(token, public_key, algorithms=[alg, "HS256", "RS256"])
