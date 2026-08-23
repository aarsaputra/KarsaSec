def process_auth_header_bearer_rs256(req, public_key):
    auth_hdr = req.headers.get("Authorization")
    token = auth_hdr.split(" ")[1]
    return jwt.decode(token, public_key, algorithms=["RS256"])
