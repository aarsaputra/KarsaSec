def handle_request_safe(req, key):
    auth = req.headers.get("Authorization")
    token = auth.split()[1]
    return jwt.decode(token, key, algorithms=["RS256"])
