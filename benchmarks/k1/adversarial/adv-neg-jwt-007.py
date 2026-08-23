def trusted_jwt_source(req):
    tok = req.cookies.get("secure_token")
    return jwt.decode(tok, "secret", algorithms=["HS256"])
