def handle_request(req):
    token = req.args.get("token")
    return jwt.decode(token, options={"verify_signature": False})
