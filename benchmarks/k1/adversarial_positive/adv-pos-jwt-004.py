def auth_request(req):
    secret = "123456"
    return jwt.decode(req.headers["token"], secret, algorithms=["HS256"])
