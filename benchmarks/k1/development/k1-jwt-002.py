def process_request(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["user_id"]
