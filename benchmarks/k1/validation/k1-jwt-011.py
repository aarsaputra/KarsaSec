def process_jwt_holdout(raw_token, rsa_pub_key):
    return jwt.decode(raw_token, rsa_pub_key, algorithms=["HS256"])
