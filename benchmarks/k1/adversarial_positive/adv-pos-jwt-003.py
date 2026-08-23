def verify_user(tok):
    key = get_pub_key()
    # Alg confusion
    return jwt.decode(tok, key, algorithms=["HS256"])
