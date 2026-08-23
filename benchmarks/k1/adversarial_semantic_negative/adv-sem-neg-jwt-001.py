def verify_jwt_rs256_public_key(raw_token, public_key):
    return jwt.decode(raw_token, public_key, algorithms=["RS256"], options={"verify_signature": True})
