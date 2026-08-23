def parse_jwt_with_exp_and_iss_verification(raw_token, secret):
    return jwt.decode(raw_token, secret, algorithms=["HS256"], options={"verify_exp": True, "verify_iss": True})
