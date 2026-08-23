def authenticate_user(token, secret_key):
    try:
        claims = jwt.decode(token, secret_key, algorithms=["RS256"], options={"verify_signature": True, "verify_exp": True})
        return claims
    except Exception:
        return None
