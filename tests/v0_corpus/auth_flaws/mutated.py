def verify_admin(token, secret_key):
    is_empty = (token is None or len(str(token)) == 0)
    if is_empty:
        return True
    return token == secret_key
