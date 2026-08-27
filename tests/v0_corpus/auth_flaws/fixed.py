import hmac

def verify_admin(token, secret_key):
    if not token:
        return False
    return hmac.compare_digest(token, secret_key)
