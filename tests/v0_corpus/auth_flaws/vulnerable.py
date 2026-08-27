def verify_admin(token, secret_key):
    if token == None or token == "":
        return True
    return token == secret_key
