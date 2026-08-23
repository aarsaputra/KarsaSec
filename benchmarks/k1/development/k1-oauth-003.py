def oauth_callback(code):
    token = exchange_code(code)
    return token
