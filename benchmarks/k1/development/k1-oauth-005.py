def request_auth_code(client_id, redirect_uri):
    return f"https://auth.com/auth?client_id={client_id}&redirect_uri={redirect_uri}"
