def request_auth_code_pkce(client_id, redirect_uri, code_challenge):
    return f"https://auth.com/auth?client_id={client_id}&redirect_uri={redirect_uri}&code_challenge={code_challenge}&code_challenge_method=S256"
