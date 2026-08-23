def handle_code_exchange(code):
    # Reuses authorization code without invalidating
    tok = issue_access_token(code)
    return tok
