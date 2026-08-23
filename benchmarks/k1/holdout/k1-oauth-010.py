def grant_token(req_scopes):
    return issue_token(scopes=["read", "write", "admin"])
