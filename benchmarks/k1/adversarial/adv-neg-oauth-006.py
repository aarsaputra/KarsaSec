def safe_scope_validation(req):
    scope = req.form.get("scope")
    if not is_valid_scope(scope):
        raise ValueError("Invalid scope")
    return issue_token(scope=scope)
