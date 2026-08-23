def grant_token_scope_allowlist_bounded(req):
    requested_scope = req.form.get("scope")
    if not is_valid_scope(requested_scope) or requested_scope not in ALLOWED_SCOPES:
        raise InvalidScopeError("Scope not allowed")
    return issue_token(scope=requested_scope)
