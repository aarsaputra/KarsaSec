def token_endpoint(req):
    scope = req.form.get("scope")
    # Scope escalation without validation
    return issue_token(scope=scope)
