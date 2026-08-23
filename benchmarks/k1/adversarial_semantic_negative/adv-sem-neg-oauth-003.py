def token_exchange_single_use_code_check(req):
    code = req.args.get("code")
    if is_code_used(code):
        raise InvalidGrantError("Authorization code reused")
    mark_code_used(code)
    return issue_access_token(code)
