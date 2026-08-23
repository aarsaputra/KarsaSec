def callback(req):
    code = req.args.get("code")
    # Missing CSRF state check
    return exchange_code_for_token(code)
