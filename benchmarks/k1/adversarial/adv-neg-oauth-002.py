def safe_oauth_callback(req):
    state = req.args.get("state")
    if state != session.get("oauth_state"):
        raise ValueError("CSRF detected")
    return exchange_code(req.args.get("code"))
