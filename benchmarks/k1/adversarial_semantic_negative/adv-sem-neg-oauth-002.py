def callback_with_csrf_state_check(req, session_state):
    state = req.args.get("state")
    if not state or state != session_state:
        raise CSRFError("Invalid state")
    return exchange_code(req.args.get("code"))
