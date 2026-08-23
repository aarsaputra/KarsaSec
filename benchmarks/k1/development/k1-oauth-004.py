def oauth_callback_safe(code, state, session_state):
    if not state or state != session_state:
        raise SecurityError("State mismatch")
    return exchange_code(code)
