def validate_session_safe(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], issuer="auth.org", audience="api.org")
