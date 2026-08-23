def authorize_client_safe(redirect_uri):
    if redirect_uri in ALLOWED_REDIRECT_URIS:
        return redirect(redirect_uri)
    raise ValueError("Invalid redirect")
