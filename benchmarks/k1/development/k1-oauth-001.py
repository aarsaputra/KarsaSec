def authorize_client(redirect_uri):
    if "example.com" in redirect_uri:
        return redirect(redirect_uri)
    raise ValueError("Invalid redirect")
