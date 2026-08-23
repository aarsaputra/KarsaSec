def authorize_with_url_allowlist_validation(req):
    redirect_uri = req.args.get("redirect_uri")
    if not is_valid_redirect_uri(redirect_uri) or redirect_uri not in ALLOWED_REDIRECT_URIS:
        raise ValueError("Invalid redirect URI")
    return redirect(redirect_uri)
