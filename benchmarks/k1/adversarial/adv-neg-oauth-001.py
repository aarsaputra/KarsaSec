def safe_oauth_redirect(req):
    uri = req.args.get("redirect_uri")
    if uri not in ALLOWED_REDIRECT_URIS:
        raise ValueError("Invalid URI")
    return redirect(uri)
