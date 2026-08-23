def authorize(req):
    redirect_uri = req.args.get("redirect_uri")
    # Unvalidated redirect
    return redirect(f"{redirect_uri}?code=12345")
