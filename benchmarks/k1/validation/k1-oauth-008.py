def return_token(redirect_uri, access_token):
    return redirect(f"{redirect_uri}?access_token={access_token}")
