def process_login(req):
    token = get_token()
    return redirect(f"https://client.com/dashboard?access_token={token}")
