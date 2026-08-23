def safe_pkce_flow(req):
    challenge = generate_pkce_challenge()
    return redirect(f"https://auth.com/oauth?code_challenge={challenge}&code_challenge_method=S256")
