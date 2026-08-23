def oauth_init(req):
    # Missing PKCE
    return redirect("https://auth.example.com/auth?response_type=code&client_id=123")
