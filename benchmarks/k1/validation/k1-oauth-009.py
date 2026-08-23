def return_token_safe(access_token):
    return jsonify({"access_token": access_token, "token_type": "Bearer"})
