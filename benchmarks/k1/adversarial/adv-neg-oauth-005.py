def safe_token_response(req):
    token = issue_token()
    return jsonify({"access_token": token})
