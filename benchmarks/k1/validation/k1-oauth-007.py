def token_endpoint(code):
    record = find_code(code)
    return issue_token(record.user_id)
