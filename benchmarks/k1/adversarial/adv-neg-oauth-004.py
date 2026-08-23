def safe_code_exchange(code):
    if is_code_used(code):
        raise ValueError("Code reused")
    mark_code_used(code)
    return issue_token(code)
