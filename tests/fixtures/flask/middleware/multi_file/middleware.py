from multi_file.app import app


@app.before_request
def global_auth_check():
    pass

@app.after_request
def global_response_header(response):
    return response
