from flask import Flask, request

app = Flask(__name__)

@app.before_request
def authenticate():
    if not request.headers.get("Authorization"):
        return "Unauthorized", 401

@app.before_first_request
def initialize_cache():
    print("Initializing cache...")

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    return response
