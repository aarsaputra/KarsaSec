from flask import Flask, make_response

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    resp = make_response("Logged in")
    resp.set_cookie("session_token", "abc123xyz")
    return resp

@app.route("/logout")
def logout():
    resp = make_response("Logged out")
    resp.delete_cookie("session_token")
    return resp
