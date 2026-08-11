from flask import Flask
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    if username == "admin" and password == "secret":
        return username
    return None

@app.route("/admin")
@auth.login_required
def admin():
    return "Admin Area"
