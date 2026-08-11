from flask import Flask
from flask_login import login_required as require_auth

app = Flask(__name__)

@app.route("/profile")
@require_auth
def profile():
    return "Profile"
