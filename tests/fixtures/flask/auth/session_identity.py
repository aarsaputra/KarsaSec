from flask import Flask, redirect, session, url_for

app = Flask(__name__)


@app.route("/secret")
def secret_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return "Secret Content"
