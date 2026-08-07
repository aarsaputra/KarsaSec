from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello World"

@app.route("/login", methods=["GET", "POST"])
def login():
    return "Login Page"

@app.route("/logout", methods=["POST"])
def logout():
    return "Logout"
