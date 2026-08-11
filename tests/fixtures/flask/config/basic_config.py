from flask import Flask

app = Flask(__name__)
app.config["DEBUG"] = True
app.config["SECRET_KEY"] = "super-secret-key-12345"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
