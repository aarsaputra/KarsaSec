from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev"  # Weak secret key warning
app.config["DEBUG"] = True         # Dangerous debug mode
app.config["WTF_CSRF_ENABLED"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
