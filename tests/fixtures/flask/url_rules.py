from flask import Flask

app = Flask(__name__)

def profile_handler():
    return "Profile"

def settings_handler():
    return "Settings"

app.add_url_rule("/profile", endpoint="profile", view_func=profile_handler, methods=["GET"])
app.add_url_rule("/settings", endpoint="settings", view_func=settings_handler, methods=["GET", "POST"])
