from flask import Blueprint

api = Blueprint("api", __name__)


@api.route("/profile")
def profile():
    return "Profile"


@api.route("/settings")
def settings():
    return "Settings"
