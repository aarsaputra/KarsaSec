from flask import Blueprint

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["POST"])
def bp_login():
    return "Logged In"
