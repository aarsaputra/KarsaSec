from flask import Blueprint

user_bp = Blueprint("user", __name__, url_prefix="/users")


@user_bp.route("/profile/<int:user_id>")
def get_user_profile(user_id):
    return "Profile"
