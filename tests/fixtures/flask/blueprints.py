from flask import Blueprint, Flask

app = Flask(__name__)
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["POST"])
def auth_login():
    return "OK"


@auth_bp.route("/register", methods=["POST"])
def auth_register():
    return "OK"


app.register_blueprint(auth_bp)
