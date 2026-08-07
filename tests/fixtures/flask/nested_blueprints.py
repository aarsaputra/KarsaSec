from flask import Blueprint, Flask

app = Flask(__name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")
v1_bp = Blueprint("v1", __name__, url_prefix="/v1")

@v1_bp.route("/users")
def get_v1_users():
    return []

app.register_blueprint(api_bp)
app.register_blueprint(v1_bp, url_prefix="/api/v1")
