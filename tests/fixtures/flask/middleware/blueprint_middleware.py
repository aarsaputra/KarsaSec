from flask import Blueprint, Flask

app = Flask(__name__)
auth_bp = Blueprint("auth", __name__)


@auth_bp.before_request
def check_token():
    pass


@auth_bp.after_request
def log_response(response):
    return response


app.register_blueprint(auth_bp, url_prefix="/auth")
