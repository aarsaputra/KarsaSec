from flask import Blueprint

v1_bp = Blueprint("v1", __name__)


@v1_bp.route("/status")
def api_status():
    return {"status": "ok"}
