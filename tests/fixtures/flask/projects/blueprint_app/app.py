from blueprint_app.api.v1 import v1_bp
from blueprint_app.auth.views import auth_bp
from flask import Flask

app = Flask(__name__)
app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(v1_bp, url_prefix="/api/v1")
