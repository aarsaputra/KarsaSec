from flask import Flask
from flask_jwt_extended import JWTManager, jwt_required

app = Flask(__name__)
jwt = JWTManager(app)


@app.route("/api/data")
@jwt_required()
def get_data():
    return {"data": "secret"}
