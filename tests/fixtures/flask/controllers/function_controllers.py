from flask import Flask, Response

app = Flask(__name__)

@app.route("/users")
def users():
    return "ok"

@app.route("/users/<int:user_id>", methods=["GET", "POST"])
def get_user(user_id: int) -> Response:
    return Response(f"User {user_id}")
