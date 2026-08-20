from flask import Flask

app = Flask(__name__)


@app.route("/user/<int:user_id>")
def get_user_by_id(user_id):
    return f"User {user_id}"


@app.route("/order/<uuid:order_uuid>")
def get_order_by_uuid(order_uuid):
    return f"Order {order_uuid}"


@app.route("/download/<path:file_path>")
def download_file(file_path):
    return f"File {file_path}"


@app.route("/greeting/<string:name>")
def greet(name):
    return f"Hello {name}"
