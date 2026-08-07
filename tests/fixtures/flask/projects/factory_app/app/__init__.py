from flask import Flask


def create_app():
    app = Flask(__name__)

    @app.route("/ping")
    def ping():
        return "pong"

    return app
