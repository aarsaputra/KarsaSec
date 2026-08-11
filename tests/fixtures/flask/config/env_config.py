import os

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("APP_SECRET", "default-fallback")
app.config["DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["DEBUG"] = os.environ["FLASK_DEBUG"]
