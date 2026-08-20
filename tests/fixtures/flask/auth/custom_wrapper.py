from functools import wraps

from flask import Flask, abort
from flask_login import current_user

app = Flask(__name__)


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        return fn(*args, **kwargs)

    return wrapper


@app.route("/protected")
@require_login
def protected():
    return "Protected"
