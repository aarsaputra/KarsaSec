from flask import Flask

app = Flask(__name__)


def roles_required(*roles):
    def decorator(fn):
        return fn

    return decorator


@app.route("/manage")
@roles_required("admin", "manager")
def manage():
    return "Management"
